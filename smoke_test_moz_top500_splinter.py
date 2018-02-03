#!/usr/bin/env python3

# example command:
#   > py.test smoke_test_moz_top500.py -s n 4

"""
Install on Ubuntu 16.04:
sudo apt-get install python3-pip python3-dev python3-venv libffi-dev libssl-dev libtiff5-dev libjpeg8-dev zlib1g-dev libwebp-dev

sudo apt-get build-dep nghttp2
wget https://github.com/nghttp2/nghttp2/releases/download/v1.17.0/nghttp2-1.17.0.tar.bz2
tar xvjf nghttp2-1.17.0.tar.bz2
cd nghttp2-1.17.0
autoreconf -i
automake
autoreconf
./configure --disable-app
make
sudo make install
sudo ldconfig

sudo apt-get build-dep curl
wget https://curl.haxx.se/download/curl-7.52.1.tar.bz2
tar xvjf curl-7.52.1.tar.bz2
cd curl-7.52.1
./configure
make



export PATH=/home/ubuntu/chromedriver_linux64:$PATH
"""

import tempfile
import sys
import os
import csv
import subprocess
import queue
import threading
import glob
import time

import pytest
from flaky import flaky

from mitmproxy import controller, flow, proxy, options
from mitmproxy.proxy.server import ProxyServer
from mitmproxy.proxy.config import ProxyConfig
from mitmproxy.addons.disable_h2c import DisableH2C
from test.mitmproxy import tservers

from splinter import Browser
from selenium.webdriver.chrome.options import Options as ChromeOptions

def generate_combinations():
    if not os.path.isdir('tmp'):
        os.makedirs('tmp')
    if not os.path.isfile('tmp/top500.domains.csv'):
        subprocess.run(['wget', 'https://moz.com/top500/domains/csv', '-q', '-O', 'tmp/top500.domains.csv'])

    domains = []
    with open('tmp/top500.domains.csv') as csvfile:
        reader = csv.reader(csvfile, delimiter=',', quotechar='"')
        headers = next(reader)
        domains = [row[1].rstrip('/') for row in reader]

    l = [[
            (False, domain, "http://{}".format(domain)),
            (False, domain, "https://{}".format(domain)),
            (False, domain, "http://www.{}".format(domain)),
            (False, domain, "https://www.{}".format(domain)),
            (True, domain, "http://{}".format(domain)),
            (True, domain, "http://www.{}".format(domain)),
            (True, domain, "https://{}".format(domain)),
            (True, domain, "https://www.{}".format(domain)),
        ] for domain in domains]
    return [item for sublist in l for item in sublist][:10]


def write_protocol(offer_h2, domain, url, message=None, fs=None, events=None, logs=None):
    u = 'h2_' if offer_h2 else ''
    u += 'http' if url.startswith('http://') else 'https'
    u += '_www.' if '://www.' in url else '_'
    u += domain
    with open("tmp/{}/{}.txt".format(os.environ['SMOKE_TEST_TIMESTAMP'], u), mode='a') as file:
        file.write("################################################################################\n".format(domain))
        file.write("{}\n\n".format(os.environ['SMOKE_TEST_TIMESTAMP']))
        file.write("offer_h2: {}\n".format(offer_h2))
        file.write("domain: {}\n".format(domain))
        file.write("url: {}\n".format(url))

        if message:
            file.write("{}\n".format(message))

        file.write("\n\n")
        if fs:
            file.write("flows in mitmproxy:\n")
            for fl in fs.keys():
                file.write("{}\n".format(fl))
        else:
            file.write("<no flows in mitmproxy>\n")

        if events:
            file.write("\n\n")
            for msg in events:
                file.write("{: <20} {}".format(msg[0].upper() + ':', msg[1]))
                file.write("\n")

        if logs:
            file.write("\n\n")
            for msg in logs:
                file.write("{: <6} {}".format(msg.level.upper() + ':', msg.msg))
                file.write("\n")

        file.write("\n\n")


class TestSmokeCurl(object):
    @classmethod
    def setup_class(cls):
        opts = options.Options(
            listen_port=0,
            upstream_cert=True,
            ssl_insecure=True,
            verbosity='debug',
            flow_detail=99,
        )
        opts.cadir = os.path.expanduser("~/.mitmproxy")
        tmaster = tservers.TestMaster(opts)

        cls.proxy = proxy = tservers.ProxyThread(tmaster)
        cls.proxy.start()

        cls.browser = None

    @classmethod
    def teardown_class(cls):
        cls.proxy.shutdown()

    def teardown_method(self, method):
        if self.browser:
            self.browser.quit()
            self.browser = None

    @flaky(max_runs=3)
    @pytest.mark.parametrize('offer_h2, domain, url', generate_combinations())
    def test_smoke_curl(self, offer_h2, domain, url):
        self.proxy.tmaster.clear()
        self.proxy.tmaster.reset([DisableH2C()])

        chrome_options = ChromeOptions()
        chrome_options.add_argument('--proxy-server=http://127.0.0.1:' + str(self.proxy.port))
        if not offer_h2:
            chrome_options.add_argument('--disable-http2')
        self.browser = Browser('chrome',
                              options=chrome_options,
                              executable_path='/usr/local/bin/chromedriver',
                              headless=True,
                              incognito=True,
                              service_log_path='/tmp/chromedriver-log.log',
                              service_args=["--verbose", "--log-net-log=/tmp/chromedriver-net-log-output.json"])

        self.browser.visit(url)
        assert self.browser.status_code.is_success()

        fs = {}
        for f in self.proxy.tmaster.state.flows:
            if f.response:
                fs[(f.request.http_version, f.request.scheme, f.request.host, f.response.status_code)] = f

        # if not offer_h2:
        print([k[0] for k in fs.keys()])
            # assert all([k[0].startswith('HTTP/1') for k in fs.keys()])

        no_failed_flows = len([k for k in fs.keys() if k[3] >= 500]) == 0
        if not no_failed_flows:
            write_protocol(offer_h2, domain, url, fs=fs, events=self.proxy.tmaster.events, logs=self.proxy.tmaster.logs)
        assert no_failed_flows

        successful_flows = len([k for k in fs.keys() if k[3] == 200]) >= 1
        if not successful_flows:
            write_protocol(offer_h2, domain, url, fs=fs, events=self.proxy.tmaster.events, logs=self.proxy.tmaster.logs)
        assert successful_flows

        for k, flow in [(k, f) for k, f in fs.items() if k[3] == 200]:
            success = flow.error is None and flow.request and flow.response
            if not success:
                write_protocol(offer_h2, domain, url, fs=fs, events=self.proxy.tmaster.events, logs=self.proxy.tmaster.logs)
            assert success

        for msg in self.proxy.tmaster.logs:
            assert 'Traceback' not in msg.msg

        write_protocol(offer_h2, domain, url, fs=fs, events=self.proxy.tmaster.events, logs=self.proxy.tmaster.logs)

if __name__ == '__main__':
    os.environ['SMOKE_TEST_TIMESTAMP'] = time.strftime("%Y%m%d-%H%M")
    print(os.environ['SMOKE_TEST_TIMESTAMP'])
    os.makedirs('tmp/{}'.format(os.environ['SMOKE_TEST_TIMESTAMP']), exist_ok=True)
    if os.path.islink('tmp/latest'):
        os.remove('tmp/latest')
    os.symlink(os.environ['SMOKE_TEST_TIMESTAMP'], 'tmp/latest')
    pytest.main(args=['-s',
                      '-v',
                      '-x',
                    #   '-n', '16',
                      '--no-flaky-report',
                      *sys.argv
                      ])
