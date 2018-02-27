import urwid
from mitmproxy.tools.console import flowdetailview
from mitmproxy.tools.console import flowview
from mitmproxy.tools.console import options
from mitmproxy.test import tflow
from mitmproxy.test import tutils
from mitmproxy.test import taddons
from mitmproxy.tools import console
from ... import tservers
from mitmproxy import certs
import os

#this just writes over 'test_output_flowdetails.txt' with an empty textfile
def test_not_a_test():
    with open("test_output_flowdetails.txt", "w") as text_file:
        text_file.close()

def test_flowflowdetailview_cert():
    #import an example certificate from file
    with open(tutils.test_data.path("mitmproxy/net/data/text_cert"), "rb") as f:
        d = f.read()
    #create a certificate object
    c1 = certs.Cert.from_pem(d)
    # creating a test flow (mock) from tflow file, to test flowdetails who needs a http flow as input
    f = tflow.tflow()
    #set the certificate for the server connection to imporove coverage for branch 6 and 7
    f.server_conn.cert=c1

    fdv = flowdetailview.flowdetails(None, f)
    # assert that the the flow detail view was created
    assert fdv is not None
    # assert that the server certificate was included
    assert fdv.body[3].text == 'Server Certificate:'
    # assert that the correct "Dummy" certificate from google is incluuded in the view
    assert fdv.body[5].widget_list[2].text == b'28:F0:44:EC:65:68:5A:A6:AE:0D:72:95:BD:8E:B4:6F:A5:65:C7:47'
    assert "google.se" in fdv.body[11].widget_list[2].text


def test_flowflowdetailview_server_tls_established():
    # creating a test flow (mock) from tflow file, to test flowdetails who needs a http flow as input
    f = tflow.tflow()
    # pretending that Transport Layer Security is established to reach branch 17
    f.server_conn.tls_established = True
    # we can use a None valued 'state' because state isn't used in the flowdetails function
    fdv = flowdetailview.flowdetails(None, f)
    # check that the flowdetailsview is not none, thus that it returned correctly from flowdetails
    assert fdv is not None
    # check that in fact the tls-handshake flag is set
    assert fdv.body[16].widget_list[1].text == 'Server conn. TLS handshake'
