import urwid

from mitmproxy.test import tflow
from mitmproxy.tools.console import common


def test_format_flow():
    f = tflow.tflow(resp=True)
    f.marked = True
    f.request.is_replay = True
    f.metadata['h2-pushed-stream'] = True
    f.intercepted = True
    f.asked = False
    f.response.status_code = 200  # 1/2
    f.request.http_version = "HTTP/3.0"
    f.response.headers["content-type"] = "text/html"
    f.response.is_replay = True
    assert common.format_flow(f, True)
    assert common.format_flow(f, True, extended=True)
    assert common.format_flow(f, True, hostheader=True)
    assert common.format_flow(f, True, max_url_len=True)
    assert common.format_flow(f, True, extended=True, hostheader=True)
    assert common.format_flow(f, True, extended=True, max_url_len=True)
    assert common.format_flow(f, True, hostheader=True, max_url_len=True)
    assert common.format_flow(f, True, extended=True, hostheader=True, max_url_len=True)
    test_format_flow_elif_branch_9()
    test_format_flow_elif_branch_10()
    test_format_flow_elif_branch_21()


def test_format_flow_elif_branch_9():
    f = tflow.tflow(resp=True)
    f.intercepted = False
    f.response.status_code = 200
    assert common.format_flow(f, True)


def test_format_flow_elif_branch_10():
    f = tflow.tflow(resp=True)
    f.intercepted = False
    f.response.status_code = 900
    f.error = True
    f.error.msg = "test_error"
    assert common.format_flow(f, True)


def test_format_flow_elif_branch_21():
    f = tflow.tflow(resp=True)
    f.request.http_version = "HTTP/3.0"
    f.response.status_code = 900
    f.error.msg = True
    assert common.format_flow(f, True)


def test_format_keyvals():
    assert common.format_keyvals(
        [
            ("aa", "bb"),
            ("cc", "dd"),
            ("ee", None),
        ]
    )
    wrapped = urwid.BoxAdapter(
        urwid.ListBox(
            urwid.SimpleFocusListWalker(
                common.format_keyvals([("foo", "bar")])
            )
        ), 1
    )
    assert wrapped.render((30, ))
    assert common.format_keyvals(
        [
            ("aa", wrapped)
        ]
    )
