import urwid

from mitmproxy.test import tflow
from mitmproxy.tools.console import common


def test_format_flow_if_statement():
    f = tflow.tflow(resp=True)
    f.marked = True
    f.request.is_replay = True
    f.metadata['h2-pushed-stream'] = True
    f.intercepted = True
    f.request.http_version = "HTTP/3.0"
    f.response.headers["content-type"] = "text/html"
    f.response.is_replay = True
    assert common.format_flow(f, True)
    assert common.format_flow(f, True, extended=True)
    assert common.format_flow(f, True, max_url_len=True)
    assert common.format_flow(f, True, extended=True, max_url_len=True)


def test_format_flow_elif_statement_resp_code():
    f = tflow.tflow(resp=True)
    f.intercepted = False
    assert common.format_flow(f, True)
    assert common.format_flow(f, True, extended=True)
    assert common.format_flow(f, True, max_url_len=True)
    assert common.format_flow(f, True, extended=True, max_url_len=True)


def test_format_flow_elif_statement_err_msg():
    f = tflow.tflow(resp=False, err=True)
    assert common.format_flow(f, True)
    assert common.format_flow(f, True, extended=True)
    assert common.format_flow(f, True, max_url_len=True)
    assert common.format_flow(f, True, extended=True, max_url_len=True)


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
