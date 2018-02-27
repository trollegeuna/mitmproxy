import urwid

from mitmproxy.test import tflow
from mitmproxy.tools.console import flowview, flowdetailview
from mitmproxy.utils import human

# BRANCH 1
def test_flowdetail_metadata():
    tf = tflow.tflow()
    tf.metadata = {'data': '123', 'url': 'www.kth.se'}

    # correct port
    assert tf.request.port == 22

    fd = flowdetailview.flowdetails(None, tf)

    # we got an actual response
    assert fd is not None

    # the metadata header has been added correctly
    assert urwid.Text([("head", "Metadata:")]).get_text() == flowdetailview.text[0].get_text()

    # positioning works properly
    assert fd.walker.next_position(0) == 1
    assert fd.walker.prev_position(10) == 9

    # initial focus is 0
    assert fd.walker.focus == 0

    #update focus
    fd.walker.set_focus(1)

    # check new focus
    assert fd.walker.focus == 1
    

# BRANCH 4
def test_flowdetail_resp():
    tf = tflow.tflow(resp=True)
    fd = flowdetailview.flowdetails(None, tf)
    
    assert tf.response.status_code == 200

    # we got an actual response
    assert fd is not None

    # positioning works properly
    assert fd.walker.next_position(0) == 1
    assert fd.walker.prev_position(10) == 9

    # initial focus is 0
    assert fd.walker.focus == 0

    #update focus
    fd.walker.set_focus(1)

    #check new focus
    assert fd.walker.focus == 1
