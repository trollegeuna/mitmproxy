import urwid

from mitmproxy.test import tflow
from mitmproxy.tools.console import flowview, flowdetailview
from mitmproxy.utils import human

# BRANCH 1
def test_flowdetail_metadata():
    tf = tflow.tflow()
    
    # mock metadata
    tf.metadata = {"data": "123", "url": "www.kth.se"}

    # correct port
    assert tf.request.port == 22

    fd = flowdetailview.flowdetails(None, tf)

    # we got an actual response
    assert fd is not None

    # the metadata header has been added correctly
    assert urwid.Text([("head", "Metadata:")]).get_text() == fd.body[0].get_text()

    # the provided metadata is there
    assert fd.body[1].widget_list[1].text == "data" and fd.body[1].widget_list[2].text == "'123'"  # no idea why it appends ' ' on the second index does this
    assert fd.body[2].widget_list[1].text == "url" and fd.body[2].widget_list[2].text == "'www.kth.se'" # does it here aswell

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
    
    # correct status_code
    assert tf.response.status_code == 200

    fd = flowdetailview.flowdetails(None, tf)

    # we got an actual response
    assert fd is not None

    # assert that the correct data has been added
    assert fd.body[3].widget_list[1].text == "HTTP Version" and fd.body[3].widget_list[2].text == "HTTP/1.1"

    # positioning works properly
    assert fd.walker.next_position(0) == 1
    assert fd.walker.prev_position(10) == 9

    # initial focus is 0
    assert fd.walker.focus == 0

    # update focus
    fd.walker.set_focus(1)

    #check new focus
    assert fd.walker.focus == 1

    
