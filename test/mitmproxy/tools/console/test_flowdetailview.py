import urwid

from mitmproxy.tools.console import flowdetailview
from mitmproxy.tools.console import flowview
from mitmproxy.tools.console import options
from mitmproxy.test import tflow
from mitmproxy.tools import console
from ... import tservers
'''
def test_standard():
    testflow = tflow.tflow()

    searchable_box_widget = flowdetailview.flowdetails(None, testflow)
'''
# branch 5
def test_flow_details_proto_negotiated():
    # creating a test flow (mock) from tflow file, to test flowdetails who needs a http flow as input
    testflow = tflow.tflow()

     # test protocol negotiated, to be able to reach branch 5
    testflow.server_conn.alpn_proto_negotiated = b'tcp'

     # we can use a None valued 'state' because state isn't used in the flowdetails function
    searchable_box_widget = flowdetailview.flowdetails(None, testflow)

    # check that the returned searchable box widget has positions, thus that it returned correctly from flowdetails
    assert searchable_box_widget.walker.positions is not None

    # check that the things added to parts (proto negotiated) in branch 5 is actually added to widget list
    assert searchable_box_widget.body[3].widget_list[1].text == "ALPN" and searchable_box_widget.body[3].widget_list[2].text == b'tcp'

# branch 15
def test_flow_details_tls_established():
    # creating a test flow (mock) from tflow file, to test flowdetails who needs a http flow as input
    testflow = tflow.tflow()

    testflow.client_conn.tls_established = True # pretending that Transport Layer Security is established to reach branch 15

     # we can use a None valued 'state' because state isn't used in the flowdetails function
    searchable_box_widget = flowdetailview.flowdetails(None, testflow)

    # check that the returned searchable box widget has positions, thus that it returned correctly from flowdetails
    assert searchable_box_widget.walker.positions is not None

    # check that the text added to parts (that client connection is established and timestamp for it) is actually added to widget list
    assert searchable_box_widget.body[11].widget_list[1].text == "Client conn. established" and searchable_box_widget.body[11].widget_list[2].text == "2000-01-01 00:00:00.000"

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

    