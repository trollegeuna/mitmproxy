import time

from mitmproxy.tools.console import flowdetailview
from mitmproxy.test import tflow


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

    # pretending that Transport Layer Security is established to reach branch 15
    testflow.client_conn.tls_established = True

    # we can use a None valued 'state' because state isn't used in the flowdetails function
    searchable_box_widget = flowdetailview.flowdetails(None, testflow)

    # check that the returned searchable box widget has positions, thus that it returned correctly from flowdetails
    assert searchable_box_widget.walker.positions is not None

    # check that the text added to parts (that client connection is established and timestamp for it) is actually added to widget list
    assert searchable_box_widget.body[11].widget_list[1].text == "Client conn. established" and searchable_box_widget.body[11].widget_list[2].text == "2000-01-01 00:00:00.000"


# branch 19
def test_flow_details_rest_timestamp():
        # creating a test flow (mock) from tflow file, to test flowdetails who needs a http flow as input
        testflow = tflow.tflow(resp=True)

        # set a mock timestamp on the response to reach branch 19
        testflow.response.timestamp_start = time.time()

        # we can use a None valued 'state' because state isn't used in the flowdetails function
        searchable_box_widget = flowdetailview.flowdetails(None, testflow)

        # check that the returned searchable box widget has positions, thus that it returned correctly from flowdetails
        assert searchable_box_widget.walker.positions is not None

        # check that text added to parts (Response complete and first byte) is actally added to widget list
        assert searchable_box_widget.body[17].widget_list[1].text == "Response complete" and searchable_box_widget.body[18].widget_list[1].text == "First response byte"
