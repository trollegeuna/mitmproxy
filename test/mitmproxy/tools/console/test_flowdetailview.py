import urwid

from mitmproxy.tools.console import flowdetailview
from mitmproxy.tools.console import flowview
from mitmproxy.tools.console import options
from mitmproxy.test import tflow
from mitmproxy.tools import console
from ... import tservers

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

# branch 15
def test_flow_details_tls_established():
    # creating a test flow (mock) from tflow file, to test flowdetails who needs a http flow as input
    testflow = tflow.tflow()

    testflow.client_conn.tls_established = True # pretending that Transport Layer Security is established to reach branch 15

     # we can use a None valued 'state' because state isn't used in the flowdetails function
    searchable_box_widget = flowdetailview.flowdetails(None, testflow)

    # check that the returned searchable box widget has positions, thus that it returned correctly from flowdetails
    assert searchable_box_widget.walker.positions is not None
