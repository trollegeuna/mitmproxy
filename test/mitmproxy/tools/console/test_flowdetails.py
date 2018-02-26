import pytest
from mitmproxy.tools.console import flowview
from mitmproxy.tools.console import flowdetailview

class TestFlowDetails:
    def test_arg_null(self):
        flowdetclass = flowview.FlowDetails(0)
        answer = flowdetailview.flowdetails(flowdetclass.view, flowdetclass.flow)
        assert answer
