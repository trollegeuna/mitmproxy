import urwid

from mitmproxy.tools.console import flowdetailview
from mitmproxy.tools.console import flowview
from mitmproxy.tools.console import options
from mitmproxy.test import tflow
from mitmproxy.test import tutils
from mitmproxy.test import taddons
from mitmproxy.tools import console
from ... import tservers

def test_flow_details():
    f = tflow.tflow()
    print(f)
    assert flowdetailview.flowdetails("a", f) is not None

    '''
    make one
    class FlowDetails(tabs.Tabs):
        def __init__(self, master):
            self.master = master
            super().__init__([])
            self.show()
            self.last_displayed_body = None

            -> view.
    '''
