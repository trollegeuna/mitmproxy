from mitmproxy.tools.console import options
from mitmproxy.test import taddons

def test_key_pressed_enter():
    with taddons.context() as tctx:
        optlist = options.OptionsList(tctx.master)
        optlist.walker.editing = True
        ans = optlist.keypress((5,5),("enter"))
        #print("This is a = %s" %(ans))
        assert ans == "enter"

def test_key_pressed_m_start():
    with taddons.context() as tctx:
        optlist = options.OptionsList(tctx.master)
        ans = optlist.keypress((5,5),("m_start"))
        assert ans == "m_start"

def test_key_pressed_m_select():
    with taddons.context() as tctx:
        optlist = options.OptionsList(tctx.master)
        ans = optlist.keypress((5,5),("m_select"))
        assert ans == "m_select"


def test_key_pressed_m_select():
    with taddons.context() as tctx:
        optlist = options.OptionsList(tctx.master)
        ans = optlist.keypress((5,5),("m_select"))
        assert ans == "m_select"
