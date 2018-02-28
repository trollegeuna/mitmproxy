import pytest
from mitmproxy.tools.console import options
from mitmproxy.test import taddons

"""This document testes the functionallity of the keypress function in
the Optionlist class created at mitmproxy/tools/console/options.py
"""


def test_esc():
    """Test if we can send an esc key to keypress. This should if it is accepted
    give back a answer of None and no errors
    """
    with taddons.context() as tctx:
        optlist = options.OptionsList(tctx.master)
        optlist.walker.editing = True
        ans = optlist.keypress((5, 5), ("esc"))
        assert ans is None


def test_m_start():
    """Test if m_start key can be sent. If the function will return m_start"""
    with taddons.context() as tctx:
        optlist = options.OptionsList(tctx.master)
        ans = optlist.keypress((5, 5), ("m_start"))
        assert ans == "m_start"


def test_m_select_coices():
    """Test m_select key works with walker.opt.choices set to True"""
    with taddons.context() as tctx:
        optlist = options.OptionsList(tctx.master)
        optlist.walker.set_focus(1)
        optlist.walker.focus_obj.opt.choices = True
        ans = optlist.keypress((5, 5), ("m_select"))
        assert ans == "m_select"


def test_m_select_error():
    """ Test to see if we run keypress with m_select but
        choices and typespec are none and False.
        This should generate a NotImplementedError
    """
    with taddons.context() as tctx:
        optlist = options.OptionsList(tctx.master)
        optlist.walker.set_focus(1)
        optlist.walker.focus_obj.opt.typespec = None
        optlist.walker.focus_obj.opt.choices = False

        with pytest.raises(NotImplementedError):
            optlist.keypress((5, 5), ("m_select"))
