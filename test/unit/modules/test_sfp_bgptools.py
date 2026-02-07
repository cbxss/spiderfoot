import pytest
import unittest

from modules.sfp_bgptools import sfp_bgptools
from sflib import SpiderFoot


@pytest.mark.usefixtures
class TestModuleBgptools(unittest.TestCase):

    def test_opts(self):
        module = sfp_bgptools()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        sf = SpiderFoot(self.default_options)
        module = sfp_bgptools()
        module.setup(sf, dict())

    def test_watchedEvents_should_return_list(self):
        module = sfp_bgptools()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = sfp_bgptools()
        self.assertIsInstance(module.producedEvents(), list)
