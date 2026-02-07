import pytest
import threading
import unittest
from unittest.mock import MagicMock

from modules.sfp_accounts import sfp_accounts
from sflib import SpiderFoot


@pytest.mark.usefixtures
class TestModuleAccounts(unittest.TestCase):

    def test_opts(self):
        module = sfp_accounts()
        # Every described option must exist in opts (opts may also contain
        # runtime-injected keys like _fetchtimeout, so we check subset)
        for key in module.optdescs:
            self.assertIn(key, module.opts)

    def test_setup(self):
        sf = SpiderFoot(self.default_options)
        module = sfp_accounts()
        module.setup(sf, dict())

    def test_watchedEvents_should_return_list(self):
        module = sfp_accounts()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = sfp_accounts()
        self.assertIsInstance(module.producedEvents(), list)

    def _make_module(self):
        """Create a configured sfp_accounts module with mocked SpiderFoot."""
        sf = SpiderFoot(self.default_options)
        module = sfp_accounts()
        # Reset opts to a fresh copy to avoid polluting the class-level
        # mutable default dict (which would break test_modules.py assertions).
        module.opts = dict(module.opts)
        module.setup(sf, {
            '_fetchtimeout': 5,
            '_useragent': 'SpiderFoot',
            '_genericusers': 'admin,root',
        })
        module.siteResults = {}
        module.lock = threading.Lock()
        return module

    def _make_site(self, key_name='uri_check', **overrides):
        """Build a minimal WMN site dict.

        Args:
            key_name: 'uri_check' (new WMN) or 'check_uri' (old WMN)
        """
        site = {
            key_name: 'https://example.com/user/{account}',
            'name': 'TestSite',
            'cat': 'Social',
            'e_code': '200',
            'm_code': '404',
            'e_string': 'profile-found',
        }
        site.update(overrides)
        return site

    # ------------------------------------------------------------------ #
    # Key name compatibility: uri_check (new) vs check_uri (old)
    # ------------------------------------------------------------------ #

    def test_checkSite_uri_check_key_finds_account(self):
        """New WMN format with 'uri_check' key should detect accounts."""
        module = self._make_module()
        site = self._make_site(key_name='uri_check')

        module.sf.fetchUrl = MagicMock(return_value={
            'content': 'hello profile-found testuser page',
            'code': '200',
        })

        module.checkSite('testuser', site)

        retname = "TestSite (Category: Social)\n<SFURL>https://example.com/user/testuser</SFURL>"
        self.assertTrue(module.siteResults.get(retname),
                        "Should detect account with uri_check key")

    def test_checkSite_check_uri_key_finds_account(self):
        """Old WMN format with 'check_uri' key should still work."""
        module = self._make_module()
        site = self._make_site(key_name='check_uri')

        module.sf.fetchUrl = MagicMock(return_value={
            'content': 'hello profile-found testuser page',
            'code': '200',
        })

        module.checkSite('testuser', site)

        retname = "TestSite (Category: Social)\n<SFURL>https://example.com/user/testuser</SFURL>"
        self.assertTrue(module.siteResults.get(retname),
                        "Should detect account with check_uri key (legacy)")

    def test_checkSite_no_uri_key_skips(self):
        """Site with neither uri_check nor check_uri should be skipped."""
        module = self._make_module()
        site = {'name': 'BadSite', 'cat': 'Social'}

        module.sf.fetchUrl = MagicMock()
        module.checkSite('testuser', site)

        module.sf.fetchUrl.assert_not_called()
        self.assertEqual(module.siteResults, {})

    # ------------------------------------------------------------------ #
    # Bytes vs str content handling
    # ------------------------------------------------------------------ #

    def test_checkSite_bytes_content_finds_account(self):
        """fetchUrl returning bytes content should not crash."""
        module = self._make_module()
        site = self._make_site()

        module.sf.fetchUrl = MagicMock(return_value={
            'content': b'hello profile-found testuser page',
            'code': '200',
        })

        module.checkSite('testuser', site)

        retname = "TestSite (Category: Social)\n<SFURL>https://example.com/user/testuser</SFURL>"
        self.assertTrue(module.siteResults.get(retname),
                        "Should detect account even when content is bytes")

    def test_checkSite_bytes_content_no_match(self):
        """fetchUrl returning bytes without e_string should mark False."""
        module = self._make_module()
        site = self._make_site()

        module.sf.fetchUrl = MagicMock(return_value={
            'content': b'nothing here testuser',
            'code': '200',
        })

        module.checkSite('testuser', site)

        retname = "TestSite (Category: Social)\n<SFURL>https://example.com/user/testuser</SFURL>"
        self.assertFalse(module.siteResults.get(retname),
                         "Should not detect account without e_string match")

    # ------------------------------------------------------------------ #
    # e_string / m_string / e_code matching logic
    # ------------------------------------------------------------------ #

    def test_checkSite_missing_e_string_returns_false(self):
        """Content without e_string should not detect account."""
        module = self._make_module()
        site = self._make_site()

        module.sf.fetchUrl = MagicMock(return_value={
            'content': 'no match here testuser',
            'code': '200',
        })

        module.checkSite('testuser', site)

        retname = "TestSite (Category: Social)\n<SFURL>https://example.com/user/testuser</SFURL>"
        self.assertFalse(module.siteResults.get(retname))

    def test_checkSite_m_string_present_returns_false(self):
        """If m_string is found in content, account should not be detected."""
        module = self._make_module()
        site = self._make_site(m_string='not-found-marker')

        module.sf.fetchUrl = MagicMock(return_value={
            'content': 'profile-found not-found-marker testuser',
            'code': '200',
        })

        module.checkSite('testuser', site)

        retname = "TestSite (Category: Social)\n<SFURL>https://example.com/user/testuser</SFURL>"
        self.assertFalse(module.siteResults.get(retname))

    def test_checkSite_wrong_status_code_returns_false(self):
        """Non-matching e_code should not detect account."""
        module = self._make_module()
        site = self._make_site()

        module.sf.fetchUrl = MagicMock(return_value={
            'content': 'profile-found testuser',
            'code': '404',
        })

        module.checkSite('testuser', site)

        retname = "TestSite (Category: Social)\n<SFURL>https://example.com/user/testuser</SFURL>"
        self.assertFalse(module.siteResults.get(retname))

    def test_checkSite_musthavename_off_still_detects(self):
        """With musthavename disabled, account detected even without name in content."""
        module = self._make_module()
        module.opts['musthavename'] = False
        site = self._make_site()

        module.sf.fetchUrl = MagicMock(return_value={
            'content': 'profile-found some other text',
            'code': '200',
        })

        module.checkSite('testuser', site)

        retname = "TestSite (Category: Social)\n<SFURL>https://example.com/user/testuser</SFURL>"
        self.assertTrue(module.siteResults.get(retname))

    def test_checkSite_musthavename_on_without_name_returns_false(self):
        """With musthavename enabled, missing name in content should not detect."""
        module = self._make_module()
        module.opts['musthavename'] = True
        site = self._make_site()

        module.sf.fetchUrl = MagicMock(return_value={
            'content': 'profile-found but no username here',
            'code': '200',
        })

        module.checkSite('testuser', site)

        retname = "TestSite (Category: Social)\n<SFURL>https://example.com/user/testuser</SFURL>"
        self.assertFalse(module.siteResults.get(retname))

    def test_checkSite_empty_content_returns_false(self):
        """Empty/None content should mark site as False."""
        module = self._make_module()
        site = self._make_site()

        module.sf.fetchUrl = MagicMock(return_value={
            'content': None,
            'code': '200',
        })

        module.checkSite('testuser', site)

        retname = "TestSite (Category: Social)\n<SFURL>https://example.com/user/testuser</SFURL>"
        self.assertFalse(module.siteResults.get(retname))

    # ------------------------------------------------------------------ #
    # pretty_uri / uri_pretty handling
    # ------------------------------------------------------------------ #

    def test_checkSite_uri_pretty_used_in_retname(self):
        """uri_pretty should be used for display URL when present."""
        module = self._make_module()
        site = self._make_site(uri_pretty='https://example.com/u/{account}')

        module.sf.fetchUrl = MagicMock(return_value={
            'content': 'profile-found testuser',
            'code': '200',
        })

        module.checkSite('testuser', site)

        retname = "TestSite (Category: Social)\n<SFURL>https://example.com/u/testuser</SFURL>"
        self.assertIn(retname, module.siteResults)

    def test_checkSite_pretty_uri_fallback(self):
        """Legacy pretty_uri key should work as fallback."""
        module = self._make_module()
        site = self._make_site(pretty_uri='https://example.com/p/{account}')

        module.sf.fetchUrl = MagicMock(return_value={
            'content': 'profile-found testuser',
            'code': '200',
        })

        module.checkSite('testuser', site)

        retname = "TestSite (Category: Social)\n<SFURL>https://example.com/p/testuser</SFURL>"
        self.assertIn(retname, module.siteResults)

    # ------------------------------------------------------------------ #
    # strip_bad_char
    # ------------------------------------------------------------------ #

    def test_checkSite_strip_bad_char(self):
        """Characters in strip_bad_char should be removed from username."""
        module = self._make_module()
        module.opts['musthavename'] = False
        site = self._make_site(strip_bad_char=['.', '_'])

        calls = []

        def capture_fetchUrl(url, **kwargs):
            calls.append(url)
            return {'content': 'profile-found', 'code': '200'}

        module.sf.fetchUrl = capture_fetchUrl
        module.checkSite('test.user_name', site)

        # URL should have dots and underscores stripped
        self.assertEqual(calls[0], 'https://example.com/user/testusername')

    # ------------------------------------------------------------------ #
    # checkSites integration
    # ------------------------------------------------------------------ #

    def test_checkSites_returns_found_sites(self):
        """checkSites should return list of sites where account was found."""
        module = self._make_module()

        sites = [
            self._make_site(name='FoundSite'),
            self._make_site(name='MissingSite'),
        ]

        def mock_fetchUrl(url, **kwargs):
            if 'FoundSite' in str(sites[0].get('name', '')):
                pass
            return {
                'content': 'profile-found testuser page',
                'code': '200',
            }

        # Mock fetchUrl to return match for first site, miss for second
        call_count = [0]

        def smart_fetchUrl(url, **kwargs):
            call_count[0] += 1
            if call_count[0] == 1:
                return {'content': 'profile-found testuser page', 'code': '200'}
            return {'content': 'page not found', 'code': '404'}

        module.sf.fetchUrl = smart_fetchUrl
        results = module.checkSites('testuser', sites)

        self.assertEqual(len(results), 1)
        self.assertIn('FoundSite', results[0])

    # ------------------------------------------------------------------ #
    # generatePermutations
    # ------------------------------------------------------------------ #

    def test_generatePermutations_returns_list(self):
        module = self._make_module()
        perms = module.generatePermutations('testuser')
        self.assertIsInstance(perms, list)
        self.assertGreater(len(perms), 0)

    def test_generatePermutations_empty_username(self):
        module = self._make_module()
        perms = module.generatePermutations('')
        self.assertEqual(perms, [])

    def test_generatePermutations_upto_limits(self):
        module = self._make_module()
        perms = module.generatePermutations('testuser', upto=5)
        self.assertLessEqual(len(perms), 5)
