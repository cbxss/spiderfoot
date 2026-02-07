# test_sfwebui.py
import os
import unittest

from fastapi.testclient import TestClient

from spiderfoot import SpiderFootHelpers
from sfwebui import create_app


class TestSpiderFootWebUiRoutes(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        default_config = {
            '_debug': False,
            '__logging': True,
            '__outputfilter': None,
            '_useragent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:62.0) Gecko/20100101 Firefox/62.0',
            '_dnsserver': '',
            '_fetchtimeout': 5,
            '_internettlds': 'https://publicsuffix.org/list/effective_tld_names.dat',
            '_internettlds_cache': 72,
            '_genericusers': ",".join(SpiderFootHelpers.usernamesFromWordlists(['generic-usernames'])),
            '__database': f"{SpiderFootHelpers.dataPath()}/spiderfoot.test.db",
            '__modules__': None,
            '__correlationrules__': None,
            '_socks1type': '',
            '_socks2addr': '',
            '_socks3port': '',
            '_socks4user': '',
            '_socks5pwd': '',
            '__logstdout': False
        }

        default_web_config = {
            'root': '/'
        }

        mod_dir = os.path.dirname(os.path.abspath(__file__)) + '/../../modules/'
        default_config['__modules__'] = SpiderFootHelpers.loadModulesAsDict(mod_dir, ['sfp_template.py'])

        app = create_app(default_web_config, default_config)
        cls.client = TestClient(app)

    def test_invalid_page_returns_404(self):
        response = self.client.get("/doesnotexist")
        self.assertEqual(response.status_code, 404)

    def test_static_returns_200(self):
        response = self.client.get("/static/img/spiderfoot-header.png")
        self.assertEqual(response.status_code, 200)

    def test_scaneventresultexport_invalid_scan_id_returns_200(self):
        response = self.client.get("/scaneventresultexport?id=doesnotexist&type=doesnotexist")
        self.assertEqual(response.status_code, 200)

    def test_scaneventresultexportmulti(self):
        response = self.client.get("/scaneventresultexportmulti?ids=doesnotexist")
        self.assertEqual(response.status_code, 200)

    def test_scansearchresultexport(self):
        response = self.client.get("/scansearchresultexport?id=doesnotexist")
        self.assertEqual(response.status_code, 200)

    def test_scanexportjsonmulti(self):
        response = self.client.get("/scanexportjsonmulti?ids=doesnotexist")
        self.assertEqual(response.status_code, 200)

    def test_scanviz(self):
        response = self.client.get("/scanviz?id=doesnotexist")
        self.assertEqual(response.status_code, 200)

    def test_scanvizmulti(self):
        response = self.client.get("/scanvizmulti?ids=doesnotexist")
        self.assertEqual(response.status_code, 200)

    def test_scanopts_invalid_scan_returns_200(self):
        response = self.client.get("/scanopts?id=doesnotexist")
        self.assertEqual(response.status_code, 200)

    def test_rerunscan(self):
        response = self.client.post("/rerunscan", data={"id": "doesnotexist"})
        self.assertEqual(response.status_code, 200)
        self.assertIn("Invalid scan ID.", response.text)

    def test_rerunscanmulti_invalid_scan_id_returns_200(self):
        response = self.client.post("/rerunscanmulti", data={"ids": "doesnotexist"})
        self.assertEqual(response.status_code, 200)
        self.assertIn("Invalid scan ID.", response.text)

    def test_newscan_returns_200(self):
        response = self.client.get("/newscan")
        self.assertEqual(response.status_code, 200)
        self.assertIn("Scan Name", response.text)
        self.assertIn("Scan Target", response.text)

    def test_clonescan(self):
        response = self.client.get("/clonescan?id=doesnotexist")
        self.assertEqual(response.status_code, 200)
        self.assertIn("Invalid scan ID.", response.text)

    def test_index_returns_200(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)

    def test_scaninfo_invalid_scan_returns_200(self):
        response = self.client.get("/scaninfo?id=doesnotexist")
        self.assertEqual(response.status_code, 200)
        self.assertIn("Scan ID not found.", response.text)

    @unittest.skip("todo")
    def test_opts_returns_200(self):
        response = self.client.get("/opts")
        self.assertEqual(response.status_code, 200)

    def test_optsexport(self):
        response = self.client.get("/optsexport")
        self.assertEqual(response.status_code, 200)
        response = self.client.get("/optsexport?pattern=api_key")
        self.assertEqual(response.status_code, 200)
        self.assertIn("attachment; filename=\"SpiderFoot.cfg\"", response.headers.get("Content-Disposition", ""))
        self.assertIn(":api_key=", response.text)

    def test_optsraw(self):
        response = self.client.get("/optsraw")
        self.assertEqual(response.status_code, 200)

    def test_scandelete_invalid_scan_id_returns_404(self):
        response = self.client.post("/scandelete", data={"id": "doesnotexist"})
        self.assertEqual(response.status_code, 404)
        self.assertIn('Scan doesnotexist does not exist', response.text)

    @unittest.skip("todo")
    def test_savesettings(self):
        response = self.client.get("/savesettings")
        self.assertEqual(response.status_code, 200)

    @unittest.skip("todo")
    def test_savesettingsraw(self):
        response = self.client.get("/savesettingsraw")
        self.assertEqual(response.status_code, 200)

    def test_resultsetfp(self):
        response = self.client.post("/resultsetfp", data={"id": "doesnotexist", "resultids": "doesnotexist", "fp": "1"})
        self.assertEqual(response.status_code, 200)
        self.assertIn("No IDs supplied.", response.text)

    def test_eventtypes(self):
        response = self.client.get("/eventtypes")
        self.assertEqual(response.status_code, 200)
        self.assertIn('"DOMAIN_NAME"', response.text)

    def test_modules(self):
        response = self.client.get("/modules")
        self.assertEqual(response.status_code, 200)
        self.assertIn('"name":', response.text)

    def test_ping_returns_200(self):
        response = self.client.get("/ping")
        self.assertEqual(response.status_code, 200)
        self.assertIn('"SUCCESS"', response.text)

    def test_query_returns_200(self):
        response = self.client.post("/query", data={"query": "SELECT 1"})
        self.assertEqual(response.status_code, 200)
        self.assertIn('"1":', response.text)

    def test_startscan_invalid_scan_name_returns_error(self):
        response = self.client.post("/startscan", data={"scanname": "", "scantarget": "", "modulelist": "", "typelist": "", "usecase": ""})
        self.assertEqual(response.status_code, 200)
        self.assertIn('Invalid request: scan name was not specified.', response.text)

    def test_startscan_invalid_scan_target_returns_error(self):
        response = self.client.post("/startscan", data={"scanname": "example-scan", "scantarget": "", "modulelist": "", "typelist": "", "usecase": ""})
        self.assertEqual(response.status_code, 200)
        self.assertIn('Invalid request: scan target was not specified.', response.text)

    def test_startscan_unrecognized_scan_target_returns_error(self):
        response = self.client.post("/startscan", data={"scanname": "example-scan", "scantarget": "invalid-target", "modulelist": "doesnotexist", "typelist": "doesnotexist", "usecase": "doesnotexist"})
        self.assertEqual(response.status_code, 200)
        self.assertIn('Invalid target type. Could not recognize it as a target SpiderFoot supports.', response.text)

    def test_startscan_invalid_modules_returns_error(self):
        response = self.client.post("/startscan", data={"scanname": "example-scan", "scantarget": "spiderfoot.net", "modulelist": "", "typelist": "", "usecase": ""})
        self.assertEqual(response.status_code, 200)
        self.assertIn('Invalid request: no modules specified for scan.', response.text)

    def test_startscan_invalid_typelist_returns_error(self):
        response = self.client.post("/startscan", data={"scanname": "example-scan", "scantarget": "spiderfoot.net", "modulelist": "", "typelist": "doesnotexist", "usecase": ""})
        self.assertEqual(response.status_code, 200)
        self.assertIn('Invalid request: no modules specified for scan.', response.text)

    def test_startscan_should_start_a_scan(self):
        response = self.client.post(
            "/startscan",
            data={"scanname": "spiderfoot.net", "scantarget": "spiderfoot.net", "modulelist": "doesnotexist", "typelist": "doesnotexist", "usecase": "doesnotexist"},
            follow_redirects=False
        )
        self.assertIn(response.status_code, [302, 303, 200])

    def test_stopscan_invalid_scan_id_returns_404(self):
        response = self.client.post("/stopscan", data={"id": "doesnotexist"})
        self.assertEqual(response.status_code, 404)
        self.assertIn('Scan doesnotexist does not exist', response.text)

    def test_scanlog_invalid_scan_returns_200(self):
        response = self.client.get("/scanlog?id=doesnotexist")
        self.assertEqual(response.status_code, 200)

    def test_scanerrors_invalid_scan_returns_200(self):
        response = self.client.get("/scanerrors?id=doesnotexist")
        self.assertEqual(response.status_code, 200)

    def test_scanlist_returns_200(self):
        response = self.client.get("/scanlist")
        self.assertEqual(response.status_code, 200)

    def test_scanstatus_invalid_scan_returns_200(self):
        response = self.client.get("/scanstatus?id=doesnotexist")
        self.assertEqual(response.status_code, 200)

    def test_scansummary_invalid_scan_returns_200(self):
        response = self.client.get("/scansummary?id=doesnotexist&by=anything")
        self.assertEqual(response.status_code, 200)

    def test_scaneventresults_invalid_scan_returns_200(self):
        response = self.client.get("/scaneventresults?id=doesnotexist&eventType=anything")
        self.assertEqual(response.status_code, 200)

    def test_scaneventresultsunique_invalid_scan_returns_200(self):
        response = self.client.get("/scaneventresultsunique?id=doesnotexist&eventType=anything")
        self.assertEqual(response.status_code, 200)

    def test_search_returns_200(self):
        response = self.client.get("/search?id=doesnotexist&eventType=doesnotexist&value=doesnotexist")
        self.assertEqual(response.status_code, 200)

    def test_scanhistory_invalid_scan_returns_200(self):
        response = self.client.get("/scanhistory?id=doesnotexist")
        self.assertEqual(response.status_code, 200)

    def test_scanelementtypediscovery_invalid_scan_id_returns_200(self):
        response = self.client.get("/scanelementtypediscovery?id=doesnotexist&eventType=anything")
        self.assertEqual(response.status_code, 200)
