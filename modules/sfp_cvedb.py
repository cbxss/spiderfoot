# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:        sfp_cvedb
# Purpose:     Look up CVE details using Shodan's free CVEDB service including
#              CVSS scores, KEV status, ransomware data, and affected products.
#
# Author:      SpiderFoot Revival Project
#
# Created:     2026-02-07
# Copyright:   (c) Steve Micallef
# Licence:     MIT
# -------------------------------------------------------------------------------

import json
import re
import time

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_cvedb(SpiderFootPlugin):

    meta = {
        'name': "Shodan CVEDB",
        'summary': "Look up CVE details, CVSS scores, CISA KEV status, and affected products from Shodan CVEDB.",
        'flags': [],
        'useCases': ["Investigate", "Passive"],
        'categories': ["Reputation Systems"],
        'dataSource': {
            'website': "https://cvedb.shodan.io/",
            'model': "FREE_NOAUTH_UNLIMITED",
            'references': [
                "https://cvedb.shodan.io/",
            ],
            'favIcon': "https://static.shodan.io/shodan/img/favicon.png",
            'logo': "https://static.shodan.io/developer/img/logo.png",
            'description': "Shodan CVEDB is a free vulnerability lookup service "
            "providing CVE details, CVSS scores, EPSS scores, CISA Known "
            "Exploited Vulnerabilities (KEV) status, ransomware campaign data, "
            "and affected product CPEs. No API key required.",
        }
    }

    opts = {
    }

    optdescs = {
    }

    results = None
    errorState = False

    def setup(self, sfc, userOpts=None):
        if userOpts is None:
            userOpts = {}
        self.sf = sfc
        self.results = self.tempStorage()
        self.errorState = False

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    def watchedEvents(self):
        return [
            "VULNERABILITY_CVE_CRITICAL",
            "VULNERABILITY_CVE_HIGH",
            "VULNERABILITY_CVE_MEDIUM",
            "VULNERABILITY_CVE_LOW",
        ]

    def producedEvents(self):
        return ["RAW_RIR_DATA"]

    def queryCvedb(self, cve_id):
        res = self.sf.fetchUrl(
            f"https://cvedb.shodan.io/cve/{cve_id}",
            timeout=self.opts['_fetchtimeout'],
            useragent="SpiderFoot"
        )
        time.sleep(0.5)

        if res['code'] == "404":
            return None

        if res['content'] is None:
            return None

        try:
            return json.loads(res['content'])
        except Exception as e:
            self.error(f"Error processing CVEDB response: {e}")
            return None

    def handleEvent(self, event):
        eventData = event.data

        if self.errorState:
            return

        match = re.search(r'(CVE-\d{4}-\d{4,})', eventData)
        if not match:
            return

        cve_id = match.group(1)

        if cve_id in self.results:
            return

        self.results[cve_id] = True

        self.debug(f"Looking up CVEDB for {cve_id}")

        data = self.queryCvedb(cve_id)
        if not data:
            self.info(f"No CVEDB data found for {cve_id}")
            return

        parts = [f"Shodan CVEDB: {cve_id}"]

        summary = data.get('summary')
        if summary:
            parts.append(f"Summary: {summary}")

        cvss_v3 = data.get('cvss_v3')
        cvss = data.get('cvss')
        if cvss_v3:
            parts.append(f"CVSS v3: {cvss_v3}")
        elif cvss:
            parts.append(f"CVSS: {cvss}")

        epss = data.get('epss')
        if epss:
            parts.append(f"EPSS: {epss}")

        kev = data.get('kev')
        if kev:
            parts.append("CISA KEV: YES - Known Exploited Vulnerability")

        ransomware = data.get('ransomware_campaign')
        if ransomware:
            parts.append(f"Ransomware Campaign: {ransomware}")

        action = data.get('propose_action')
        if action:
            parts.append(f"Recommended Action: {action}")

        cpes = data.get('cpes', [])
        if cpes:
            cpe_display = cpes[:10]
            parts.append(f"Affected Products ({len(cpes)}): {', '.join(cpe_display)}")
            if len(cpes) > 10:
                parts.append(f"  ... and {len(cpes) - 10} more")

        references = data.get('references', [])
        if references:
            ref_urls = [f"<SFURL>{r}</SFURL>" for r in references[:5]]
            parts.append("References: " + " ".join(ref_urls))

        parts.append(f"<SFURL>https://cvedb.shodan.io/cve/{cve_id}</SFURL>")

        text = "\n".join(parts)

        evt = SpiderFootEvent("RAW_RIR_DATA", text, self.__name__, event)
        self.notifyListeners(evt)

# End of sfp_cvedb class
