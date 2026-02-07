# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:        sfp_epss
# Purpose:     Enrich CVE findings with EPSS (Exploit Prediction Scoring System)
#              scores from FIRST.org.
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


class sfp_epss(SpiderFootPlugin):

    meta = {
        'name': "EPSS",
        'summary': "Enrich CVE findings with EPSS exploit probability scores from FIRST.org.",
        'flags': [],
        'useCases': ["Investigate", "Passive"],
        'categories': ["Reputation Systems"],
        'dataSource': {
            'website': "https://www.first.org/epss/",
            'model': "FREE_NOAUTH_UNLIMITED",
            'references': [
                "https://www.first.org/epss/api",
            ],
            'favIcon': "https://www.first.org/favicon.ico",
            'logo': "https://www.first.org/resources/images/logo_v2.png",
            'description': "The Exploit Prediction Scoring System (EPSS) is a data-driven "
            "effort for estimating the probability that a software vulnerability "
            "will be exploited in the wild within 30 days. "
            "EPSS scores range from 0 to 1 (0% to 100%). No API key required.",
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

    def queryEpss(self, cve_id):
        res = self.sf.fetchUrl(
            f"https://api.first.org/data/v1/epss?cve={cve_id}",
            timeout=self.opts['_fetchtimeout'],
            useragent="SpiderFoot"
        )
        time.sleep(0.5)

        if res['content'] is None:
            return None

        try:
            data = json.loads(res['content'])
            if data.get('status') != 'OK':
                return None
            results = data.get('data', [])
            if not results:
                return None
            return results[0]
        except Exception as e:
            self.error(f"Error processing EPSS response: {e}")
            return None

    def handleEvent(self, event):
        eventData = event.data

        if self.errorState:
            return

        # Extract CVE ID from event data
        match = re.search(r'(CVE-\d{4}-\d{4,})', eventData)
        if not match:
            return

        cve_id = match.group(1)

        if cve_id in self.results:
            return

        self.results[cve_id] = True

        self.debug(f"Looking up EPSS score for {cve_id}")

        result = self.queryEpss(cve_id)
        if not result:
            self.info(f"No EPSS data found for {cve_id}")
            return

        epss_score = float(result.get('epss', 0))
        percentile = float(result.get('percentile', 0))

        if percentile > 0.9:
            risk = "CRITICAL"
        elif percentile > 0.7:
            risk = "HIGH"
        elif percentile > 0.5:
            risk = "MODERATE"
        else:
            risk = "LOW"

        text = (
            f"EPSS for {cve_id}: {epss_score:.5f} "
            f"({epss_score * 100:.2f}% chance of exploitation in 30 days)\n"
            f"Percentile: {percentile * 100:.1f}% "
            f"(higher than {percentile * 100:.0f}% of all scored CVEs)\n"
            f"Risk Level: {risk}\n"
            f"<SFURL>https://www.first.org/epss/</SFURL>"
        )

        evt = SpiderFootEvent("RAW_RIR_DATA", text, self.__name__, event)
        self.notifyListeners(evt)

# End of sfp_epss class
