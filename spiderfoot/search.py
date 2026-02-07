# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         spiderfoot.search
# Purpose:      Search engine API utilities (CVE, Google, Bing).
# -------------------------------------------------------------------------------

import json
import urllib.parse


class SpiderFootSearch:
    """Search engine API utilities (CVE, Google, Bing).

    Needs a back-reference to SpiderFoot for fetchUrl, cacheGet/Put, and logging.
    """

    def __init__(self, sf):
        self._sf = sf

    def cveInfo(self, cveId: str, sources: str = "circl,nist") -> (str, str):
        """Look up a CVE ID for more information in the first available source.

        Args:
            cveId (str): CVE ID, e.g. CVE-2018-15473
            sources (str): Comma-separated list of sources to query. Options available are circl and nist

        Returns:
            (str, str): Appropriate event type and descriptive text
        """
        sources = sources.split(",")
        # VULNERABILITY_GENERAL is the generic type in case we don't have
        # a real/mappable CVE.
        eventType = "VULNERABILITY_GENERAL"

        def cveRating(score: int) -> str:
            if score == "Unknown":
                return None
            if score >= 0 and score <= 3.9:
                return "LOW"
            if score >= 4.0 and score <= 6.9:
                return "MEDIUM"
            if score >= 7.0 and score <= 8.9:
                return "HIGH"
            if score >= 9.0:
                return "CRITICAL"
            return None

        for source in sources:
            jsondata = self._sf.cacheGet(f"{source}-{cveId}", 86400)

            if not jsondata:
                # Fetch data from source
                if source == "nist":
                    ret = self._sf.fetchUrl(f"https://services.nvd.nist.gov/rest/json/cve/1.0/{cveId}", timeout=5)
                if source == "circl":
                    ret = self._sf.fetchUrl(f"https://cve.circl.lu/api/cve/{cveId}", timeout=5)

                if not ret:
                    continue

                if not ret['content']:
                    continue

                self._sf.cachePut(f"{source}-{cveId}", ret['content'])
                jsondata = ret['content']

            try:
                data = json.loads(jsondata)

                if source == "circl":
                    score = data.get('cvss', 'Unknown')
                    rating = cveRating(score)
                    if rating:
                        eventType = f"VULNERABILITY_CVE_{rating}"
                        return (eventType, f"{cveId}\n<SFURL>https://nvd.nist.gov/vuln/detail/{cveId}</SFURL>\n"
                                f"Score: {score}\nDescription: {data.get('summary', 'Unknown')}")

                if source == "nist":
                    try:
                        if data['result']['CVE_Items'][0]['impact'].get('baseMetricV3'):
                            score = data['result']['CVE_Items'][0]['impact']['baseMetricV3']['cvssV3']['baseScore']
                        else:
                            score = data['result']['CVE_Items'][0]['impact']['baseMetricV2']['cvssV2']['baseScore']
                        rating = cveRating(score)
                        if rating:
                            eventType = f"VULNERABILITY_CVE_{rating}"
                    except Exception:
                        score = "Unknown"

                    try:
                        descr = data['result']['CVE_Items'][0]['cve']['description']['description_data'][0]['value']
                    except Exception:
                        descr = "Unknown"

                    return (eventType, f"{cveId}\n<SFURL>https://nvd.nist.gov/vuln/detail/{cveId}</SFURL>\n"
                            f"Score: {score}\nDescription: {descr}")
            except BaseException as e:
                self._sf.debug(f"Unable to parse CVE response from {source.upper()}: {e}")
                continue

        return (eventType, f"{cveId}\nScore: Unknown\nDescription: Unknown")

    def googleIterate(self, searchString: str, opts: dict = None) -> dict:
        """Request search results from the Google API.

        Will return a dict:
        {
          "urls": a list of urls that match the query string,
          "webSearchUrl": url for Google results page,
        }

        Options accepted:
            useragent: User-Agent string to use
            timeout: API call timeout

        Args:
            searchString (str): Google search query
            opts (dict): TBD

        Returns:
            dict: Search results as {"webSearchUrl": "URL", "urls": [results]}
        """
        if not searchString:
            return None

        if opts is None:
            opts = {}

        search_string = searchString.replace(" ", "%20")
        params = urllib.parse.urlencode({
            "cx": opts["cse_id"],
            "key": opts["api_key"],
        })

        response = self._sf.fetchUrl(
            f"https://www.googleapis.com/customsearch/v1?q={search_string}&{params}",
            timeout=opts["timeout"],
        )

        if response['code'] != '200':
            self._sf.error("Failed to get a valid response from the Google API")
            return None

        try:
            response_json = json.loads(response['content'])
        except ValueError:
            self._sf.error("The key 'content' in the Google API response doesn't contain valid JSON.")
            return None

        if "items" not in response_json:
            return None

        # We attempt to make the URL params look as authentically human as possible
        params = urllib.parse.urlencode({
            "ie": "utf-8",
            "oe": "utf-8",
            "aq": "t",
            "rls": "org.mozilla:en-US:official",
            "client": "firefox-a",
        })

        return {
            "urls": [str(k['link']) for k in response_json['items']],
            "webSearchUrl": f"https://www.google.com/search?q={search_string}&{params}"
        }

    def bingIterate(self, searchString: str, opts: dict = None) -> dict:
        """Request search results from the Bing API.

        Will return a dict:
        {
          "urls": a list of urls that match the query string,
          "webSearchUrl": url for bing results page,
        }

        Options accepted:
            count: number of search results to request from the API
            useragent: User-Agent string to use
            timeout: API call timeout

        Args:
            searchString (str): Bing search query
            opts (dict): TBD

        Returns:
            dict: Search results as {"webSearchUrl": "URL", "urls": [results]}
        """
        if not searchString:
            return None

        if opts is None:
            opts = {}

        self._sf.error("Bing Search APIs were retired on 2025-08-11; Bing search is no longer available.")
        return None

        search_string = searchString.replace(" ", "%20")
        params = urllib.parse.urlencode({
            "responseFilter": "Webpages",
            "count": opts["count"],
        })

        response = self._sf.fetchUrl(
            f"https://api.cognitive.microsoft.com/bing/v7.0/search?q={search_string}&{params}",
            timeout=opts["timeout"],
            useragent=opts["useragent"],
            headers={"Ocp-Apim-Subscription-Key": opts["api_key"]},
        )

        if response['code'] != '200':
            self._sf.error("Failed to get a valid response from the Bing API")
            return None

        try:
            response_json = json.loads(response['content'])
        except ValueError:
            self._sf.error("The key 'content' in the bing API response doesn't contain valid JSON.")
            return None

        if ("webPages" in response_json and "value" in response_json["webPages"] and "webSearchUrl" in response_json["webPages"]):
            return {
                "urls": [result["url"] for result in response_json["webPages"]["value"]],
                "webSearchUrl": response_json["webPages"]["webSearchUrl"],
            }

        return None
