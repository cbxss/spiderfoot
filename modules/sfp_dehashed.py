# -------------------------------------------------------------------------------
# Name:        sfp_dehashed
# Purpose:     Gather breach data from Dehashed API.
#
# Author:      <krishnasis@hotmail.com>
#
# Created:     16-01-2021
# Copyright:   (c) Steve Micallef
# Licence:     MIT
# -------------------------------------------------------------------------------

import json
import time

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_dehashed(SpiderFootPlugin):

    meta = {
        'name': "Dehashed",
        'summary': "Gather breach data from Dehashed API.",
        'flags': ["apikey"],
        'useCases': ["Footprint", "Investigate", "Passive"],
        'categories': ["Leaks, Dumps and Breaches"],
        'dataSource': {
            'website': "https://www.dehashed.com/",
            'model': "COMMERCIAL_ONLY",
            'references': [
                "https://www.dehashed.com/api"
            ],
            'apiKeyInstructions': [
                "Visit https://www.dehashed.com/register",
                "Register an account",
                "Visit https://www.dehashed.com/profile",
                "Generate or refresh your API key under 'API Key'",
            ],
            'favIcon': "https://www.dehashed.com/assets/img/favicon.ico",
            'logo': "https://www.dehashed.com/assets/img/logo.png",
            'description': "Have you been compromised? "
            "DeHashed provides free deep-web scans and protection against credential leaks. "
            "A modern personal asset search engine created for "
            "security analysts, journalists, security companies, "
            "and everyday people to help secure accounts and provide insight on compromised assets. "
            "Free breach alerts & breach notifications.",
        }
    }

    # Default options
    opts = {
        'api_key': '',
        'per_page': 10000,
        'max_pages': 2,
        'pause': 1
    }

    # Option descriptions
    optdescs = {
        'api_key': 'Dehashed API key.',
        'per_page': 'Maximum number of results per page (max: 10000).',
        'max_pages': 'Maximum number of pages to fetch (max depth 10000).',
        'pause': 'Number of seconds to wait between each API call.'
    }

    results = None
    errorState = False

    def setup(self, sfc, userOpts=None):
        if userOpts is None:
            userOpts = {}
        self.sf = sfc
        self.results = self.tempStorage()

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return [
            "DOMAIN_NAME",
            "EMAILADDR"
        ]

    # What events this module produces
    def producedEvents(self):
        return [
            'EMAILADDR',
            'EMAILADDR_COMPROMISED',
            'PASSWORD_COMPROMISED',
            'HASH_COMPROMISED',
            'RAW_RIR_DATA'
        ]

    # Query Dehashed
    def query(self, event, per_page, start):
        query_string = None
        if event.eventType == "EMAILADDR":
            query_string = f'email:"{event.data}"'
        if event.eventType == "DOMAIN_NAME":
            query_string = f'email:"@{event.data}"'

        if not query_string:
            return None

        headers = {
            'Accept': 'application/json',
            'Content-Type': 'application/json',
            'Dehashed-Api-Key': self.opts['api_key']
        }

        payload = {
            "query": query_string,
            "page": start,
            "size": per_page,
            "wildcard": False,
            "regex": False,
            "de_dupe": False
        }

        res = self.sf.fetchUrl("https://api.dehashed.com/v2/search",
                               postData=json.dumps(payload),
                               headers=headers,
                               timeout=15,
                               useragent=self.opts['_useragent'],
                               verify=True)

        time.sleep(self.opts['pause'])

        if res['code'] == "429":
            self.error("Dehashed rate limit hit (too many requests). Please wait before retrying.")
            time.sleep(5)
            res = self.sf.fetchUrl("https://api.dehashed.com/v2/search",
                                   postData=json.dumps(payload),
                                   headers=headers,
                                   timeout=15,
                                   useragent=self.opts['_useragent'],
                                   verify=True)

        if res['code'] == "401":
            self.error("Unauthorized: search subscription and credits required.")
            self.errorState = True
            return None

        if res['code'] == "403":
            self.error("Forbidden: insufficient credits.")
            self.errorState = True
            return None

        if res['code'] != "200":
            self.error(f"Unable to fetch data from Dehashed (HTTP {res['code']}).")
            self.errorState = True
            return None

        if res['content'] is None:
            self.debug('No response from Dehashed')
            return None

        try:
            return json.loads(res['content'])
        except Exception as e:
            self.debug(f"Error processing JSON response: {e}")
            return None

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if srcModuleName == self.__name__:
            return

        if eventData in self.results:
            return

        if self.errorState:
            return

        self.results[eventData] = True

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        if self.opts['api_key'] == "":
            self.error("You enabled sfp_dehashed but did not set an API key!")
            self.errorState = True
            return

        currentPage = 1
        maxPages = self.opts['max_pages']
        perPage = self.opts['per_page']

        while currentPage <= maxPages:
            if self.checkForStop():
                return

            if self.errorState:
                break

            data = self.query(event, perPage, currentPage)

            if not data:
                return

            breachResults = set()
            emailResults = set()

            if not data.get('entries'):
                return

            for row in data.get('entries'):
                email_values = row.get('email')
                password_values = row.get('password')
                hash_values = row.get('hashed_password')
                leakSource = row.get('database_name', 'Unknown')

                emails = email_values if isinstance(email_values, list) else [email_values] if email_values else []
                passwords = password_values if isinstance(password_values, list) else [password_values] if password_values else []
                hashes = hash_values if isinstance(hash_values, list) else [hash_values] if hash_values else []

                for email in emails:
                    if f"{email} [{leakSource}]" in breachResults:
                        continue

                    breachResults.add(f"{email} [{leakSource}]")

                    if eventName == "EMAILADDR":
                        if email == eventData:
                            evt = SpiderFootEvent('EMAILADDR_COMPROMISED', f"{email} [{leakSource}]", self.__name__, event)
                            self.notifyListeners(evt)

                            for password in passwords[:1]:
                                evt = SpiderFootEvent('PASSWORD_COMPROMISED', f"{email}:{password} [{leakSource}]", self.__name__, event)
                                self.notifyListeners(evt)

                            for passwordHash in hashes[:1]:
                                evt = SpiderFootEvent('HASH_COMPROMISED', f"{email}:{passwordHash} [{leakSource}]", self.__name__, event)
                                self.notifyListeners(evt)

                            evt = SpiderFootEvent('RAW_RIR_DATA', str(row), self.__name__, event)
                            self.notifyListeners(evt)

                    if eventName == "DOMAIN_NAME":
                        pevent = SpiderFootEvent("EMAILADDR", email, self.__name__, event)
                        if email not in emailResults:
                            self.notifyListeners(pevent)
                            emailResults.add(email)

                        evt = SpiderFootEvent('EMAILADDR_COMPROMISED', f"{email} [{leakSource}]", self.__name__, pevent)
                        self.notifyListeners(evt)

                        for password in passwords[:1]:
                            evt = SpiderFootEvent('PASSWORD_COMPROMISED', f"{email}:{password} [{leakSource}]", self.__name__, pevent)
                            self.notifyListeners(evt)

                        for passwordHash in hashes[:1]:
                            evt = SpiderFootEvent('HASH_COMPROMISED', f"{email}:{passwordHash} [{leakSource}]", self.__name__, pevent)
                            self.notifyListeners(evt)

                        evt = SpiderFootEvent('RAW_RIR_DATA', str(row), self.__name__, pevent)
                        self.notifyListeners(evt)

            currentPage += 1

            if data.get('total') < self.opts['per_page']:
                break

# End of sfp_dehashed class
