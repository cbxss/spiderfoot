# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:        sfp_mastodon
# Purpose:     Search Mastodon/Fediverse for user profiles and mentions of
#              target domains.
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
import urllib.parse

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_mastodon(SpiderFootPlugin):

    meta = {
        'name': "Mastodon",
        'summary': "Search Mastodon/Fediverse for user profiles and posts mentioning target domains.",
        'flags': [],
        'useCases': ["Footprint", "Investigate", "Passive"],
        'categories': ["Social Media"],
        'dataSource': {
            'website': "https://mastodon.social/",
            'model': "FREE_NOAUTH_UNLIMITED",
            'references': [
                "https://docs.joinmastodon.org/api/",
                "https://docs.joinmastodon.org/methods/search/",
            ],
            'favIcon': "https://mastodon.social/favicon.ico",
            'logo': "https://mastodon.social/android-chrome-192x192.png",
            'description': "Mastodon is a decentralized social network built on the ActivityPub protocol. "
            "The public API allows searching for users and content without authentication.",
        }
    }

    opts = {
        'instance': 'mastodon.social',
        'max_pages': 3,
    }

    optdescs = {
        'instance': "Mastodon instance to search (default: mastodon.social).",
        'max_pages': "Maximum number of pages of search results to fetch.",
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
        return ["DOMAIN_NAME", "USERNAME"]

    def producedEvents(self):
        return ["SOCIAL_MEDIA", "RAW_RIR_DATA"]

    def search(self, query, search_type="accounts", offset=0):
        instance = self.opts['instance']
        params = {
            'q': query,
            'type': search_type,
            'limit': '20',
            'offset': str(offset),
        }

        url = f"https://{instance}/api/v2/search?" + urllib.parse.urlencode(params)
        res = self.sf.fetchUrl(
            url,
            timeout=self.opts['_fetchtimeout'],
            useragent=self.opts['_useragent']
        )
        time.sleep(1)

        if res['code'] == "429":
            self.error("Mastodon API rate limit reached.")
            self.errorState = True
            return None

        if res['content'] is None:
            return None

        try:
            return json.loads(res['content'])
        except Exception as e:
            self.error(f"Error processing Mastodon response: {e}")
            return None

    def lookupAccount(self, username):
        instance = self.opts['instance']
        params = {'acct': username}
        url = f"https://{instance}/api/v1/accounts/lookup?" + urllib.parse.urlencode(params)
        res = self.sf.fetchUrl(
            url,
            timeout=self.opts['_fetchtimeout'],
            useragent=self.opts['_useragent']
        )
        time.sleep(0.5)

        if res['code'] == "404":
            return None

        if res['content'] is None:
            return None

        try:
            return json.loads(res['content'])
        except Exception:
            return None

    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if self.errorState:
            return

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        if eventData in self.results:
            return

        self.results[eventData] = True

        instance = self.opts['instance']

        if eventName == "USERNAME":
            # Direct account lookup
            account = self.lookupAccount(eventData)
            if account:
                acct = account.get('acct', '')
                display = account.get('display_name', '')
                url = account.get('url', '')
                note = account.get('note', '')
                followers = account.get('followers_count', 0)
                statuses = account.get('statuses_count', 0)

                # Strip HTML from bio
                note_text = re.sub(r'<[^>]+>', ' ', note).strip()

                if url:
                    if url in self.results:
                        return
                    self.results[url] = True

                    evt = SpiderFootEvent(
                        "SOCIAL_MEDIA",
                        f"Mastodon ({instance}): <SFURL>{url}</SFURL>",
                        self.__name__, event
                    )
                    self.notifyListeners(evt)

                raw = f"Mastodon: {display} (@{acct}@{instance})"
                if note_text:
                    raw += f"\n{note_text[:300]}"
                raw += f"\nFollowers: {followers} | Posts: {statuses}"
                if url:
                    raw += f"\n<SFURL>{url}</SFURL>"

                evt = SpiderFootEvent("RAW_RIR_DATA", raw, self.__name__, event)
                self.notifyListeners(evt)
                return

            # Fallback: search for accounts matching the username
            data = self.search(eventData, "accounts")
            if data:
                for account in data.get('accounts', []):
                    if self.checkForStop():
                        return

                    acct = account.get('acct', '')
                    display = account.get('display_name', '')
                    url = account.get('url', '')

                    if not acct:
                        continue

                    if eventData.lower() not in acct.lower() and eventData.lower() not in display.lower():
                        continue

                    if url and url not in self.results:
                        self.results[url] = True
                        evt = SpiderFootEvent(
                            "SOCIAL_MEDIA",
                            f"Mastodon ({instance}): <SFURL>{url}</SFURL>",
                            self.__name__, event
                        )
                        self.notifyListeners(evt)

        if eventName == "DOMAIN_NAME":
            for page in range(self.opts['max_pages']):
                if self.checkForStop():
                    return

                if self.errorState:
                    return

                data = self.search(eventData, "statuses", offset=page * 20)
                if not data:
                    break

                statuses = data.get('statuses', [])
                if not statuses:
                    break

                for status in statuses:
                    account = status.get('account', {})
                    acct = account.get('acct', '')
                    content = status.get('content', '')
                    url = status.get('url', '')
                    created = status.get('created_at', '')

                    # Strip HTML tags from content
                    content_text = re.sub(r'<[^>]+>', ' ', content).strip()

                    if not content_text:
                        continue

                    if url and url in self.results:
                        continue
                    if url:
                        self.results[url] = True

                    summary = f"Mastodon post by @{acct}"
                    if created:
                        summary += f" ({created[:10]})"
                    summary += f":\n{content_text[:500]}"
                    if url:
                        summary += f"\n<SFURL>{url}</SFURL>"

                    evt = SpiderFootEvent("RAW_RIR_DATA", summary, self.__name__, event)
                    self.notifyListeners(evt)

# End of sfp_mastodon class
