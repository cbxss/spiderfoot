# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:        sfp_reddit
# Purpose:     Search Reddit for posts mentioning target domains and look up
#              user profiles via the Reddit API.
#
# Author:      SpiderFoot Revival Project
#
# Created:     2026-02-07
# Copyright:   (c) Steve Micallef
# Licence:     MIT
# -------------------------------------------------------------------------------

import base64
import datetime
import json
import time
import urllib.parse

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_reddit(SpiderFootPlugin):

    meta = {
        'name': "Reddit",
        'summary': "Search Reddit for posts mentioning target domains and look up user profiles.",
        'flags': ["apikey"],
        'useCases': ["Footprint", "Investigate", "Passive"],
        'categories': ["Social Media"],
        'dataSource': {
            'website': "https://www.reddit.com/",
            'model': "FREE_AUTH_LIMITED",
            'references': [
                "https://www.reddit.com/dev/api/",
                "https://support.reddithelp.com/hc/en-us/articles/16160319875092-Reddit-Data-API-Wiki",
            ],
            'favIcon': "https://www.redditstatic.com/shreddit/assets/favicon/64x64.png",
            'logo': "https://www.redditstatic.com/shreddit/assets/favicon/192x192.png",
            'description': "Reddit is a social news aggregation and discussion platform. "
            "The API allows searching posts and retrieving user profiles. "
            "Requires a free API application (create at reddit.com/prefs/apps). "
            "Rate limit: 100 requests/minute.",
            'apiKeyInstructions': [
                "Visit https://www.reddit.com/prefs/apps",
                "Click 'create another app...' at the bottom",
                "Select 'script' as the app type",
                "Fill in name and redirect URI (http://localhost)",
                "The client ID is shown under the app name",
                "The secret is labeled 'secret'",
            ],
        }
    }

    opts = {
        'api_key': '',
        'api_secret': '',
        'max_pages': 3,
    }

    optdescs = {
        'api_key': "Reddit API client ID (create a 'script' app at reddit.com/prefs/apps).",
        'api_secret': "Reddit API client secret.",
        'max_pages': "Maximum number of pages of search results to fetch.",
    }

    results = None
    errorState = False
    accessToken = None
    tokenExpiry = 0

    def setup(self, sfc, userOpts=None):
        if userOpts is None:
            userOpts = {}
        self.sf = sfc
        self.results = self.tempStorage()
        self.errorState = False
        self.accessToken = None
        self.tokenExpiry = 0

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    def watchedEvents(self):
        return ["DOMAIN_NAME", "USERNAME"]

    def producedEvents(self):
        return ["SOCIAL_MEDIA", "RAW_RIR_DATA"]

    def authenticate(self):
        api_key = self.opts['api_key']
        api_secret = self.opts['api_secret']

        if not api_key or not api_secret:
            return False

        # Check if existing token is still valid (with 60s buffer)
        if self.accessToken and time.time() < self.tokenExpiry - 60:
            return True

        auth_str = base64.b64encode(f"{api_key}:{api_secret}".encode()).decode()
        headers = {
            'Authorization': f'Basic {auth_str}',
            'Content-Type': 'application/x-www-form-urlencoded',
        }

        res = self.sf.fetchUrl(
            "https://www.reddit.com/api/v1/access_token",
            timeout=self.opts['_fetchtimeout'],
            useragent="SpiderFoot:OSINT:v4.1 (by /u/SpiderFootOSINT)",
            postData="grant_type=client_credentials",
            headers=headers,
        )

        if res['content'] is None:
            self.error("Failed to authenticate with Reddit API.")
            return False

        try:
            data = json.loads(res['content'])
            if 'access_token' not in data:
                self.error(f"Reddit auth failed: {data.get('error', 'unknown error')}")
                return False
            self.accessToken = data['access_token']
            self.tokenExpiry = time.time() + data.get('expires_in', 3600)
            return True
        except Exception as e:
            self.error(f"Error parsing Reddit auth response: {e}")
            return False

    def apiRequest(self, endpoint, params=None):
        if not self.authenticate():
            return None

        url = f"https://oauth.reddit.com{endpoint}"
        if params:
            url += "?" + urllib.parse.urlencode(params)

        res = self.sf.fetchUrl(
            url,
            timeout=self.opts['_fetchtimeout'],
            useragent="SpiderFoot:OSINT:v4.1 (by /u/SpiderFootOSINT)",
            headers={'Authorization': f'Bearer {self.accessToken}'},
        )
        time.sleep(1)

        if res['code'] == "429":
            self.error("Reddit API rate limit reached.")
            self.errorState = True
            return None

        if res['code'] == "401":
            # Token expired, reset and retry once
            self.accessToken = None
            if not self.authenticate():
                return None
            res = self.sf.fetchUrl(
                url,
                timeout=self.opts['_fetchtimeout'],
                useragent="SpiderFoot:OSINT:v4.1 (by /u/SpiderFootOSINT)",
                headers={'Authorization': f'Bearer {self.accessToken}'},
            )
            time.sleep(1)

        if res['content'] is None:
            return None

        try:
            return json.loads(res['content'])
        except Exception as e:
            self.error(f"Error processing Reddit response: {e}")
            return None

    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if self.errorState:
            return

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        if not self.opts['api_key'] or not self.opts['api_secret']:
            self.error("Reddit API requires api_key and api_secret. Create a free app at reddit.com/prefs/apps.")
            self.errorState = True
            return

        if eventData in self.results:
            return

        self.results[eventData] = True

        if eventName == "USERNAME":
            data = self.apiRequest(f"/user/{eventData}/about")
            if not data:
                return

            user_data = data.get('data', data)
            name = user_data.get('name', '')
            if not name:
                return

            profile_url = f"https://www.reddit.com/user/{name}"

            if profile_url in self.results:
                return
            self.results[profile_url] = True

            evt = SpiderFootEvent(
                "SOCIAL_MEDIA",
                f"Reddit: <SFURL>{profile_url}</SFURL>",
                self.__name__, event
            )
            self.notifyListeners(evt)

            karma = user_data.get('total_karma', 0)
            link_karma = user_data.get('link_karma', 0)
            comment_karma = user_data.get('comment_karma', 0)
            created = user_data.get('created_utc', 0)
            verified = user_data.get('verified', False)

            raw = f"Reddit: u/{name}"
            raw += f"\nKarma: {karma} (link: {link_karma}, comment: {comment_karma})"
            if created:
                created_date = datetime.datetime.fromtimestamp(created).strftime('%Y-%m-%d')
                raw += f"\nAccount created: {created_date}"
            if verified:
                raw += "\nVerified: Yes"
            raw += f"\n<SFURL>{profile_url}</SFURL>"

            evt = SpiderFootEvent("RAW_RIR_DATA", raw, self.__name__, event)
            self.notifyListeners(evt)

        if eventName == "DOMAIN_NAME":
            after = None
            for _page in range(self.opts['max_pages']):
                if self.checkForStop():
                    return

                if self.errorState:
                    return

                params = {
                    'q': f'url:{eventData} OR selftext:{eventData}',
                    'type': 'link',
                    'sort': 'relevance',
                    'limit': '25',
                }
                if after:
                    params['after'] = after

                data = self.apiRequest("/search", params)
                if not data:
                    break

                children = data.get('data', {}).get('children', [])
                if not children:
                    break

                for child in children:
                    post = child.get('data', {})
                    title = post.get('title', '')
                    author = post.get('author', '')
                    subreddit = post.get('subreddit', '')
                    permalink = post.get('permalink', '')
                    score = post.get('score', 0)
                    num_comments = post.get('num_comments', 0)
                    created_utc = post.get('created_utc', 0)
                    url = post.get('url', '')

                    if not title:
                        continue

                    post_url = f"https://www.reddit.com{permalink}" if permalink else ''

                    if post_url and post_url in self.results:
                        continue
                    if post_url:
                        self.results[post_url] = True

                    summary = f"Reddit post in r/{subreddit} by u/{author}"
                    if created_utc:
                        import datetime
                        post_date = datetime.datetime.fromtimestamp(created_utc).strftime('%Y-%m-%d')
                        summary += f" ({post_date})"
                    summary += f":\n{title}"
                    summary += f"\nScore: {score} | Comments: {num_comments}"
                    if url and url != post_url:
                        summary += f"\nLink: <SFURL>{url}</SFURL>"
                    if post_url:
                        summary += f"\n<SFURL>{post_url}</SFURL>"

                    evt = SpiderFootEvent("RAW_RIR_DATA", summary, self.__name__, event)
                    self.notifyListeners(evt)

                after = data.get('data', {}).get('after')
                if not after:
                    break

# End of sfp_reddit class
