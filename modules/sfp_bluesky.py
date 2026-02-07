# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:        sfp_bluesky
# Purpose:     Search Bluesky (AT Protocol) for posts mentioning target domains
#              and look up user profiles.
#
# Author:      SpiderFoot Revival Project
#
# Created:     2026-02-07
# Copyright:   (c) Steve Micallef
# Licence:     MIT
# -------------------------------------------------------------------------------

import json
import time
import urllib.parse

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_bluesky(SpiderFootPlugin):

    meta = {
        'name': "Bluesky",
        'summary': "Search Bluesky for posts mentioning target domains and look up user profiles.",
        'flags': [],
        'useCases': ["Footprint", "Investigate", "Passive"],
        'categories': ["Social Media"],
        'dataSource': {
            'website': "https://bsky.app/",
            'model': "FREE_NOAUTH_UNLIMITED",
            'references': [
                "https://docs.bsky.app/",
                "https://docs.bsky.app/docs/api/app-bsky-feed-search-posts",
                "https://docs.bsky.app/docs/api/app-bsky-actor-search-actors",
            ],
            'favIcon': "https://bsky.app/static/favicon-32x32.png",
            'logo': "https://bsky.app/static/apple-touch-icon.png",
            'description': "Bluesky is a decentralized social network built on the AT Protocol. "
            "The public API allows searching posts and user profiles without authentication.",
        }
    }

    opts = {
        'max_pages': 3,
    }

    optdescs = {
        'max_pages': "Maximum number of pages of search results to fetch per query.",
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

    def searchPosts(self, query, cursor=None):
        params = {'q': query, 'limit': '25'}
        if cursor:
            params['cursor'] = cursor

        url = "https://public.api.bsky.app/xrpc/app.bsky.feed.searchPosts?" + urllib.parse.urlencode(params)
        res = self.sf.fetchUrl(
            url,
            timeout=self.opts['_fetchtimeout'],
            useragent=self.opts['_useragent']
        )
        time.sleep(1)

        if res['code'] == "429":
            self.error("Bluesky API rate limit reached.")
            self.errorState = True
            return None

        if res['content'] is None:
            return None

        try:
            return json.loads(res['content'])
        except Exception as e:
            self.error(f"Error processing Bluesky response: {e}")
            return None

    def searchActors(self, query):
        params = {'q': query, 'limit': '10'}
        url = "https://public.api.bsky.app/xrpc/app.bsky.actor.searchActors?" + urllib.parse.urlencode(params)
        res = self.sf.fetchUrl(
            url,
            timeout=self.opts['_fetchtimeout'],
            useragent=self.opts['_useragent']
        )
        time.sleep(1)

        if res['content'] is None:
            return None

        try:
            return json.loads(res['content'])
        except Exception as e:
            self.error(f"Error processing Bluesky actor search response: {e}")
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

        # Search for username as a Bluesky actor
        if eventName == "USERNAME":
            data = self.searchActors(eventData)
            if not data:
                return

            for actor in data.get('actors', []):
                if self.checkForStop():
                    return

                handle = actor.get('handle', '')
                display = actor.get('displayName', '')

                if not handle:
                    continue

                # Only match if the username appears in the handle or display name
                if eventData.lower() not in handle.lower() and eventData.lower() not in display.lower():
                    continue

                profile_url = f"https://bsky.app/profile/{handle}"

                if profile_url in self.results:
                    continue
                self.results[profile_url] = True

                evt = SpiderFootEvent(
                    "SOCIAL_MEDIA",
                    f"Bluesky: <SFURL>{profile_url}</SFURL>",
                    self.__name__, event
                )
                self.notifyListeners(evt)

                desc = actor.get('description', '')
                followers = actor.get('followersCount', 0)
                following = actor.get('followsCount', 0)
                posts = actor.get('postsCount', 0)

                raw = f"Bluesky: {display} (@{handle})"
                if desc:
                    raw += f"\n{desc[:300]}"
                raw += f"\nFollowers: {followers} | Following: {following} | Posts: {posts}"
                raw += f"\n<SFURL>{profile_url}</SFURL>"

                evt = SpiderFootEvent("RAW_RIR_DATA", raw, self.__name__, event)
                self.notifyListeners(evt)

        # Search posts mentioning the domain
        if eventName == "DOMAIN_NAME":
            cursor = None
            for _page in range(self.opts['max_pages']):
                if self.checkForStop():
                    return

                if self.errorState:
                    return

                data = self.searchPosts(eventData, cursor)
                if not data:
                    break

                posts = data.get('posts', [])
                if not posts:
                    break

                for post in posts:
                    author = post.get('author', {})
                    handle = author.get('handle', '')
                    record = post.get('record', {})
                    text = record.get('text', '')
                    uri = post.get('uri', '')
                    created = record.get('createdAt', '')

                    if not text or not handle:
                        continue

                    # Convert AT URI to web URL
                    post_id = uri.split('/')[-1] if uri else ''
                    post_url = f"https://bsky.app/profile/{handle}/post/{post_id}" if post_id else ''

                    if post_url and post_url in self.results:
                        continue
                    if post_url:
                        self.results[post_url] = True

                    summary = f"Bluesky post by @{handle}"
                    if created:
                        summary += f" ({created[:10]})"
                    summary += f":\n{text[:500]}"
                    if post_url:
                        summary += f"\n<SFURL>{post_url}</SFURL>"

                    evt = SpiderFootEvent("RAW_RIR_DATA", summary, self.__name__, event)
                    self.notifyListeners(evt)

                cursor = data.get('cursor')
                if not cursor:
                    break

# End of sfp_bluesky class
