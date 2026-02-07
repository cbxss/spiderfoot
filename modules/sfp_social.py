# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_social`
# Purpose:      Identify the usage of popular social networks
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     26/05/2013
# Copyright:   (c) Steve Micallef 2013
# Licence:     MIT
# -------------------------------------------------------------------------------

import re

from spiderfoot import SpiderFootEvent, SpiderFootPlugin

regexps = dict({
    "LinkedIn (Individual)": list(['.*linkedin.com/in/([a-zA-Z0-9_-]+)/?$']),
    "LinkedIn (Company)": list(['.*linkedin.com/company/([a-zA-Z0-9_-]+)/?$']),
    "Github": list([r'.*github.com/([a-zA-Z0-9_-]+)/?$']),
    "Bitbucket": list([r'.*bitbucket.org/([a-zA-Z0-9_-]+)/?$']),
    "Gitlab": list([r'.*gitlab.com/([a-zA-Z0-9_-]+)/?$']),
    "Facebook": list(['.*facebook.com/([a-zA-Z0-9_.]+)/?$']),
    "Instagram": list([r'.*instagram.com/([a-zA-Z0-9_.]+)/?$']),
    "TikTok": list([r'.*tiktok.com/@([a-zA-Z0-9_.]+)/?$']),
    "YouTube": list([
        r'.*youtube.com/@([a-zA-Z0-9_-]+)/?$',
        r'.*youtube.com/c/([a-zA-Z0-9_-]+)/?$',
        r'.*youtube.com/user/([a-zA-Z0-9_-]+)/?$',
    ]),
    "X/Twitter": list([
        r'.*twitter.com/([a-zA-Z0-9_]{1,15})/?$',
        r'.*x.com/([a-zA-Z0-9_]{1,15})/?$',
    ]),
    "Bluesky": list([r'.*bsky.app/profile/([a-zA-Z0-9_.-]+)/?$']),
    "Mastodon": list([r'.*mastodon\.\w+/@([a-zA-Z0-9_]+)/?$']),
    "Threads": list([r'.*threads.net/@([a-zA-Z0-9_.]+)/?$']),
    "Reddit": list([r'.*reddit.com/u(?:ser)?/([a-zA-Z0-9_-]+)/?$']),
    "Pinterest": list([r'.*pinterest.com/([a-zA-Z0-9_-]+)/?$']),
    "Medium": list([r'.*medium.com/@([a-zA-Z0-9_.]+)/?$']),
})


class sfp_social(SpiderFootPlugin):

    meta = {
        'name': "Social Network Identifier",
        'summary': "Identify presence on social media networks such as LinkedIn, TikTok, Bluesky and others.",
        'flags': [],
        'useCases': ["Footprint", "Passive"],
        'categories': ["Social Media"]
    }

    opts = {}

    optdescs = {
    }

    results = None

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()
        self.__dataSource__ = "Target Website"

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    def watchedEvents(self):
        return ["LINKED_URL_EXTERNAL"]

    def producedEvents(self):
        return ["SOCIAL_MEDIA", "USERNAME"]

    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        if eventData in list(self.results.keys()):
            return

        self.results[eventData] = True

        for regexpGrp in list(regexps.keys()):
            for regex in regexps[regexpGrp]:
                bits = re.match(regex, eventData, re.IGNORECASE)

                if not bits:
                    continue

                self.info(f"Matched {regexpGrp} in {eventData}")
                evt = SpiderFootEvent(
                    "SOCIAL_MEDIA", f"{regexpGrp}: <SFURL>{eventData}</SFURL>",
                    self.__name__,
                    event
                )
                self.notifyListeners(evt)

                un = bits.group(1)
                evt = SpiderFootEvent("USERNAME", str(un), self.__name__, event)
                self.notifyListeners(evt)

# End of sfp_social class
