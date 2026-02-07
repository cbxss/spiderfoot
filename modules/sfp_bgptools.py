# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:        sfp_bgptools
# Purpose:     Query BGP.tools whois service for BGP routing information.
#
# Author:      SpiderFoot Revival Project
#
# Created:     2026-02-07
# Copyright:   (c) Steve Micallef
# Licence:     MIT
# -------------------------------------------------------------------------------

import socket
import time

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_bgptools(SpiderFootPlugin):

    meta = {
        'name': "BGP.tools",
        'summary': "Obtain network information from BGP.tools whois service.",
        'flags': [],
        'useCases': ["Investigate", "Footprint", "Passive"],
        'categories': ["Search Engines"],
        'dataSource': {
            'website': "https://bgp.tools/",
            'model': "FREE_NOAUTH_UNLIMITED",
            'references': [
                "https://bgp.tools/kb/api"
            ],
            'favIcon': "https://bgp.tools/favicon-32x32.png",
            'logo': "https://bgp.tools/apple-touch-icon.png",
            'description': "BGP.tools provides BGP routing information including "
            "AS numbers, prefixes, country codes, and registry data. "
            "It is the successor to BGPView which shut down in 2025.",
        }
    }

    opts = {
    }

    optdescs = {
    }

    results = None
    errorState = False

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()
        self.errorState = False

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    def watchedEvents(self):
        return [
            'IP_ADDRESS',
            'IPV6_ADDRESS',
            'BGP_AS_MEMBER',
            'NETBLOCK_MEMBER',
            'NETBLOCKV6_MEMBER',
        ]

    def producedEvents(self):
        return [
            'BGP_AS_MEMBER',
            'NETBLOCK_MEMBER',
            'NETBLOCKV6_MEMBER',
            'RAW_RIR_DATA',
        ]

    def queryWhois(self, qry):
        """Query BGP.tools whois service on TCP port 43.

        Args:
            qry: IP address, ASN (e.g. 'AS13335'), or prefix to query.

        Returns:
            list: List of parsed result dicts, or None on failure.
                  Each dict contains: asn, ip, prefix, cc, registry, allocated, name.
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.opts.get('_fetchtimeout', 15))
            sock.connect(("bgp.tools", 43))
            sock.sendall((qry + "\r\n").encode('utf-8'))

            response = b""
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk

            sock.close()
        except Exception as e:
            self.error(f"Error querying BGP.tools whois: {e}")
            return None

        time.sleep(1)

        if not response:
            return None

        text = response.decode('utf-8', errors='replace').strip()
        if not text:
            return None

        results = []
        for line in text.split('\n'):
            line = line.strip()
            if not line:
                continue
            # Skip header line and warning lines
            if line.startswith('AS') and 'IP' in line and 'BGP Prefix' in line:
                continue
            if line.startswith('Warning:'):
                continue

            parts = [p.strip() for p in line.split('|')]
            if len(parts) < 7:
                continue

            results.append({
                'asn': parts[0],
                'ip': parts[1],
                'prefix': parts[2],
                'cc': parts[3],
                'registry': parts[4],
                'allocated': parts[5],
                'name': parts[6],
            })

        return results if results else None

    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if self.errorState:
            return

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        if eventData in self.results:
            self.debug(f"Skipping {eventData}, already checked.")
            return

        self.results[eventData] = True

        if eventName == 'BGP_AS_MEMBER':
            qry = eventData if eventData.upper().startswith('AS') else f"AS{eventData}"
            data = self.queryWhois(qry)

            if not data:
                self.info(f"No results found for ASN {eventData}")
                return

            e = SpiderFootEvent('RAW_RIR_DATA', str(data), self.__name__, event)
            self.notifyListeners(e)

        if eventName in ['NETBLOCK_MEMBER', 'NETBLOCKV6_MEMBER']:
            # BGP.tools doesn't support CIDR lookup directly,
            # it uses the first IP of the prefix instead.
            prefix_ip = eventData.split('/')[0]
            data = self.queryWhois(prefix_ip)

            if not data:
                self.info(f"No results found for netblock {eventData}")
                return

            e = SpiderFootEvent('RAW_RIR_DATA', str(data), self.__name__, event)
            self.notifyListeners(e)

        if eventName in ['IP_ADDRESS', 'IPV6_ADDRESS']:
            data = self.queryWhois(eventData)

            if not data:
                self.info(f"No results found for IP address {eventData}")
                return

            e = SpiderFootEvent('RAW_RIR_DATA', str(data), self.__name__, event)
            self.notifyListeners(e)

            for entry in data:
                if self.checkForStop():
                    return

                asn = entry.get('asn')
                prefix = entry.get('prefix')

                if not asn:
                    continue

                asn_str = str(asn)
                if asn_str and asn_str not in self.results:
                    self.results[asn_str] = True
                    self.info(f"BGP AS found: {asn_str}")
                    evt = SpiderFootEvent("BGP_AS_MEMBER", asn_str, self.__name__, event)
                    self.notifyListeners(evt)

                if not prefix:
                    continue

                if self.sf.validIpNetwork(prefix) and prefix not in self.results:
                    self.results[prefix] = True
                    self.info(f"Netblock found: {prefix} (AS{asn_str})")
                    if ":" in prefix:
                        evt = SpiderFootEvent("NETBLOCKV6_MEMBER", prefix, self.__name__, event)
                    else:
                        evt = SpiderFootEvent("NETBLOCK_MEMBER", prefix, self.__name__, event)
                    self.notifyListeners(evt)

# End of sfp_bgptools class
