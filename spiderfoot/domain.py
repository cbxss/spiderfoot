# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         spiderfoot.domain
# Purpose:      Domain and hostname validation/parsing utilities.
# -------------------------------------------------------------------------------

import re

from publicsuffixlist import PublicSuffixList
from spiderfoot import SpiderFootHelpers


class SpiderFootDomain:
    """Domain and hostname validation/parsing utilities.

    Methods that need logging get a back-reference to the SpiderFoot facade.
    """

    def __init__(self, sf):
        self._sf = sf

    def urlFQDN(self, url: str) -> str:
        """Extract the FQDN from a URL.

        Args:
            url (str): URL

        Returns:
            str: FQDN
        """
        if not url:
            self._sf.error(f"Invalid URL: {url}")
            return None

        baseurl = SpiderFootHelpers.urlBaseUrl(url)
        if '://' in baseurl:
            count = 2
        else:
            count = 0

        # http://abc.com will split to ['http:', '', 'abc.com']
        return baseurl.split('/')[count].lower()

    def domainKeyword(self, domain: str, tldList: list) -> str:
        """Extract the keyword (the domain without the TLD or any subdomains) from a domain.

        Args:
            domain (str): The domain to check.
            tldList (list): The list of TLDs based on the Mozilla public list.

        Returns:
            str: The keyword
        """
        if not domain:
            self._sf.error(f"Invalid domain: {domain}")
            return None

        # Strip off the TLD
        dom = self.hostDomain(domain.lower(), tldList)
        if not dom:
            return None

        tld = '.'.join(dom.split('.')[1:])
        ret = domain.lower().replace('.' + tld, '')

        # If the user supplied a domain with a sub-domain, return the second part
        if '.' in ret:
            return ret.split('.')[-1]

        return ret

    def domainKeywords(self, domainList: list, tldList: list) -> set:
        """Extract the keywords (the domains without the TLD or any subdomains) from a list of domains.

        Args:
            domainList (list): The list of domains to check.
            tldList (list): The list of TLDs based on the Mozilla public list.

        Returns:
            set: List of keywords
        """
        if not domainList:
            self._sf.error(f"Invalid domain list: {domainList}")
            return set()

        keywords = [self.domainKeyword(domain, tldList) for domain in domainList]

        self._sf.debug(f"Keywords: {keywords}")
        return {k for k in keywords if k}

    def hostDomain(self, hostname: str, tldList: list) -> str:
        """Obtain the domain name for a supplied hostname.

        Args:
            hostname (str): The hostname to check.
            tldList (list): The list of TLDs based on the Mozilla public list.

        Returns:
            str: The domain name.
        """
        if not tldList:
            return None
        if not hostname:
            return None

        ps = PublicSuffixList(tldList, only_icann=True)
        return ps.privatesuffix(hostname)

    def validHost(self, hostname: str, tldList: str) -> bool:
        """Check if the provided string is a valid hostname with a valid public suffix TLD.

        Args:
            hostname (str): The hostname to check.
            tldList (str): The list of TLDs based on the Mozilla public list.

        Returns:
            bool
        """
        if not tldList:
            return False
        if not hostname:
            return False

        if "." not in hostname:
            return False

        if not re.match(r"^[a-z0-9-\.]*$", hostname, re.IGNORECASE):
            return False

        ps = PublicSuffixList(tldList, only_icann=True, accept_unknown=False)
        sfx = ps.privatesuffix(hostname)
        return sfx is not None

    def isDomain(self, hostname: str, tldList: list) -> bool:
        """Check if the provided hostname string is a valid domain name.

        Given a possible hostname, check if it's a domain name
        By checking whether it rests atop a valid TLD.
        e.g. www.example.com = False because tld of hostname is com,
        and www.example has a . in it.

        Args:
            hostname (str): The hostname to check.
            tldList (list): The list of TLDs based on the Mozilla public list.

        Returns:
            bool
        """
        if not tldList:
            return False
        if not hostname:
            return False

        ps = PublicSuffixList(tldList, only_icann=True, accept_unknown=False)
        sfx = ps.privatesuffix(hostname)
        return sfx == hostname
