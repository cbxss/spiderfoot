#  -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sflib
# Purpose:      Common functions used by SpiderFoot modules.
#               Now a thin facade delegating to focused domain modules.
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     26/03/2012
# Copyright:   (c) Steve Micallef 2012
# Licence:     MIT
# -------------------------------------------------------------------------------

import hashlib
import inspect
import logging
import ssl
import sys
from copy import deepcopy

import dns.resolver
import urllib3

from spiderfoot.cache import SpiderFootCache
from spiderfoot.config import SpiderFootConfig
from spiderfoot.dns_utils import SpiderFootDns
from spiderfoot.domain import SpiderFootDomain
from spiderfoot.http import SpiderFootHttp
from spiderfoot.ip import SpiderFootIp
from spiderfoot.module_introspection import SpiderFootModuleIntrospection
from spiderfoot.search import SpiderFootSearch
from spiderfoot.ssl_utils import SpiderFootSSL

# For hiding the SSL warnings coming from the requests lib
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)  # noqa: DUO131


class SpiderFoot:
    """SpiderFoot

    Thin facade delegating to focused domain modules.

    Attributes:
        dbh (SpiderFootDb): database handle
        scanId (str): scan ID this instance of SpiderFoot is being used in
        socksProxy (str): SOCKS proxy
        opts (dict): configuration options
    """
    _dbh = None
    _scanId = None
    _socksProxy = None
    opts = dict()

    def __init__(self, options: dict) -> None:
        """Initialize SpiderFoot object.

        Args:
            options (dict): dictionary of configuration options.

        Raises:
            TypeError: options argument was invalid type
        """
        if not isinstance(options, dict):
            raise TypeError(f"options is {type(options)}; expected dict()")

        self.opts = deepcopy(options)
        self.log = logging.getLogger(f"spiderfoot.{__name__}")

        # This is ugly but we don't want any fetches to fail - we expect
        # to encounter unverified SSL certs!
        ssl._create_default_https_context = ssl._create_unverified_context  # noqa: DUO122

        if self.opts.get('_dnsserver', "") != "":
            res = dns.resolver.Resolver()
            res.nameservers = [self.opts['_dnsserver']]
            dns.resolver.override_system_resolver(res)

        # Initialize domain modules
        self._ip = SpiderFootIp()
        self._cache = SpiderFootCache()
        self._config = SpiderFootConfig()
        self._domain = SpiderFootDomain(self)
        self._dns = SpiderFootDns(self)
        self._http = SpiderFootHttp(self)
        self._ssl = SpiderFootSSL(self)
        self._introspection = SpiderFootModuleIntrospection(self)
        self._search = SpiderFootSearch(self)

    # -----------------------------------------------------------------------
    # Properties
    # -----------------------------------------------------------------------

    @property
    def dbh(self):
        """Database handle

        Returns:
            SpiderFootDb: database handle
        """
        return self._dbh

    @property
    def scanId(self) -> str:
        """Scan instance ID

        Returns:
            str: scan instance ID
        """
        return self._scanId

    @property
    def socksProxy(self) -> str:
        """SOCKS proxy

        Returns:
            str: socks proxy
        """
        return self._socksProxy

    @dbh.setter
    def dbh(self, dbh):
        """Called usually some time after instantiation
        to set up a database handle and scan ID, used
        for logging events to the database about a scan.

        Args:
            dbh (SpiderFootDb): database handle
        """
        self._dbh = dbh

    @scanId.setter
    def scanId(self, scanId: str) -> str:
        """Set the scan ID this instance of SpiderFoot is being used in.

        Args:
            scanId (str): scan instance ID
        """
        self._scanId = scanId

    @socksProxy.setter
    def socksProxy(self, socksProxy: str) -> str:
        """SOCKS proxy

        Bit of a hack to support SOCKS because of the loading order of
        modules. sfscan will call this to update the socket reference
        to the SOCKS one.

        Args:
            socksProxy (str): SOCKS proxy
        """
        self._socksProxy = socksProxy

    # -----------------------------------------------------------------------
    # Logging (kept directly in facade)
    # -----------------------------------------------------------------------

    def error(self, message: str, exc_info: bool = False) -> None:
        """Print and log an error message

        Args:
            message (str): error message
            exc_info (bool): include exception traceback in log
        """
        if not self.opts['__logging']:
            return

        self.log.error(message, extra={'scanId': self._scanId})

    def fatal(self, error: str) -> None:
        """Print an error message and stacktrace then exit.

        Args:
            error (str): error message
        """
        self.log.critical(error, extra={'scanId': self._scanId})

        print(str(inspect.stack()))

        sys.exit(-1)

    def status(self, message: str) -> None:
        """Log and print a status message.

        Args:
            message (str): status message
        """
        if not self.opts['__logging']:
            return

        self.log.info(message, extra={'scanId': self._scanId})

    def info(self, message: str) -> None:
        """Log and print an info message.

        Args:
            message (str): info message
        """
        if not self.opts['__logging']:
            return

        self.log.info(f"{message}", extra={'scanId': self._scanId})

    def debug(self, message: str, exc_info: bool = False) -> None:
        """Log and print a debug message.

        Args:
            message (str): debug message
            exc_info (bool): include exception traceback in log
        """
        if not self.opts['_debug']:
            return
        if not self.opts['__logging']:
            return

        self.log.debug(f"{message}", extra={'scanId': self._scanId})

    # -----------------------------------------------------------------------
    # Utility (kept directly in facade)
    # -----------------------------------------------------------------------

    def hashstring(self, string: str) -> str:
        """Returns a SHA256 hash of the specified input.

        Args:
            string (str): data to be hashed

        Returns:
            str: SHA256 hash
        """
        s = string
        if type(string) in [list, dict]:
            s = str(string)
        return hashlib.sha256(s.encode('raw_unicode_escape')).hexdigest()

    # -----------------------------------------------------------------------
    # Delegating wrappers - Cache
    # -----------------------------------------------------------------------

    def cachePut(self, label: str, data: str) -> None:
        return self._cache.cachePut(label, data)

    def cacheGet(self, label: str, timeoutHrs: int) -> str:
        return self._cache.cacheGet(label, timeoutHrs)

    # -----------------------------------------------------------------------
    # Delegating wrappers - Config
    # -----------------------------------------------------------------------

    def configSerialize(self, opts: dict, filterSystem: bool = True):
        return self._config.configSerialize(opts, filterSystem)

    def configUnserialize(self, opts: dict, referencePoint: dict, filterSystem: bool = True):
        return self._config.configUnserialize(opts, referencePoint, filterSystem)

    def optValueToData(self, val: str) -> str:
        return self._config.optValueToData(val, sf=self)

    # -----------------------------------------------------------------------
    # Delegating wrappers - IP
    # -----------------------------------------------------------------------

    def validIP(self, address: str) -> bool:
        return self._ip.validIP(address)

    def validIP6(self, address: str) -> bool:
        return self._ip.validIP6(address)

    def validIpNetwork(self, cidr: str) -> bool:
        return self._ip.validIpNetwork(cidr)

    def isPublicIpAddress(self, ip: str) -> bool:
        return self._ip.isPublicIpAddress(ip)

    def isValidLocalOrLoopbackIp(self, ip: str) -> bool:
        return self._ip.isValidLocalOrLoopbackIp(ip)

    # -----------------------------------------------------------------------
    # Delegating wrappers - Domain
    # -----------------------------------------------------------------------

    def urlFQDN(self, url: str) -> str:
        return self._domain.urlFQDN(url)

    def domainKeyword(self, domain: str, tldList: list) -> str:
        return self._domain.domainKeyword(domain, tldList)

    def domainKeywords(self, domainList: list, tldList: list) -> set:
        return self._domain.domainKeywords(domainList, tldList)

    def hostDomain(self, hostname: str, tldList: list) -> str:
        return self._domain.hostDomain(hostname, tldList)

    def validHost(self, hostname: str, tldList: str) -> bool:
        return self._domain.validHost(hostname, tldList)

    def isDomain(self, hostname: str, tldList: list) -> bool:
        return self._domain.isDomain(hostname, tldList)

    # -----------------------------------------------------------------------
    # Delegating wrappers - DNS
    # -----------------------------------------------------------------------

    def normalizeDNS(self, res: list) -> list:
        return self._dns.normalizeDNS(res)

    def resolveHost(self, host: str) -> list:
        return self._dns.resolveHost(host)

    def resolveIP(self, ipaddr: str) -> list:
        return self._dns.resolveIP(ipaddr)

    def resolveHost6(self, hostname: str) -> list:
        return self._dns.resolveHost6(hostname)

    def validateIP(self, host: str, ip: str) -> bool:
        return self._dns.validateIP(host, ip)

    def checkDnsWildcard(self, target: str) -> bool:
        return self._dns.checkDnsWildcard(target)

    # -----------------------------------------------------------------------
    # Delegating wrappers - HTTP
    # -----------------------------------------------------------------------

    def getSession(self):
        return self._http.getSession()

    def removeUrlCreds(self, url: str) -> str:
        return self._http.removeUrlCreds(url)

    def useProxyForUrl(self, url: str) -> bool:
        return self._http.useProxyForUrl(url)

    def fetchUrl(
        self,
        url: str,
        cookies: str = None,
        timeout: int = 30,
        useragent: str = "SpiderFoot",
        headers: dict = None,
        noLog: bool = False,
        postData: str = None,
        disableContentEncoding: bool = False,
        sizeLimit: int = None,
        headOnly: bool = False,
        verify: bool = True
    ) -> dict:
        return self._http.fetchUrl(
            url, cookies, timeout, useragent, headers, noLog,
            postData, disableContentEncoding, sizeLimit, headOnly, verify
        )

    # -----------------------------------------------------------------------
    # Delegating wrappers - SSL
    # -----------------------------------------------------------------------

    def safeSocket(self, host: str, port: int, timeout: int) -> 'ssl.SSLSocket':
        return self._ssl.safeSocket(host, port, timeout)

    def safeSSLSocket(self, host: str, port: int, timeout: int) -> 'ssl.SSLSocket':
        return self._ssl.safeSSLSocket(host, port, timeout)

    def parseCert(self, rawcert: str, fqdn: str = None, expiringdays: int = 30) -> dict:
        return self._ssl.parseCert(rawcert, fqdn, expiringdays)

    # -----------------------------------------------------------------------
    # Delegating wrappers - Module Introspection
    # -----------------------------------------------------------------------

    def modulesProducing(self, events: list) -> list:
        return self._introspection.modulesProducing(events)

    def modulesConsuming(self, events: list) -> list:
        return self._introspection.modulesConsuming(events)

    def eventsFromModules(self, modules: list) -> list:
        return self._introspection.eventsFromModules(modules)

    def eventsToModules(self, modules: list) -> list:
        return self._introspection.eventsToModules(modules)

    # -----------------------------------------------------------------------
    # Delegating wrappers - Search
    # -----------------------------------------------------------------------

    def cveInfo(self, cveId: str, sources: str = "circl,nist") -> (str, str):
        return self._search.cveInfo(cveId, sources)

    def googleIterate(self, searchString: str, opts: dict = None) -> dict:
        return self._search.googleIterate(searchString, opts)

    def bingIterate(self, searchString: str, opts: dict = None) -> dict:
        return self._search.bingIterate(searchString, opts)

# end of SpiderFoot class
