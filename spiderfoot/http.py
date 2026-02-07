# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         spiderfoot.http
# Purpose:      HTTP request utilities.
# -------------------------------------------------------------------------------

import random
import re
import time
import urllib.parse

import netaddr
import requests

from spiderfoot import SpiderFootHelpers


class SpiderFootHttp:
    """HTTP request utilities.

    Needs a back-reference to SpiderFoot for opts, logging, proxy, and domain/ip methods.
    """

    def __init__(self, sf):
        self._sf = sf

    def getSession(self) -> 'requests.sessions.Session':
        """Return requests session object.

        Returns:
            requests.sessions.Session: requests session
        """
        session = requests.session()
        if self._sf.socksProxy:
            session.proxies = {
                'http': self._sf.socksProxy,
                'https': self._sf.socksProxy,
            }
        return session

    def removeUrlCreds(self, url: str) -> str:
        """Remove potentially sensitive strings (such as "key=..." and "password=...") from a string.

        Used to remove potential credentials from URLs prior during logging.

        Args:
            url (str): URL

        Returns:
            str: Sanitized URL
        """
        pats = {
            r'key=\S+': "key=XXX",
            r'pass=\S+': "pass=XXX",
            r'user=\S+': "user=XXX",
            r'password=\S+': "password=XXX"
        }

        ret = url
        for pat, repl in pats.items():
            ret = re.sub(pat, repl, ret, flags=re.IGNORECASE)

        return ret

    def useProxyForUrl(self, url: str) -> bool:
        """Check if the configured proxy should be used to connect to a specified URL.

        Args:
            url (str): The URL to check

        Returns:
            bool: should the configured proxy be used?

        Todo:
            Allow using TOR only for .onion addresses
        """
        host = self._sf.urlFQDN(url).lower()

        if not self._sf.opts['_socks1type']:
            return False

        proxy_host = self._sf.opts['_socks2addr']

        if not proxy_host:
            return False

        proxy_port = self._sf.opts['_socks3port']

        if not proxy_port:
            return False

        # Never proxy requests to the proxy host
        if host == proxy_host.lower():
            return False

        # Never proxy RFC1918 addresses on the LAN or the local network interface
        if self._sf.validIP(host):
            if netaddr.IPAddress(host).is_private():
                return False
            if netaddr.IPAddress(host).is_loopback():
                return False

        # Never proxy local hostnames
        else:
            neverProxyNames = ['local', 'localhost']
            if host in neverProxyNames:
                return False

            for s in neverProxyNames:
                if host.endswith(s):
                    return False

        return True

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
        """Fetch a URL and return the HTTP response as a dictionary.

        Args:
            url (str): URL to fetch
            cookies (str): cookies
            timeout (int): timeout
            useragent (str): user agent header
            headers (dict): headers
            noLog (bool): do not log request
            postData (str): HTTP POST data
            disableContentEncoding (bool): do not UTF-8 encode response body
            sizeLimit (int): size threshold
            headOnly (bool): use HTTP HEAD method
            verify (bool): use HTTPS SSL/TLS verification

        Returns:
            dict: HTTP response
        """
        if not url:
            return None

        result = {
            'code': None,
            'status': None,
            'content': None,
            'headers': None,
            'realurl': url
        }

        url = url.strip()

        try:
            parsed_url = urllib.parse.urlparse(url)
        except Exception:
            self._sf.debug(f"Could not parse URL: {url}")
            return None

        if parsed_url.scheme not in ('http', 'https'):
            self._sf.debug(f"Invalid URL scheme for URL: {url}")
            return None

        request_log = []

        proxies = dict()
        if self.useProxyForUrl(url):
            proxies = {
                'http': self._sf.socksProxy,
                'https': self._sf.socksProxy,
            }

        header = dict()
        btime = time.time()

        if isinstance(useragent, list):
            header['User-Agent'] = random.SystemRandom().choice(useragent)
        else:
            header['User-Agent'] = useragent

        # Add custom headers
        if isinstance(headers, dict):
            for k, v in headers.items():
                header[k] = str(v)

        request_log.append(f"proxy={self._sf.socksProxy}")
        request_log.append(f"user-agent={header['User-Agent']}")
        request_log.append(f"timeout={timeout}")
        request_log.append(f"cookies={cookies}")

        if sizeLimit or headOnly:
            if noLog:
                self._sf.debug(f"Fetching (HEAD): {self.removeUrlCreds(url)} ({', '.join(request_log)})")
            else:
                self._sf.info(f"Fetching (HEAD): {self.removeUrlCreds(url)} ({', '.join(request_log)})")

            try:
                hdr = self.getSession().head(
                    url,
                    headers=header,
                    proxies=proxies,
                    verify=verify,
                    timeout=timeout
                )
            except Exception as e:
                if noLog:
                    self._sf.debug(f"Unexpected exception ({e}) occurred fetching (HEAD only) URL: {url}", exc_info=True)
                else:
                    self._sf.error(f"Unexpected exception ({e}) occurred fetching (HEAD only) URL: {url}", exc_info=True)

                return result

            size = int(hdr.headers.get('content-length', 0))
            newloc = hdr.headers.get('location', url).strip()

            # Relative re-direct
            if newloc.startswith("/") or newloc.startswith("../"):
                newloc = SpiderFootHelpers.urlBaseUrl(url) + newloc
            result['realurl'] = newloc
            result['code'] = str(hdr.status_code)

            if headOnly:
                return result

            if size > sizeLimit:
                return result

            if result['realurl'] != url:
                if noLog:
                    self._sf.debug(f"Fetching (HEAD): {self.removeUrlCreds(result['realurl'])} ({', '.join(request_log)})")
                else:
                    self._sf.info(f"Fetching (HEAD): {self.removeUrlCreds(result['realurl'])} ({', '.join(request_log)})")

                try:
                    hdr = self.getSession().head(
                        result['realurl'],
                        headers=header,
                        proxies=proxies,
                        verify=verify,
                        timeout=timeout
                    )
                    size = int(hdr.headers.get('content-length', 0))
                    result['realurl'] = hdr.headers.get('location', result['realurl'])
                    result['code'] = str(hdr.status_code)

                    if size > sizeLimit:
                        return result

                except Exception as e:
                    if noLog:
                        self._sf.debug(f"Unexpected exception ({e}) occurred fetching (HEAD only) URL: {result['realurl']}", exc_info=True)
                    else:
                        self._sf.error(f"Unexpected exception ({e}) occurred fetching (HEAD only) URL: {result['realurl']}", exc_info=True)

                    return result

        try:
            if postData:
                if noLog:
                    self._sf.debug(f"Fetching (POST): {self.removeUrlCreds(url)} ({', '.join(request_log)})")
                else:
                    self._sf.info(f"Fetching (POST): {self.removeUrlCreds(url)} ({', '.join(request_log)})")
                res = self.getSession().post(
                    url,
                    data=postData,
                    headers=header,
                    proxies=proxies,
                    allow_redirects=True,
                    cookies=cookies,
                    timeout=timeout,
                    verify=verify
                )
            else:
                if noLog:
                    self._sf.debug(f"Fetching (GET): {self.removeUrlCreds(url)} ({', '.join(request_log)})")
                else:
                    self._sf.info(f"Fetching (GET): {self.removeUrlCreds(url)} ({', '.join(request_log)})")
                res = self.getSession().get(
                    url,
                    headers=header,
                    proxies=proxies,
                    allow_redirects=True,
                    cookies=cookies,
                    timeout=timeout,
                    verify=verify
                )
        except requests.exceptions.RequestException as e:
            self._sf.error(f"Failed to connect to {url}: {e}")
            return result
        except Exception as e:
            if noLog:
                self._sf.debug(f"Unexpected exception ({e}) occurred fetching URL: {url}", exc_info=True)
            else:
                self._sf.error(f"Unexpected exception ({e}) occurred fetching URL: {url}", exc_info=True)

            return result

        try:
            result['headers'] = dict()
            result['realurl'] = res.url
            result['code'] = str(res.status_code)

            for header, value in res.headers.items():
                result['headers'][str(header).lower()] = str(value)

            # Sometimes content exceeds the size limit after decompression
            if sizeLimit and len(res.content) > sizeLimit:
                self._sf.debug(f"Content exceeded size limit ({sizeLimit}), so returning no data just headers")
                return result

            refresh_header = result['headers'].get('refresh')
            if refresh_header:
                try:
                    newurl = refresh_header.split(";url=")[1]
                except Exception as e:
                    self._sf.debug(f"Refresh header '{refresh_header}' found, but not parsable: {e}")
                    return result

                self._sf.debug(f"Refresh header '{refresh_header}' found, re-directing to {self.removeUrlCreds(newurl)}")

                return self.fetchUrl(
                    newurl,
                    cookies,
                    timeout,
                    useragent,
                    headers,
                    noLog,
                    postData,
                    disableContentEncoding,
                    sizeLimit,
                    headOnly
                )

            if disableContentEncoding:
                result['content'] = res.content
            else:
                for encoding in ("utf-8", "ascii"):
                    try:
                        result["content"] = res.content.decode(encoding)
                    except UnicodeDecodeError:
                        pass
                    else:
                        break
                else:
                    result["content"] = res.content

        except Exception as e:
            self._sf.error(f"Unexpected exception ({e}) occurred parsing response for URL: {url}", exc_info=True)
            result['content'] = None
            result['status'] = str(e)

        atime = time.time()
        t = str(atime - btime)
        self._sf.info(f"Fetched {self.removeUrlCreds(url)} ({len(result['content'] or '')} bytes in {t}s)")
        return result
