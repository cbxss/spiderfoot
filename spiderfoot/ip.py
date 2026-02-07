# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         spiderfoot.ip
# Purpose:      IP address validation and classification utilities.
# -------------------------------------------------------------------------------

import netaddr


class SpiderFootIp:
    """IP address validation and classification utilities.

    All methods are pure functions - no back-reference needed.
    """

    @staticmethod
    def validIP(address: str) -> bool:
        """Check if the provided string is a valid IPv4 address.

        Args:
            address (str): The IPv4 address to check.

        Returns:
            bool
        """
        if not address:
            return False
        return netaddr.valid_ipv4(address)

    @staticmethod
    def validIP6(address: str) -> bool:
        """Check if the provided string is a valid IPv6 address.

        Args:
            address (str): The IPv6 address to check.

        Returns:
            bool: string is a valid IPv6 address
        """
        if not address:
            return False
        return netaddr.valid_ipv6(address)

    @staticmethod
    def validIpNetwork(cidr: str) -> bool:
        """Check if the provided string is a valid CIDR netblock.

        Args:
            cidr (str): The netblock to check.

        Returns:
            bool: string is a valid CIDR netblock
        """
        if not isinstance(cidr, str):
            return False

        if '/' not in cidr:
            return False

        try:
            return netaddr.IPNetwork(str(cidr)).size > 0
        except BaseException:
            return False

    @staticmethod
    def isPublicIpAddress(ip: str) -> bool:
        """Check if an IP address is public.

        Args:
            ip (str): IP address

        Returns:
            bool: IP address is public
        """
        if not isinstance(ip, (str, netaddr.IPAddress)):
            return False
        if not SpiderFootIp.validIP(ip) and not SpiderFootIp.validIP6(ip):
            return False

        addr = netaddr.IPAddress(ip)
        return addr.is_unicast() and not (addr.is_loopback() or addr.is_reserved() or addr.is_multicast() or addr.is_private())

    @staticmethod
    def isValidLocalOrLoopbackIp(ip: str) -> bool:
        """Check if the specified IPv4 or IPv6 address is a loopback or local network IP address (IPv4 RFC1918 / IPv6 RFC4192 ULA).

        Args:
            ip (str): IPv4 or IPv6 address

        Returns:
            bool: IP address is local or loopback
        """
        if not SpiderFootIp.validIP(ip) and not SpiderFootIp.validIP6(ip):
            return False

        addr = netaddr.IPAddress(ip)
        return addr.is_private() or addr.is_loopback()
