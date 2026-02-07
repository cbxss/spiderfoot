# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         spiderfoot.cache
# Purpose:      File-based caching utilities.
# -------------------------------------------------------------------------------

import hashlib
import io
import os
import time

from spiderfoot import SpiderFootHelpers


class SpiderFootCache:
    """File-based caching utilities."""

    @staticmethod
    def cachePut(label: str, data: str) -> None:
        """Store data to the cache.

        Args:
            label (str): Name of the cached data to be used when retrieving the cached data.
            data (str): Data to cache
        """
        pathLabel = hashlib.sha224(label.encode('utf-8')).hexdigest()
        cacheFile = SpiderFootHelpers.cachePath() + "/" + pathLabel
        with io.open(cacheFile, "w", encoding="utf-8", errors="ignore") as fp:
            if isinstance(data, list):
                for line in data:
                    if isinstance(line, str):
                        fp.write(line)
                        fp.write("\n")
                    else:
                        fp.write(line.decode('utf-8') + '\n')
            elif isinstance(data, bytes):
                fp.write(data.decode('utf-8'))
            else:
                fp.write(data)

    @staticmethod
    def cacheGet(label: str, timeoutHrs: int) -> str:
        """Retreive data from the cache.

        Args:
            label (str): Name of the cached data to retrieve
            timeoutHrs (int): Age of the cached data (in hours)
                              for which the data is considered to be too old and ignored.

        Returns:
            str: cached data
        """
        if not label:
            return None

        pathLabel = hashlib.sha224(label.encode('utf-8')).hexdigest()
        cacheFile = SpiderFootHelpers.cachePath() + "/" + pathLabel
        try:
            cache_stat = os.stat(cacheFile)
        except OSError:
            return None

        if cache_stat.st_size == 0:
            return None

        if cache_stat.st_mtime > time.time() - timeoutHrs * 3600 or timeoutHrs == 0:
            with open(cacheFile, "r", encoding='utf-8') as fp:
                return fp.read()

        return None
