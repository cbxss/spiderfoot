# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         spiderfoot.config
# Purpose:      Configuration serialization/deserialization utilities.
# -------------------------------------------------------------------------------


class SpiderFootConfig:
    """Configuration serialization/deserialization utilities.

    Pure functions - no back-reference needed.
    """

    @staticmethod
    def configSerialize(opts: dict, filterSystem: bool = True):
        """Convert a Python dictionary to something storable in the database.

        Args:
            opts (dict): Dictionary of SpiderFoot configuration options
            filterSystem (bool): TBD

        Returns:
            dict: config options

        Raises:
            TypeError: arg type was invalid
        """
        if not isinstance(opts, dict):
            raise TypeError(f"opts is {type(opts)}; expected dict()")

        storeopts = dict()

        if not opts:
            return storeopts

        for opt in list(opts.keys()):
            # Filter out system temporary variables like GUID and others
            if opt.startswith('__') and filterSystem:
                continue

            if isinstance(opts[opt], (int, str)):
                storeopts[opt] = opts[opt]

            if isinstance(opts[opt], bool):
                if opts[opt]:
                    storeopts[opt] = 1
                else:
                    storeopts[opt] = 0
            if isinstance(opts[opt], list):
                storeopts[opt] = ','.join(opts[opt])

        if '__modules__' not in opts:
            return storeopts

        if not isinstance(opts['__modules__'], dict):
            raise TypeError(f"opts['__modules__'] is {type(opts['__modules__'])}; expected dict()")

        for mod in opts['__modules__']:
            for opt in opts['__modules__'][mod]['opts']:
                if opt.startswith('_') and filterSystem:
                    continue

                mod_opt = f"{mod}:{opt}"
                mod_opt_val = opts['__modules__'][mod]['opts'][opt]

                if isinstance(mod_opt_val, (int, str)):
                    storeopts[mod_opt] = mod_opt_val

                if isinstance(mod_opt_val, bool):
                    if mod_opt_val:
                        storeopts[mod_opt] = 1
                    else:
                        storeopts[mod_opt] = 0
                if isinstance(mod_opt_val, list):
                    storeopts[mod_opt] = ','.join(str(x) for x in mod_opt_val)

        return storeopts

    @staticmethod
    def configUnserialize(opts: dict, referencePoint: dict, filterSystem: bool = True):
        """Take strings, etc. from the database or UI and convert them
        to a dictionary for Python to process.

        Args:
            opts (dict): SpiderFoot configuration options
            referencePoint (dict): needed to know the actual types the options are supposed to be.
            filterSystem (bool): Ignore global "system" configuration options

        Returns:
            dict: TBD

        Raises:
            TypeError: arg type was invalid
        """

        if not isinstance(opts, dict):
            raise TypeError(f"opts is {type(opts)}; expected dict()")
        if not isinstance(referencePoint, dict):
            raise TypeError(f"referencePoint is {type(referencePoint)}; expected dict()")

        returnOpts = referencePoint

        # Global options
        for opt in list(referencePoint.keys()):
            if opt.startswith('__') and filterSystem:
                # Leave out system variables
                continue

            if opt not in opts:
                continue

            if isinstance(referencePoint[opt], bool):
                if opts[opt] == "1":
                    returnOpts[opt] = True
                else:
                    returnOpts[opt] = False
                continue

            if isinstance(referencePoint[opt], str):
                returnOpts[opt] = str(opts[opt])
                continue

            if isinstance(referencePoint[opt], int):
                returnOpts[opt] = int(opts[opt])
                continue

            if isinstance(referencePoint[opt], list):
                if isinstance(referencePoint[opt][0], int):
                    returnOpts[opt] = list()
                    for x in str(opts[opt]).split(","):
                        returnOpts[opt].append(int(x))
                else:
                    returnOpts[opt] = str(opts[opt]).split(",")

        if '__modules__' not in referencePoint:
            return returnOpts

        if not isinstance(referencePoint['__modules__'], dict):
            raise TypeError(f"referencePoint['__modules__'] is {type(referencePoint['__modules__'])}; expected dict()")

        # Module options
        # A lot of mess to handle typing..
        for modName in referencePoint['__modules__']:
            for opt in referencePoint['__modules__'][modName]['opts']:
                if opt.startswith('_') and filterSystem:
                    continue

                if modName + ":" + opt in opts:
                    ref_mod = referencePoint['__modules__'][modName]['opts'][opt]
                    if isinstance(ref_mod, bool):
                        if opts[modName + ":" + opt] == "1":
                            returnOpts['__modules__'][modName]['opts'][opt] = True
                        else:
                            returnOpts['__modules__'][modName]['opts'][opt] = False
                        continue

                    if isinstance(ref_mod, str):
                        returnOpts['__modules__'][modName]['opts'][opt] = str(opts[modName + ":" + opt])
                        continue

                    if isinstance(ref_mod, int):
                        returnOpts['__modules__'][modName]['opts'][opt] = int(opts[modName + ":" + opt])
                        continue

                    if isinstance(ref_mod, list):
                        if isinstance(ref_mod[0], int):
                            returnOpts['__modules__'][modName]['opts'][opt] = list()
                            for x in str(opts[modName + ":" + opt]).split(","):
                                returnOpts['__modules__'][modName]['opts'][opt].append(int(x))
                        else:
                            returnOpts['__modules__'][modName]['opts'][opt] = str(opts[modName + ":" + opt]).split(",")

        return returnOpts

    @staticmethod
    def optValueToData(val: str, sf=None) -> str:
        """Supplied an option value, return the data based on what the
        value is. If val is a URL, you'll get back the fetched content,
        if val is a file path it will be loaded and get back the contents,
        and if a string it will simply be returned back.

        Args:
            val (str): option name
            sf: SpiderFoot facade instance (needed for logging and HTTP)

        Returns:
            str: option data
        """
        if not isinstance(val, str):
            if sf:
                sf.error(f"Invalid option value {val}")
            return None

        if val.startswith('@'):
            fname = val.split('@')[1]
            if sf:
                sf.info(f"Loading configuration data from: {fname}")

            try:
                with open(fname, "r") as f:
                    return f.read()
            except Exception as e:
                if sf:
                    sf.error(f"Unable to open option file, {fname}: {e}")
                return None

        if val.lower().startswith('http://') or val.lower().startswith('https://'):
            try:
                if sf:
                    sf.info(f"Downloading configuration data from: {val}")
                    session = sf.getSession()
                    res = session.get(val)
                    return res.content.decode('utf-8')
                return None
            except BaseException as e:
                if sf:
                    sf.error(f"Unable to open option URL, {val}: {e}")
                return None

        return val
