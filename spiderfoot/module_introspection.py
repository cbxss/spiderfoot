# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         spiderfoot.module_introspection
# Purpose:      Module introspection utilities for event/module relationships.
# -------------------------------------------------------------------------------


class SpiderFootModuleIntrospection:
    """Module introspection utilities for event/module relationships.

    Needs opts from the SpiderFoot facade to access __modules__.
    """

    def __init__(self, sf):
        self._sf = sf

    def modulesProducing(self, events: list) -> list:
        """Return an array of modules that produce the list of types supplied.

        Args:
            events (list): list of event types

        Returns:
            list: list of modules
        """
        modlist = list()

        if not events:
            return modlist

        loaded_modules = self._sf.opts.get('__modules__')

        if not loaded_modules:
            return modlist

        for mod in loaded_modules:
            provides = loaded_modules[mod].get('provides')

            if not provides:
                continue

            if "*" in events:
                modlist.append(mod)

            for evtype in provides:
                if evtype in events:
                    modlist.append(mod)

        return list(set(modlist))

    def modulesConsuming(self, events: list) -> list:
        """Return an array of modules that consume the list of types supplied.

        Args:
            events (list): list of event types

        Returns:
            list: list of modules
        """
        modlist = list()

        if not events:
            return modlist

        loaded_modules = self._sf.opts.get('__modules__')

        if not loaded_modules:
            return modlist

        for mod in loaded_modules:
            consumes = loaded_modules[mod].get('consumes')

            if not consumes:
                continue

            if "*" in consumes:
                modlist.append(mod)
                continue

            for evtype in consumes:
                if evtype in events:
                    modlist.append(mod)

        return list(set(modlist))

    def eventsFromModules(self, modules: list) -> list:
        """Return an array of types that are produced by the list of modules supplied.

        Args:
            modules (list): list of modules

        Returns:
            list: list of types
        """
        evtlist = list()

        if not modules:
            return evtlist

        loaded_modules = self._sf.opts.get('__modules__')

        if not loaded_modules:
            return evtlist

        for mod in modules:
            if mod in loaded_modules:
                provides = loaded_modules[mod].get('provides')
                if provides:
                    for evt in provides:
                        evtlist.append(evt)

        return evtlist

    def eventsToModules(self, modules: list) -> list:
        """Return an array of types that are consumed by the list of modules supplied.

        Args:
            modules (list): list of modules

        Returns:
            list: list of types
        """
        evtlist = list()

        if not modules:
            return evtlist

        loaded_modules = self._sf.opts.get('__modules__')

        if not loaded_modules:
            return evtlist

        for mod in modules:
            if mod in loaded_modules:
                consumes = loaded_modules[mod].get('consumes')
                if consumes:
                    for evt in consumes:
                        evtlist.append(evt)

        return evtlist
