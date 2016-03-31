############################################################################
# Copyright (C) 2015  Internet Systems Consortium, Inc. ("ISC")
#
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES WITH
# REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
# AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE FOR ANY SPECIAL, DIRECT,
# INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
# LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
# OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
# PERFORMANCE OF THIS SOFTWARE.
############################################################################

from collections import defaultdict
from .dnskey import *
from .keyzone import *
from .keydict import *
from .keyevent import *
import time

class keyseries:
    _K = defaultdict(lambda : defaultdict(list))
    _Z = defaultdict(lambda : defaultdict(list))
    _zones = set()
    _kdict = None

    def __init__(self, kdict):
        self._kdict = kdict
        for zone in kdict.zones():
            self._zones.add(zone)
            for alg, keys in kdict[zone].items():
                for k in keys.values():
                    if k.sep:
                        self._K[zone][alg].append(k)
                    else:
                        self._Z[zone][alg].append(k)

                for group in [ self._K[zone][alg], self._Z[zone][alg] ]:
                    group.sort()
                    for k in group:
                        if k.delete() and k.delete() < now:
                            group.remove(k)

    def __iter__(self):
        for zone in self._zones:
            for collection in [ self._K, self._Z ]:
                if not zone in collection:
                    continue
                for alg, keys in collection[zone].items():
                    for key in keys:
                        yield key

    def dump(self):
        for k in self:
            print("%s" % repr(k))

    def fixseries(self, keys, policy, now):
        # handle the first key
        key = keys[0]
        rp = policy.rollperiod(key.sep)
        prepub = policy.prepublish(key.sep) or (30 * 86400)
        postpub = policy.postpublish(key.sep) or (30 * 86400)

        # the first key should be published and active
        p = key.publish()
        a = key.active()
        if not p or p > now:
            key.setpublish(now)
        if not a or a > now:
            key.setactive(now)

        if not rp:
            key.setinactive(None)
            key.setdelete(None)
        else:
            key.setinactive(a + rp)

        # handle all the subsequent keys
        prev = key
        for key in keys[1:]:
            # if no rollperiod, then all keys after the first in
            # the series kept inactive.
            # (XXX: we need to change this to allow standby keys)
            if not rp:
                key.setpublish(None)
                key.setactive(None)
                key.setinactive(None)
                key.setdelete(None)
                continue

            # otherwise, ensure all dates are set correctly based on
            # the initial key
            a = prev.inactive()
            p = a - prepub
            key.setactive(a)
            key.setpublish(p)
            key.setinactive(a + rp)
            prev.setdelete(a + postpub)
            prev = key

        # if we haven't got sufficient coverage, create
        # successor keys until we do
        while rp and prev.inactive() < now + coverage:
            key = prev.generate_successor()
            key.setinactive(key.active() + rp)
            prev.setdelete(key.active() + postpub)
            keys.append(key)
            prev = key

        # last key. we know we have sufficient coverage now, so
        # disable the inactivation of the final key, ensuring that
        # if dnssec-keymgr isn't run again, the last key in the series
        # will at least remain usable.
        prev.setinactive(None)
        prev.setdelete(None)

        # commit any changes we've made
        for key in keys:
            key.commit()

    def enforce_policy(self, zones=None, policy_file=None, **kwargs):
        dp = dnssec_policy(policy_file)
        if not zones:
            zones = self._zones

        for zone in self._zones:
            collections = []
            coverage = dp.coverage or (365 * 86400) # default 1 year
            if not 'ksk' in kwargs:
                if not self._Z[zone]:
                    dnskey.generate(zone, policy.algorithm,
                                    policy.zsk_keysize, False)
                else:
                    collections.append(self._Z[zone])

            if not 'zsk' in kwargs:
                if not self._Z[zone]:
                    dnskey.generate(zone, policy.algorithm,
                                    policy.ksk_keysize, True)
                else:
                    collections.append(self._K[zone])

            for collection in collections:
                for alg, keys in collection.items():
                    self.fixseries(keys, policy, now)
