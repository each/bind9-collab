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
from . import dnskey
import os
import glob


########################################################################
# Class keydict
########################################################################
class keydict:
    """ A dictionary of keys, indexed by name, algorithm, and key id """

    _keydict = defaultdict(lambda: defaultdict(dict))
    _missing = []
    _defttl = 86400

    def __init__(self, path=".", **kwargs):
        if 'keyttl' in kwargs:
            self._defttl = kwargs['keyttl']

        found = []
        zones = kwargs.get('zones', None)

        files = glob.glob(os.path.join(path, '*.private'))
        for infile in files:
            key = dnskey(infile, path, self._defttl)

            if zones and key.name not in zones:
                continue

            if not key.ttl:
                key.ttl = self._defttl

            found.append(key.name)
            self._keydict[key.name][key.alg][key.keyid] = key

        if not zones:
            return
        for z in zones:
            if z not in found:
                self._missing.append(z)

    def __iter__(self):
        for zone, algorithms in self._keydict.items():
            for alg, keys in algorithms.items():
                for key in keys.values():
                    yield key

    def __getitem__(self, name):
        return self._keydict[name]

    def zones(self):
        return (self._keydict.keys())

    def algorithms(self, zone):
        return (self._keydict[zone].keys())

    def keys(self, zone, alg):
        return (self._keydict[zone][alg].keys())

    def missing(self):
        return (self._missing)
