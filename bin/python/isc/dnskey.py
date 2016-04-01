############################################################################
# Copyright (C) 2013-2015  Internet Systems Consortium, Inc. ("ISC")
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

import os, time, calendar

########################################################################
# Class dnskey
########################################################################
class TimePast(Exception):
    def __init__(self, key, prop, value):
        super(TimePast, self).__init__('%s time for key %s (%d) is already past'
                                       % (prop, key, value))

class dnskey:
    """An individual DNSSEC key.  Identified by path, name, algorithm, keyid.
    Contains a dictionary of metadata events."""

    _PROPS = ('Created', 'Publish', 'Activate', 'Inactive', 'Delete',
                  'Revoke', 'DSPublish', 'SyncPublish', 'SyncDelete')
    _OPTS = (None, '-P', '-A', '-I', '-D', '-R', None, '-Psync', '-Dsync')

    _ALGNAMES = (None, 'RSAMD5', 'DH', 'DSA', 'ECC', 'RSASHA1',
                 'NSEC3DSA', 'NSEC3RSASHA1', 'RSASHA256', None,
                 'RSASHA512', None, 'ECCGOST', 'ECDSAP256SHA256',
                 'ECDSAP384SHA384')

    def __init__(self, key, directory=None, keyttl=None):
        # this makes it possible to use algname as a class or instance method
        if isinstance(key, tuple) and len(key) == 3:
            self._dir = directory or '.'
            (name, alg, keyid) = key
            return self.fromtuple(name, alg, keyid, keyttl)

        self._dir = directory or os.path.dirname(key) or '.'
        key = os.path.basename(key)

        (name, alg, keyid) = key.split('+')
        name = name[1:-1]
        alg = int(alg)
        keyid = int(keyid.split('.')[0])
        return self.fromtuple(name, alg, keyid, keyttl)

    def fromtuple(self, name, alg, keyid, keyttl):
        if name[-1] == '.':
            fullname = name
            name = name[0:-1]
        else:
            fullname = name + '.'

        keystr = "K%s+%03d+%05d" % (fullname, alg, keyid)
        key_file = self._dir + (self._dir and os.sep or '') + keystr + ".key"
        private_file = (self._dir + (self._dir and os.sep or '')
                        + keystr + ".private")

        self.keystr = keystr

        self.name = name
        self.alg = int(alg)
        self.keyid = int(keyid)
        self.fullname = fullname

        kfp = open(key_file, "r")
        for line in kfp:
            if line[0] == ';':
                continue
            tokens = line.split()
            if not tokens:
                continue

            if tokens[1].lower() in ('in', 'ch', 'hs'):
                septoken = 3
                self.ttl = keyttl
            else:
                septoken = 4
                self.ttl = int(tokens[1]) if not keyttl else keyttl

            if (int(tokens[septoken]) & 0x1) == 1:
                self.sep = True
            else:
                self.sep = False
        kfp.close()

        pfp = open(private_file, "rU")

        self.metadata = dict()
        self._changed = dict()
        self._delete = dict()
        self._times = dict()
        self._fmttime = dict()
        self._timestamps = dict()

        for line in pfp:
            line = line.strip()
            if len(line) == 0 or line[0] in ('!#'):
                continue
            punctuation = [line.find(c) for c in ':= '] + [len(line)]
            found = min([ pos for pos in punctuation if pos != -1 ])
            name = line[:found].rstrip()
            value =  line[found:].lstrip(":= ").rstrip()
            self.metadata[name] = value

        for prop in dnskey._PROPS:
            self._changed[prop] = False
            if prop in self.metadata:
                t = self.parsetime(self.metadata[prop])
                self._times[prop] = t
                self._fmttime[prop] = self.formattime(t)
                self._timestamps[prop] = self.epochfromtime(t)
            else:
                self._times[prop] = None
                self._fmttime[prop] = None
                self._timestamps[prop] = None

        pfp.close()

    def commit(self):
        cmd=''
        first=True
        for prop, opt in zip(dnskey._PROPS, dnskey._OPTS):
            if not opt or not self._changed[prop]:
                continue

            delete = False
            if prop in self._delete and self._delete[prop]:
                delete = True

            when = 'none' if delete else self._fmttime[prop]
            cmd += "%s%s %s" % ('' if first else ' ', opt, when)
            first = False

        if cmd:
            # XXX: change this to run the command, or modify the private
            # file directly
            print ("dnssec-settime -K %s -L %d %s %s" %
                   (self._dir, self.ttl, cmd, self.keystr))

    @staticmethod
    def generate(directory, name, alg, keysize, sep, ttl=604800,
                 publish=None, active=None):
        pub = act = a = b = ''
        if publish:
            pub = "-P %s" % dnskey.formattime(publish)
        if active:
            act = "-A %s" % dnskey.formattime(active)

        if keysize:
            b = "-b %s" % keysize
        if alg:
            a = "-a %s" % alg

        # XXX: change this to run the command
        print ("dnssec-keygen -q -K %s -L %d %s %s %s %s %s" %
                (directory, ttl, a, b, pub, act, name))

    def generate_successor(self):
        if not self.inactive():
            raise Exception("predecessor key %s has no inactive date" % self)

        fp = os.popen("dnssec-keygen -q -K %s -S %s" % (self._dir, self.keystr))
        for line in fp:
            break
        fp.close()

        try:
            newkey = dnskey(line, self._dir, self.ttl)
            return newkey
        except:
            raise Exception('unable to generate successor for key %s' % self)


    @staticmethod
    def algstr(alg):
        name = None
        if alg in range(len(dnskey._ALGNAMES)):
            name = dnskey._ALGNAMES[alg]
        return (name if name else ("%03d" % alg))

    def algname(self, alg=None):
        return self.algstr(alg or self.alg)

    @staticmethod
    def timefromepoch(secs):
        return time.gmtime(secs)

    @staticmethod
    def parsetime(string):
        return time.strptime(string, "%Y%m%d%H%M%S")

    @staticmethod
    def epochfromtime(t):
        return calendar.timegm(t)

    @staticmethod
    def formattime(t):
        return time.strftime("%Y%m%d%H%M%S", t)

    def setmeta(self, prop, secs, now, force):
        if not secs:
            if not self._timestamps[prop]:
                return
            self._delete[prop] = True
            self._timestamps[prop] = None
            self._times[prop] = None
            self._fmttime[prop] = None
            self._changed[prop] = True
            return

        if self._timestamps[prop] and \
           self._timestamps[prop] < now and not force:
            raise TimePast(self, prop, self._timestamps[prop])
        elif self._timestamps[prop] == secs:
            return

        t = self.timefromepoch(secs)
        self._timestamps[prop] = secs
        self._times[prop] = t
        self._fmttime[prop] = self.formattime(t)
        self._changed[prop] = True

    def gettime(self, prop):
        return self._times[prop]

    def getfmttime(self, prop):
        return self._fmttime[prop]

    def gettimestamp(self, prop):
        return self._timestamps[prop]

    def created(self):
        return self._timestamps["Created"]

    def syncpublish(self):
        return self._timestamps["SyncPublish"]

    def setsyncpublish(self, secs, now=time.time(), force=False):
        self.setmeta("SyncPublish", secs, now, force)

    def publish(self):
        return self._timestamps["Publish"]

    def setpublish(self, secs, now=time.time(), force=False):
        self.setmeta("Publish", secs, now, force)

    def activate(self):
        return self._timestamps["Activate"]

    def setactivate(self, secs, now=time.time(), force=False):
        self.setmeta("Activate", secs, now, force)

    def revoke(self):
        return self._timestamps["Revoke"]

    def setrevoke(self, secs, now=time.time(), force=False):
        self.setmeta("Revoke", secs, now, force)

    def inactive(self):
        return self._timestamps["Inactive"]

    def setinactive(self, secs, now=time.time(), force=False):
        self.setmeta("Inactive", secs, now, force)

    def delete(self):
        return self._timestamps["Delete"]

    def setdelete(self, secs, now=time.time(), force=False):
        self.setmeta("Delete", secs, now, force)

    def syncdelete(self):
        return self._timestamps["SyncDelete"]

    def setsyncdelete(self, secs, now=time.time(), force=False):
        self.setmeta("SyncDelete", secs, now, force)

    def keytype(self):
        return ("KSK" if self.sep else "ZSK")

    def __str__(self):
        return ("%s/%s/%05d"
                % (self.name, self.algname(), self.keyid))

    def __repr__(self):
        return ("%s/%s/%05d (%s)"
                % (self.name, self.algname(), self.keyid,
                   ("KSK" if self.sep else "ZSK")))

    def date(self):
        return (self.activate() or self.publish() or self.created())

    # keys are sorted first by zone name, then by algorithm. within
    # the same name/algorithm, they are sorted according to their
    # 'date' value: the activation date if set, OR the publication
    # if set, OR the creation date.
    def __lt__(self, other):
        if self.name != other.name:
            return self.name < other.name
        if self.alg != other.alg:
            return self.alg < other.alg
        return self.date() < other.date()

    def check_prepub(self, output = None):
        def noop(*args, **kwargs): pass
        if not output:
            output = noop

        now = int(time.time())
        a = self.activate()
        p = self.publish()

        if not a:
            return False

        if not p:
            if a > now:
                output("WARNING: Key %s is scheduled for\n"
                       "\t activation but not for publication."
                       % repr(self))
            return False

        if p <= now and a <= now:
            return True

        if p == a:
            output("WARNING: %s is scheduled to be\n"
                   "\t published and activated at the same time. This\n"
                   "\t could result in a coverage gap if the zone was\n"
                   "\t previously signed. Activation should be at least\n"
                   "\t %s after publication."
                   % (repr(self), dnskey.duration(self.ttl)))
            return True

        if a < p:
            output("WARNING: Key %s is active before it is published"
                    % repr(self))
            return False

        if (a - p < self.ttl):
            output("WARNING: Key %s is activated too soon\n"
                   "\t after publication; this could result in coverage \n"
                   "\t gaps due to resolver caches containing old data.\n"
                   "\t Activation should be at least %s after publication."
                   % (repr(self), dnskey.duration(self.ttl)))
            return False

        return True

    def check_postpub(self, output = None, timespan = None):
        def noop(*args, **kwargs): pass
        if not output:
            output = noop

        if not timespan:
            timespan = self.ttl

        now = time.time()
        d = self.delete()
        i = self.inactive()

        if not d:
            return False

        if not i:
            if d > now:
                output("WARNING: Key %s is scheduled for\n"
                       "\t deletion but not for inactivation." % repr(self))
            return False

        if d < now and i < now:
            return True

        if d < i:
            output("WARNING: Key %s is scheduled for\n"
                   "\t deletion before inactivation."
                   % repr(self))
            return False

        if d - i < timespan:
            output("WARNING: Key %s scheduled for\n"
                   "\t deletion too soon after deactivation; this may \n"
                   "\t result in coverage gaps due to resolver caches\n"
                   "\t containing old data.  Deletion should be at least\n"
                   "\t %s after inactivation."
                  % (repr(self), dnskey.duration(timespan)))
            return False

        return True

    @staticmethod
    def getunit(secs, size):
        bigunit = secs // size
        if bigunit:
            secs %= size
        return (bigunit, secs)

    @staticmethod
    def addtime(output, unit, t):
        if t:
            output += ("%s%d %s%s" %
                      ((", " if output else ""),
                       t, unit, ("s" if t > 1 else "")))

        return output

    @staticmethod
    def duration(secs):
        # define units:
        minute = 60
        hour = minute * 60
        day = hour * 24
        month = day * 30
        year = day * 365

        # calculate time in units:
        (years, secs) = dnskey.getunit(secs, year)
        (months, secs) = dnskey.getunit(secs, month)
        (days, secs) = dnskey.getunit(secs, day)
        (hours, secs) = dnskey.getunit(secs, hour)
        (minutes, secs) = dnskey.getunit(secs, minute)

        output = ''
        output = dnskey.addtime(output, "year", years)
        output = dnskey.addtime(output, "month", months)
        output = dnskey.addtime(output, "day", days)
        output = dnskey.addtime(output, "hour", hours)
        output = dnskey.addtime(output, "minute", minutes)
        output = dnskey.addtime(output, "second", secs)
        return output

