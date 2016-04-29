############################################################################
# Copyright (C) 2016  Internet Systems Consortium, Inc. ("ISC")
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

from __future__ import print_function
import os, sys, argparse, glob, re, time, calendar, pprint
from collections import defaultdict

prog='dnssec-keymgr'

from isc import *
from isc.utils import prefix

############################################################################
# print a fatal error and exit
############################################################################
def fatal(*args, **kwargs):
    print(*args, **kwargs)
    sys.exit(1)

############################################################################
# find the location of an external command
############################################################################
def set_path(command, default=None):
    """ find the location of a specified command. If a default is supplied,
    exists and it's an executable, we use it; otherwise we search PATH
    for an alternative.
    :param command: command to look for
    :param default: default value to use
    :return: PATH with the location of a suitable binary
    """
    fpath = default
    if not fpath or not os.path.isfile(fpath) or not os.access(fpath, os.X_OK):
        path = os.environ["PATH"]
        if not path:
            path = os.path.defpath
        for directory in path.split(os.pathsep):
            fpath = directory + os.sep + command
            if os.path.isfile(fpath) and os.access(fpath, os.X_OK):
                break
            fpath = None

    return fpath

############################################################################
# parse arguments
############################################################################
def parse_args():
    """ Read command line arguments, returns 'args' object
    :return: args object properly prepared
    """

    keygen = set_path('dnssec-keygen',
                      os.path.join(prefix('sbin'), 'dnssec-keygen'))
    settime = set_path('dnssec-settime',
                       os.path.join(prefix('sbin'), 'dnssec-settime'))

    parser = argparse.ArgumentParser(description=prog + ': schedule '
                                     'DNSSEC key rollovers according to a '
                                     'pre-defined policy')

    parser.add_argument('zone', type=str, nargs='*', default=None,
                        help='Zone(s) to which the policy should be applied ' +
                        '(default: all zones in the directory)')
    parser.add_argument('-K', dest='path', type=str,
                        help='Directory containing keys', metavar='dir')
    parser.add_argument('-c', dest='policyfile', type=str,
                        help='Policy definition file', metavar='file')
    parser.add_argument('-g', dest='keygen', default=keygen, type=str,
                        help='Path to \'dnssec-keygen\'',
                        metavar='path')
    parser.add_argument('-s', dest='settime', default=settime, type=str,
                        help='Path to \'dnssec-settime\'',
                        metavar='path')
    parser.add_argument('-k', dest='no_zsk',
                        action='store_true', default=False,
                        help='Only apply policy to key-signing keys (KSKs)')
    parser.add_argument('-z', dest='no_ksk',
                        action='store_true', default=False,
                        help='Only apply policy to zone-signing keys (ZSKs)')
    parser.add_argument('-f', '--force', dest='force', action='store_true',
                        default=False, help='Force updates to key events '+
                        'even if they are in the past')
    parser.add_argument('-q', '--quiet', dest='quiet', action='store_true',
                        default=False, help='Update keys silently')
    parser.add_argument('-v', '--version', action='version',
                        version=utils.version)

    args = parser.parse_args()

    if args.no_zsk and args.no_ksk:
        fatal("ERROR: -z and -k cannot be used together.")

    if args.keygen is None or args.settime is None:
        fatal("ERROR: dnssec-keygen/dnssec-settime not found")

    # if a policy file was specified, check that it exists.
    # if not, use the default file, unless it doesn't exist
    if args.policyfile is not None:
        if not os.path.exists(args.policyfile):
            fatal('ERROR: Policy file "%s" not found' % args.policyfile)
    else:
        args.policyfile = os.path.join(utils.sysconfdir, 'policy.conf')
        if not os.path.exists(args.policyfile):
            args.policyfile = None

    return args

############################################################################
# main
############################################################################
def main():
    args = parse_args()

    # As we may have specific locations for the binaries, we put that info
    # into a context object that can be passed around
    context = {'keygen_path': args.keygen,
               'settime_path': args.settime,
               'keys_path': args.path}

    try:
        dp = policy.dnssec_policy(args.policyfile)
    except Exception as e:
        fatal('Unable to load DNSSEC policy: ' + str(e))

    try:
        kd = keydict(dp, path=args.path, zones=args.zone)
    except Exception as e:
        fatal('Unable to build key dictionary: ' + str(e))

    try:
        ks = keyseries(kd, context=context)
    except Exception as e:
        fatal('Unable to build key series: ' + str(e))

    try:
        ks.enforce_policy(dp, ksk=args.no_zsk, zsk=args.no_ksk,
                          force=args.force, quiet=args.quiet)
    except Exception as e:
        fatal('Unable to apply policy: ' + str(e))