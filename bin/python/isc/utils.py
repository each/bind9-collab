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
# utils.py
# Grouping shared code in one place
############################################################################

import os

# These routines permit platform-independent location of BIND 9 tools
if os.name == 'nt':
    import win32con
    import win32api


def prefix(bindir=''):
    if os.name != 'nt':
        return os.path.join('@prefix@', bindir)

    bind_subkey = "Software\\ISC\\BIND"
    h_key = None
    key_found = True
    try:
        h_key = win32api.RegOpenKeyEx(win32con.HKEY_LOCAL_MACHINE, bind_subkey)
    except:
        key_found = False
    if key_found:
        try:
            (named_base, _) = win32api.RegQueryValueEx(h_key, "InstallDir")
        except:
            key_found = False
        win32api.RegCloseKey(h_key)
    if key_found:
        return os.path.join(named_base, bindir)
    return os.path.join(win32api.GetSystemDirectory(), bindir)


def shellquote(s):
    if os.name == 'nt':
        return '"' + s.replace('"', '"\\"') + '"'
    return "'" + s.replace("'", "'\\''") + "'"

