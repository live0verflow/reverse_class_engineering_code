#!/usr/bin/env python3

'''Define a function for runtime debugging.

This module defines the functions `debug` for writing debugging
information at runtime, and `error` for reporting errors.  It
also sets a variable `DEBUG` that you can import to access
definitions from the environment.  This variable is a simple
list of defined debugging options.  Check for an option with
`'option' in DEBUG`.

Debugging supports some simple options, controlled via the
`DEBUG` environment variable.  Set this to a comma-separated
list of debugging options.  The following are debugging options
supported by this module, but you can add any you care about.
Just be sure to document them.

debug ............. Enable debugging output.
1 ................. Synonym for debug, for backward compatibility.
context ........... Add context (file, line) information to every
                    debugging message.
nocolor ........... Do not try to use color in messages.
timestamp ......... Include a timestamp in every debugging message.
'''

import sys
from os import environ
from typing import Any


# Get the DEBUG environment variable, if it is defined.
if 'DEBUG' in environ:
    # The presence of the variable does not necessarily
    # enable debugging.  Break it into an array on commas.
    DEBUG = environ['DEBUG'].split(',')
    if '1' in DEBUG:
        DEBUG.remove('1')
        if 'debug' not in DEBUG:
            DEBUG.append('debug')
else:
    DEBUG = []


if 'context' in DEBUG:
    from inspect import currentframe, getframeinfo


# Enable or disable debugging.
_CONTEXT = 'context' in DEBUG
_COLOR = 'nocolor' not in DEBUG
if 'debug' in DEBUG:
    def debug(_msg: Any) -> None:
        '''Write a debugging message, if enabled.'''
        context = ''
        if _CONTEXT:
            frame = currentframe()
            if frame:
                frame = frame.f_back
                if frame:
                    info = getframeinfo(frame)
                    file = info.filename
                    if len(file) > 20:
                        file = '...'+file[-20:]
                    line = info.lineno
                    context = f'{file}:{line}: '
        if _COLOR:
            print(f"\x1b[32m\x1b[1mDEBUG\x1b[0m: {context}{_msg}", flush=True)
        else:
            print(f'DEBUG: {context}{_msg}', flush=True)
    debug("Debugging is enabled")
else:
    def debug(_msg: Any) -> None:
        '''Write a debugging message, if enabled.'''


if _COLOR:
    def error(msg: Any) -> None:
        '''Write an error message.'''
        sys.stderr.write(f"\x1b[31m\x1b[1mError\x1b[0m\x1b[1m: {msg}\x1b[0m\n")
        sys.stderr.flush()
else:
    def error(msg: Any) -> None:
        '''Write an error message.'''
        sys.stderr.write(f"Error: {msg}\n")
        sys.stderr.flush()
