#!/usr/bin/env python
''' A tool for analyzing the tools options for conflicts.

This tool analyzes the c files in the directory given as the first argument for
conflicting options within tpm command groups. The groups themselves are
organized by the standard document:
https://trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-3-Commands-01.38.pdf

The tool outputs the group, the tools in the group, and the conflicting options. From there
a human will need to make a plan of action to correct the tools so they conform.

The tool exits with a status of non-zero on error, making this useful for checking
PRs and can thus be added to travis.
'''

import glob
import os
import re
import sys

class Tool(object):
    '''Represents a tool name and it's options'''

    def __init__(self, name, options):
        self._name = name
        self._options = options

    @property
    def options(self):
        '''Returns the tools options'''
        return self._options

    @property
    def name(self):
        '''Returns the tools name'''
        return self._name

    def __str__(self, *args, **kwargs):
        return "%s: %s" % (self._name, str(self._options))


class ToolConflictor(object):
    '''Finds option conflicts in tools '''

    _ignore = ["tpm2_tool"]

    def __init__(self, tools):

        # Using the command summary here:
        # https://trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-3-Commands-01.38.pdf
        # We organize the tools into their grouping
        #
        # Our names in the tools might not be exactly the same, so fix them up in the map
        self._tools_by_group = [
            {
                "gname": "start-up",
                "tools-in-group": ["tpm2_startup"],
                "tools": [],
                "conflict": None,
                "ignore": set(),
            },
            {
                "gname": "session",
                "tools-in-group":
                ["tpm2_startauthsession", "tpm2_policyrestart"],
                "tools": [],
                "conflict": None,
                "ignore": set()
            },
            {
                "gname": "object",
                "tools-in-group": [
                    "tpm2_create", "tpm2_createprimary", "tpm2_changeauth",
                    "tpm2_load", "tpm2_loadexternal", "tpm2_readpublic",
                    "tpm2_activatecredential", "tpm2_makecredential",
                    "tpm2_unseal"
                ],
                "tools": [],
                "conflict": None,
                "ignore": set(['r', 'privfile', 'u', 'pubfile', 's', 'secret'])
            },
            {
                "gname": "duplication",
                "tools-in-group": ["tpm2_import"],
                "tools": [],
                "conflict": None,
                "ignore": set()
            },
            {
                "gname": "asymmetric",
                "tools-in-group": ["tpm2_rsaencrypt", "tpm2_rsadecrypt"],
                "tools": [],
                "conflict": None,
                "ignore": set()
            },
            {
                "gname": "symmetric",
                "tools-in-group":
                ["tpm2_encryptdecrypt", "tpm2_hmac", "tpm2_hash"],
                "tools": [],
                "conflict": None,
                "ignore": set(['a', 'hierarchy', 'D', 'decrypt', 't', 'ticket'])
            },
            {
                "gname": "random",
                "tools-in-group": ["tpm2_getrandom"],
                "tools": [],
                "conflict": None,
                "ignore": set()
            },
            {
                "gname": "attestation",
                "tools-in-group": ["tpm2_certify", "tpm2_quote"],
                "tools": [],
                "conflict": None,
                "ignore": set(['g', 'halg', 'm', 'message', 's', 'signature'])
            },
            {
                "gname": "signing",
                "tools-in-group": ["tpm2_verifysignature", "tpm2_sign"],
                "tools": [],
                "conflict": None,
                "ignore": set()
            },
            {
                "gname": "integrity",
                "tools-in-group":
                ["tpm2_pcrextend", "tpm2_pcrevent", "tpm2_pcrlist"],
                "tools": [],
                "conflict": None,
                "ignore": set(['g', 'halg', 'f', 'format', 's', 'algs'])
            },
            {
                "gname": "ea",
                "tools-in-group": ["tpm2_policypcr", "tpm2_createpolicy"],
                "tools": [],
                "conflict": None,
                "ignore": set(['S', 'session'])
            },
            {
                "gname": "hierarchy",
                "tools-in-group": ["tpm2_clear", "tpm2_clearlock"],
                "tools": [],
                "conflict": None,
                "ignore": set(['c', 'clear'])
            },
            {
                "gname": "context",
                "tools-in-group": ["tpm2_flushcontext", "tpm2_evictcontrol"],
                "tools": [],
                "conflict": None,
                "ignore": set()
            },
            {
                "gname": "nv",
                "tools-in-group": [
                    "tpm2_nvreadlock", "tpm2_nvrelease", "tpm2_nvdefine",
                    "tpm2_nvread", "tpm2_nvwrite", "tpm2_nvlist"
                ],
                "tools": [],
                "conflict": None,
                "ignore": set()
            },
            {
                "gname": "capability",
                "tools-in-group": ["tpm2_getcap"],
                "tools": [],
                "conflict": None,
                "ignore": set()
            },
            {
                "gname": "dictionary",
                "tools-in-group": ["tpm2_dictionarylockout"],
                "tools": [],
                "conflict": None,
                "ignore": set()
            },
            {
                "gname": "custom",
                "tools-in-group": [
                    "tpm2_send", "tpm2_createak", "tpm2_createek",
                    "tpm2_getmanufec", "tpm2_listpersistent"
                ],
                "tools": [],
                "conflict": None,
                "ignore": set()
            },
        ]

        for tool in tools:
            if tool.name in ToolConflictor._ignore:
                continue

            found = False
            for tool_group in self._tools_by_group:
                if tool.name in tool_group['tools-in-group']:
                    tool_group["tools"].append(tool)
                    found = True
                    break
            if not found:
                sys.exit("Did not find group for tool: %s", tool.name)

    def process(self):
        '''Processes the tool groups and generates the conflict data'''

        #
        # Now that we have the tools mapped onto a group, lets figure out conflicts within the
        # group, and record them in the conflict field.
        #

        for tool_group in self._tools_by_group:

            # If their is only one tool, it can't conflict
            if len(tool_group['tools']) == 1:
                continue

            option_sets = [
                set(t.options.keys()) | set(t.options.values())
                for t in tool_group['tools']
            ]
            diff = set()
            for option_set in option_sets:
                diff ^= option_set

            diff -= tool_group['ignore']

            if len(diff) > 0:
                tool_group['conflict'] = diff

    def report(self):
        '''Prints a conflict report to stdout

        It returns True if conflicts were detected or false otherwise
        '''

        has_conflicts = False

        for tool_group in self._tools_by_group:
            gname = tool_group["gname"]
            conflicts = tool_group["conflict"]
            tools = tool_group["tools"]
            if conflicts is None:
                continue

            has_conflicts = True
            print "group: %s:" % (gname)
            print "\ttools: %s" % str([t.name for t in tools])
            print "\tconflicts: %s" % (str(conflicts))

        return has_conflicts

# pylint: disable=locally-disabled, too-few-public-methods
class Parser(object):
    '''Parses C files for long option style option blocks'''

    regx = re.compile(
        r'^\s*{\s*"(\w+)"\s*,\s*(?:required_argument|no_argument)\s*,\s*\w+\s*,\s*\'(\w)\'\s*},+$',
        re.MULTILINE)

    def __init__(self, path=os.getcwd()):
        self._path = path

    @staticmethod
    def _extract_options(source_file):
        with open(source_file) as open_file:
            contents = open_file.read()

            # This returns a list of tuples, where each tuple
            # is group 1 ... N of the matched options
            # We want to build a dict() of short to long option
            # and thus need to swap the positions in the tuple,
            # as match order is long option then short option
            match_obj = Parser.regx.findall(contents)
            if match_obj is None:
                return {}

            # Reverse the tuples in the list and make a dictionary
            # of short option to long option.
            return dict([t[::-1] for t in match_obj])

    def parse(self):
        '''Parses the directory and aggregates tool option data'''
        tools = []
        path = os.path.join(self._path, "*.c")
        for c_file in glob.glob(path):
            name = (os.path.split(c_file)[-1])[:-2]
            opts = Parser._extract_options(c_file)
            tools.append(Tool(name, opts))

        return tools


def main():
    '''main entry point to program'''

    if len(sys.argv) != 2:
        sys.exit("Expected file path argument, got %d arguments" %
                 (len(sys.argv)))

    parser = Parser(sys.argv[1])
    tools = parser.parse()

    conflictor = ToolConflictor(tools)
    conflictor.process()

    has_conflicts = conflictor.report()

    # If it had conflicts, exit non-zero
    sys.exit(has_conflicts)

if __name__ == "__main__":
    main()
