#!/usr/bin/env python

from __future__ import print_function

import sys
import yaml

def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)

if (len(sys.argv) != 4):
    eprint("Expeted algorith, pcr index and yaml file from pcrlist!")
    sys.exit(1)

with open(sys.argv[3], 'r') as stream:

    try:
        y = yaml.load(stream)
        algid=sys.argv[1]
        if (algid == "sha"):
            if "sha" not in y:
                algid="sha1"
        elif (algid == "sha1"):
            if "sha1" not in y:
                algid="sha"

        alg = y[algid]

        pcrid = int(sys.argv[2], 0)

        value = alg[pcrid]
        print(value)
    except yaml.YAMLError as exc:
        eprint(exc)
        sys.exit(1)

    sys.exit(0)