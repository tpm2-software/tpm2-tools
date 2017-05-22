#!/usr/bin/env bash

tmpfile=$(mktemp /tmp/`basename "$0"`.XXXXXX)
if [ $? -ne 0 ]; then
   >&2 echo "Could not create tempfile"
   exit 1
fi

# man doesn't report warnings from groff/troff via an exit status, thus we have to inspect
# the output of stderr to determine if a warning happened and convert it to a exit status
# for Make.
#
# use # as the sed seperator instead of / since $1 has paths
man --warnings -lZ "$1" 2> >(tee $tmpfile | sed s#\<standard\ input\>#"$1"#) 1>/dev/null
if [ $? -ne 0 ]; then
   >&2 echo "Could not execute man"
   rm "$tmpfile"
   exit 1
fi

grep -q warning "$tmpfile"

exit `test $? -ne 0`
