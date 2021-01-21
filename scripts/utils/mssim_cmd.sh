#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-3-Clause
# The commands in this script line up with ibmtpm1628 TpmTcpProtocol.h, it may work on
# other versions.
set -euo pipefail

raw="no"
port="2322"
ip="127.0.0.1"

while getopts "a:p:rh" opt; do
case ${opt} in
  h)
    echo "Send a command to the simulator"
    echo "mssim_command [option] <command>"
    echo "Valid commands are: "
    echo "  on, off, reset, phys_on, phys_off, nv_on, nv_off and failure_mode"
    echo "Additionally any other string can be passed and is interpreted as is"
    echo ""
    echo "Valid Options are:"
    echo " -p: Setting port number, defaults to 2321"
    echo " -a: Setting the IP Address, defaults to 127.0.0.1"
    echo " -r: For raw mode, do not interpret the string as a 4 byte u32 via xxd -p -r first"
    echo " -h: Show this help message"
  ;;
  p )
    port=$OPTARG
  ;;
  a )
    ip=$OPTARG
  ;;
  r )
    raw="yes"
  ;;
  \? )
    echo "Invalid option: $OPTARG" 1>&2
  ;;
  : )
    echo "Invalid option: $OPTARG requires an argument" 1>&2
  ;;
esac
shift
done

if [ "$#" -ne 1 ]; then
    echo "Expected one argument, got: $#"
    exit 1
fi

arg1="$1"
if [ -z "$arg1" ]; then
    echo "Expected command as argument"
    exit 1
fi

case "$arg1" in

on)
  cmd="00000001"
  ;;

off)
  cmd="00000002"
  ;;

reset)
  cmd="00000011"
  ;;

phys_on)
  cmd="00000003"
  ;;

phys_off)
  cmd="00000004"
  ;;

cancel_on)
  cmd="00000009"
  ;;

cancel_off)
  cmd="0000000a"
  ;;

nv_on)
  cmd="0000000b"
  ;;

nv_off)
  cmd="0000000c"
  ;;

failure_mode)
  cmd="0000001e"
  ;;

*)
  cmd="$1"
  ;;
esac

if [ "$raw" == "yes" ]; then
  echo -n "$cmd" | nc -N "$ip" "$port"
else
  echo -n "$cmd" | xxd -p -r | nc -N "$ip" "$port"
fi

exit 0
