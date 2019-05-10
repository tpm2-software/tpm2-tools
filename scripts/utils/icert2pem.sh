#!/bin/sh
# SPDX-License-Identifier: BSD-3-Clause

usage() {
cat <<EOF
Converts an Intel certificate from DER encoding to PEM encoding, writing the
result to stdout.

Usage: $0 [options] FILE

Options:
  -h    print this help text.
EOF
  exit 0
}

while getopts ":h" opt; do
  case $opt in
    h)
      usage
      ;;
    \?)
      echo "Invalid option: -$OPTARG" >&2
      exit 1
      ;;
  esac
done

if [ "$#" -ne 1 ]; then
    (>&2 echo "Error: expected 1 certificate file parameter, got: $#")
    exit 1
fi

sed 's/-/+/g;s/_/\//g;s/%3D/=/g;s/^{.*certificate":"//g;s/"}$//g;' $1 |
    base64 --decode |
    openssl x509 -inform DER -outform PEM

exit 0
