#!/bin/sh

MODULES=""
MODULES="$MODULES /usr/local/homebrew/lib/softhsm/libsofthsm2.so"
MODULES="$MODULES /usr/lib/softhsm/libsofthsm2.so"
MODULES="$MODULES /usr/lib64/pkcs11/libsofthsm2.so"

for m in $MODULES; do
	if [ -f $m ]; then
		echo $m
		exit 0
	fi
done
