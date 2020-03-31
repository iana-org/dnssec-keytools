#!/bin/sh
#
# Test two different sha2wordlist implementations

for size in 128 256 1024 4096; do
	echo Testing $size
	datafile=random-${size}.tmp
	openssl rand -out $datafile $size
	sha2wordlist < $datafile > old.tmp
	kskm-sha2wordlist < $datafile > new.tmp	
	if ! cmp -s old.tmp new.tmp; then
		echo "compare failed"
		exit 1
	fi
	rm *.tmp
done
