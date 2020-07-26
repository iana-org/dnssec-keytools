#!/bin/sh

kskm-trustanchor --config ksrsigner.invalid.yaml 2>/dev/null
if [ $? -ne 1 ]; then
	echo "kskm-trustanchor failed to fail on invalid config"
	exit 1
else
	echo "kskm-trustanchor failed correctly on invalid config"
fi

kskm-ksrsigner --config ksrsigner.invalid.yaml --force ksr.xml 2>/dev/null
if [ $? -ne 2 ]; then
	echo "kskm-ksrsigner failed to fail on invalid config"
	exit 1
else
	echo "kskm-ksrsigner failed correctly on invalid config"
fi

kskm-ksrsigner --force ksr.bad.xml 2>/dev/null
if [ $? -ne 3 ]; then
	echo "kskm-ksrsigner failed to fail on bad ksr"
	exit 1
else
	echo "kskm-ksrsigner failed correctly on bad ksr"
fi
