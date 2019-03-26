#!/usr/bin/env python3

# TODO: Key exporter
# - export key as RFC 7958 trust anchor

# for each key in the ksr signer configuration file:
# - fetch public key from HSM
# - check matching algorithm and key parameters
# - create keydigest using kskm.ta.data.KeyDigest
# export kskm.ta.data.TrustAnchor to file
