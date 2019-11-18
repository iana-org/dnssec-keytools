# Key Signing Request Processing

The following controls was initially described in _draft-icann-dnssec-keymgmt-01.txt_ and is further clarified and elaborated here.


## Validating the Key Signing Request

The following checks are performed by the KSK operator to validate the Key Signing Request before processing. The validation may be done before accepting a KSR from the the ZSK operator (i.e. as part of the transmission process) and must be done before producing a corresponding SKR.

The input to the KSR validation process is the KSR to be validated, KSR(n), as well as the last processed SKR, SKR(n-1).



### Verify KSR header

- **KSR-DOMAIN**: Verify that the KSR domain name is correct.
- **KSR-ID**: Verify that the KSR ID is unique. This requires a list of all previously seen KSRs.
- **KSR-SERIAL**: Verify that the KSR serial is unique and increasing for the KSR ID. This requires a list of all previously seen KSRs with the current KSR ID.

### Verify KSR bundles

- **KSR-BUNDLE-UNIQUE**: Verify that all requested bundles has unique IDs
- **KSR-BUNDLE-KEYS**: Verify that the keys are consistent across all bundles and that the key tags are correctly calculated. Each _keyIdentifier_ should refer to the same key (tag, ttl, flags, protocol, algorithm, public key) for all bundles.
- **KSR-BUNDLE-POP**: For each key bundle in KSR(n), verify the signature by each ZSK to confirm proof-of-possession of private component of each ZSK. The inception and expiration times of the RRSIGs in the KSR are ignored when checking proof-of-possession.
- **KSR-BUNDLE-COUNT**: Verify that the number of requested bundles are within acceptable limits.

### Verify KSR policy parameters

If the KSR passes the checks below it follows that each key bundle is compliant with the ZSK operator's policy, and that the submitter didn't make any mistakes by straying from the stated policy.

Validate the policy parameters present in the KSR against the KSK operator's own policy. It is expected that the KSK operator's policy will have acceptance ranges for the policy parameters.

- **KSR-POLICY-KEYS**: Verify that the number of keys per bundle are acceptable according to the KSR operators policy.

- **KSR-POLICY-ALG**: Verify that only signature algorithms listed in the KSK operators policy are used in the request and that the the signature algorithms listed in the KSR policy have parameters allowed by the KSK operators policy. Parameters checked are different for different algorithms. For RSA, the following parameters applies:

    - key size
    - exponent

- **KSR-POLICY-SAFETY**: Verify _PublishSafety_ and _RetireSafety_ periods. A key must be published at least _PublishSafety_ before being used for signing and at least _RetireSafety_ before being removed after it is no longer used for signing.

- **KSR-POLICY-SIG-VALIDITY**: Verify that each requested signature (bundle inception/expiration) has a validity period between _MinSignatureValidity_ and _MaxSignatureValidity_.

- **KSR-POLICY-SIG-HORIZON**: Verify that each requested signature has a maximum validity horizon counting 180 days from now.

- **KSR-POLICY-SIG-OVERLAP**: Verify that the requested signature inceptions/expirations has an overlap period between _MinValidityOverlap_ and _MaxValidityOverlap_. This check ensures that no gaps exists in the KSR timeline.

### Verify KSR/SKR chaining

- **KSR-CHAIN-KEYS**: Check the integrity of all ZSKs in the last SKR, SKR(n-1), by verifying the KSK signature over each key bundle using the KSK stored in the HSM. Then, to build the chain of trust linking the previous KSR to the current, the pre-published ZSK from the last key bundle of SKR(n-1) must match the ZSK published in the first key bundle of KSR(n), and the post-published ZSK from the first key bundle of KSR(n) must match the ZSKs published in the last key bundle of SKR(n-1).
- **KSR-CHAIN-OVERLAP**: Check that the requested signature inceptions/expirations in the current KSR are coherent with those in the last bundle from the SKR(n-1).

## Signing the Key Signing Request

Before signing the request, the KSK operator calculates a SHA-256 hash (**HASH#1**) over the KSR XML file as received from the ZSK operator and verifies this hash out-of-band with the hash (**HASH#2**) previously calculated by the ZSK operator. If the hashes do not match, the KSR MUST NOT processed by the KSK operator and no corresponding SKR should be produced.

The KSK operator constructs a Signed Key Response (SKR) by building a ResponsePolicy consisting of a KSK policy and a ZSK policy (copied from the KSR), together with a set of ResponseBundles. Each ResponseBundle is constructed by the appropriate KSKs and ZSKs (copied from the KSR), together with a set of RRSIGs created with the Inception/Expiration
specified in the KSR.

The SKR is sent back to the ZSK operator for further processing.


## Validating the Signed Key Response

The following checks are performed by the ZSK operator to validate the Signed Key Response. The validation may be done before accepting a SKR from the KSK operator (i.e. as part of the transmission process) and must be done before the SKR is authorized and activated.

- **SKR-MATCH**: Verify that the SKR received corresponds to the most recent KSR sent by the ZSK operator; verify that the ID, serialNumber, and Domain parameters in the SKR and its corresponding KSR match, verify that number of request bundles in the SKR matches that of the corresponding KSR, and verify that for each request bundle the following parameters in the response match those in the request:

    - bundle id
    - inception date
    - expiration date

- **SKR-PAIR**: Verify that for each paired request and response bundle:

    - all the ZSKs in the request bundle are present in the response bundle,
    - the only ZSKs present in the response bundle are the ones in the request bundle,
    - KSKs are present in the SKR,
    - the signature inception in the response bundle is not later than inception of request bundle,
    - the signature expiration in the response bundle is not earlier than expiration of request bundle, and
    - each KSK signature is verified cryptographically.
