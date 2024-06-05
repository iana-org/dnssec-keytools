# Algorithm support

### Overview

| Algorithm | parsing | signing | key generation |
| --------- | ------- | ------- | -------------- |
| RSA       | ✅      | ✅      | ✅             |
| ECDSA     | ✅ (*)  | ✅      | ✅             |

(*) When verifying `KSR-POLICY-ALG`, ECDSA is only allowed if the configuration option `enable_unsupported_ecdsa` is enabled.


### Checklist for adding support for new algorithms

- [ ] Update `AlgorithmDNSSEC`, `SUPPORTED_ALGORITHMS` as needed.
- [ ] Add another subclass of `AlgorithmPolicy`.
- [ ] Update checks `KSR-BUNDLE-KEYS` and `KSR-POLICY-ALG` with new requirements.
- [ ] Add another subclass of `KSKM_PublicKey`.
- [ ] Update HSM interface code for signing.
- [ ] Update HSM interface code for key generation.




### Details of usage

Places where execution differs for different algorithms can mostly be found by searching for use of the `is_algorithm_*` functions.


#### Parsing

`src/kskm/common/data.py`:

The class `Key` represents a DNSSEC key. When instantiating, some validation is done for keys of certain algorithms (ECDSA keys have their key length validated).

`src/kskm/common/parse_utils.py`:

The function `_parse_signature_algorithms()` that parses `SignatureAlgorithm` XML stanzas based on their `algorithm` value is found here.

`src/kskm/ksr/verify_bundles.py`:

The checks `KSR-BUNDLE-KEYS` verify all keys mentioned in all bundles of an KSR. Checks are quite algorithm specific.

`src/kskm/ksr/verify_policy.py`:

The checks `KSR-POLICY-ALG` verify the KSK operators expressed policies, and that they are allowable. `ECDSA` policies is only permitted if the configuration option `enable_unsupported_ecdsa` is enabled.


#### Public key operations

`src/kskm/common/public_key.py`:

The abstract base class `KSKM_PublicKey` resides here. This is where all verifying of signatures is performed. Signing is always done using PKCS#11, and is handled by special classes.

`src/kskm/common/ecdsa_utils.py`:

Implementation of ECDSA functionality. Most notably the `KSKM_PublicKey_ECDSA` subclass of `KSKM_PublicKey`.

`src/kskm/common/rsa_utils.py`:

Implementation of RSA functionality. Most notably the `KSKM_PublicKey_RSA` subclass of `KSKM_PublicKey`.


#### Private key operations

`src/kskm/misc/hsm.py`:

The PKCS#11 related code is found here. Some low-level things are different for different algorithms, such as how to prepare data for signing. An attempt have been made to contain this in a function called `_format_data_for_signing()`, hopefully making it easy to add support for new algorithms.

`src/kskm/signer/key.py`:

When signing, a key is located in an PKCS#11 provider using the CKA_LABEL (key identifier). When a (EC/RSA) key is found, it is verified that it is of the same type as the excepted key.

`src/kskm/tools/keymaster.py`:

This tool can be used to generate keys using an PKCS#11 provider. Different algorithms require different PKCS#11 attributes.
