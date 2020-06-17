# Claims Arguments Evidence Framework

This documentation is based on the Claims-Arguments-Evidence (CAE) framework to define assurance cases, demonstrating that the signer system prevents bypassing of the security-enforcing functionality:

- **Claim**. A claim is a true/false statement about a property of a particular object in a defined context. The context defines the scope of the claim. A claim may only hold true within the boundaries of that scope. Ambiguous or overloaded words are enclosed in brackets, which are further defined in the context, sub-claims or arguments.

- **Argument**. An argument is a rule that provides the bridge between what is known or are assumed (sub-claims, evidence) and the claim being investigated. The argument used depends on the available evidence and the nature of the claim. Note that *argument* is an overloaded word which is being used with a specific meaning in this context.

- **Evidence**. Evidence is an artefact that establishes facts that can be observed and leads directly to a claim. In this project the test cases constitutes the evidence provided.

## Security Environment Assumptions

The claims in turn depends upon a number of fundamental assumptions on the environment in which the software is being executed.


- **[A1]** The integrity of the hardware and the operating system on which the signer runs has been verified by other means before execution.
- **[A2]** The integrity of the signer software and the configured policy has been verified by other means before execution.
- **[A3]** The configured policy and default values provided in 'common/config_misc.py' have been reviewed as being suitable for its intended purpose.
- **[A4]** The HSM and the provided PKCS#11 library is trusted and the HSM holds the correct components of the current KSK.
- **[A5]** The values in data.py (AlgorithmDNSSEC, TypeDNSSEC and FlagsDNSKEY) correctly reflects the current RFCs.
- **[A6]** The libraries 'cryptography', 'pyYAML', 'PyKCS11' and 'voluptuous' are trusted for the provided functions.


# Root Claim (1)

The signer system will **[safely process]** a KSR according to the **[configured policy]**.

Context: All requirements set forth in the DPS and targeting the signer system has been identified and these controls are being enforced to **[safely process]** the KSR.


## Claim (1.1)

The signer system will only **[proceed to process]** the KSR if a valid policy containing all **[required parameters]** have been configured.

Context: All parameters required to constitute a valid policy have been identified using the requirements from the DPS (Appendix A).

### Sub Claim (1.1.2)

The signer software checks that all **[required parameters]** exists and have been set to reasonable values in the **[configured policy]**.

#### Argument (1.1.2.1)

The **[configured policy]** is provided in the '--config' argument to 'keymaster.py' and defaults to 'ksrsigner.yaml' in the current directory.

##### Evidence

This is evident in 'main' from 'tools/ksrsigner.py'.


#### Argument (1.1.2.2)

The **[configured policy]** is parsed (in 'from\_yaml' of 'common/config.py') and checked to comply with the schema ('common/config_schema.py').

##### Evidence

Test cases provides evidence that (a) an invalid policy is rejected, and (b) a valid policy is accepted.

#### Argument (1.1.2.3)

If the **[configured policy]** does not comply with the schema, execution is aborted (in 'main' of 'tools/keymaster.py'). The program will not **[proceed to process]** the KSR.

##### Evidence

Test cases provides evidence that if a policy is rejected, 'ConfigurationError' is raised and the load configuration procedure in main of 'keymaster.py' will return 'False'.

## Claim (1.2)

The signer system will only **[proceed to process]** the KSR if it conforms to the **[policy configured]**.

### Sub Claim (1.2.1)

The system only processes a KSR which is signed using a key which is **[verifiable as belonging to the RZ-Maintainer]**.

#### Argument (1.2.1.1)

KSR-CHAIN.1: To cryptographically authenticate the KSR, the signer software verifies the authenticity of all keys in the last SKR, SKR(n-1), using the KSK stored in the HSM. The keys in this SKR is **[verifiable as belonging to the RZ-Maintainer]**.

##### Evidence

Test cases provides evidence that (a) a SKR with signatures which can not be verified using the KSK is rejected, and (b) a SKR with valid signatures is accepted.

#### Argument (1.2.1.2)

KSR-CHAIN.2: To establish a chain of trust linking the previous set of keys to the current, the signer software then checks (in 'check_chain_keys' of 'signer/verify_chain.py') that all ZSKs from the last key bundle of SKR(n-1) matches the ZSKs published in the first key bundle of KSR(n).

##### Evidence

Test cases provides evidence that (a) the KSR is rejected if the KSR's first key bundle does not match the SKR's last key bundle, and (b) the KSR is accepted if they match.

#### Argument (1.2.1.3)

KSR-BUNDLE-POP: The signer software verifies (in 'check_proof_of_possession' from 'ksr/verify_bundles.py') for each key in the key bundles of KSR(n) that signatures exists which confirms proof-of-possession of the private component of each ZSK.

##### Evidence

Test cases provides evidence that (a) if a key present in a KSR is not used for signing any of the bundles the KSR is rejected, and (b) if all present keys are used to validate the signatures of the key bundles the KSR is accepted.

### Sub Claim (1.2.2)

The signer software verifies that the keys and parameters provided in the KSR are consistent across all bundles to ensure that ZSKs are only changed according to the roll-over scheme.

#### Argument (1.2.2.1)

KSR-BUNDLE-KEYS.1: The signer software (in 'check_keys_match_zsk_policy' of 'ksr/verify_bundles.py') checks each key in each bundle to ensure the key identifiers are unique per key. The control ensure that different keys can not appear with the same key tag within the bundle.

##### Evidence

Test cases provides evidence that (a) a KSR with collisions in the key tags is rejected, and (b) that a KSR with unique key tags for each identical key is accepted.

#### Argument (1.2.2.2)

KSR-BUNDLE-KEYS.2: The signer software (in 'check_keys_match_zsk_policy' of 'ksr/verify_bundles.py') checks each key in each bundle is tested to ensure the flags are acceptable according to current RFCs (configured in 'ksr/data.py').

##### Evidence

Test cases provides evidence that (a) a KSR containing keys with invalid flags is rejected and (b) a KSR containing keys with only valid flags is accepted.

#### Argument (1.2.2.3)

KSR-BUNDLE-KEYS.3: The signer software (in 'check_keys_match_zsk_policy' from 'ksr/verify_bundles.py') checks each key in each bundle to ensure the key tag is correctly calculated according to RFC 4034 (updated by RFC 6840). This control ensures that the same key can not appear with different key tags.

##### Evidence

Test cases provides evidence that (a) if a key tag is incorrectly calculated the KSR is rejected and (b) that is all key tags is calculated correctly the KSR is accepted.

### Sub Claim (1.2.3)

The signer software verifies that the number of keys per slot, which are used by the RZ-Maintainer for ZSK roll-overs, is in compliance with policy.

#### Argument (1.2.3.1)

KSR-POLICY-KEYS.4: The signer software (in 'check_keys_in_bundles' of 'ksr/verify_policy') checks that the number of bundles in the KSR matches the number of elements in the configured policy ('num_keys_per_bundle').

##### Evidence

Test cases provides evidence that (a) if the number bundles differ from the number of elements in the configured policy the KSR is rejected, and that (b) if the number of bundles matches the number of elements in the configured policy the KSR is accepted.

#### Argument (1.2.3.2)

KSR-POLICY-KEYS.5: The signer software (in 'check_keys_in_bundles' of 'ksr/verify_policy') checks that for each bundle the number of keys matches the corresponding element in the configured policy ('num_keys_per_bundle').

##### Evidence

Test cases provides evidence that (a) if the number of keys in a key bundle differ from the corresponding element of the configured policy the KSR is rejected, and that (b) if the number of keys of each key bundle matches the corresponding element of the configured policy the KSR is accepted.

### Sub Claim (1.2.4)

The signer software checks to verify that the time period covered by the KSR is in compliance with policy.

#### Argument (1.2.4.1)

KSR-BUNDLE-CYCLE-DURATION.1: In check_cycle_durations of 'verify_bundles.py' it is checked that the difference in time between the last bundles' inception time and the first bundles' inception time falls within the span defined by the configuration variables 'min_cycle_inception_length' and 'max_cycle_inception_length'.

##### Evidence

Test cases provides evidence that (a) if the duration covered by the KSR is less than the configured minimum in the policy or (b) if the duration covered by the KSR is greater than the configured maximum in the policy, the KSR is rejected.

#### Argument (1.2.4.2)

KSR-BUNDLE-CYCLE-DURATION.2: In 'check_bundle_intervals' of 'verify_policy.py' it is checked that the difference in time between two adjacent bundles' inception times falls within the span defined by the configuration variables 'min_bundle_interval' and 'max_bundle_interval'.

##### Evidence

Test cases provides evidence that (a) if the interval between two adjacent key bundles is less than the configured minimum in the policy or (b) if the interval between two adjacent key bundles is greater the configured maximum in the policy, the KSR is rejected.


### Sub Claim (1.2.5)

The signer software checks that the signature's validity periods overlaps according to policy to ensure the safe operation of the root zone.

#### Argument (1.2.5.1)

KSR-CHAIN: The signer software (in 'check_chain_overlap' of 'signer/verify_chain.py') checks to ensure the overlap between the signature expiry of the last bundle of the previous SKR and the inception of the first bundle of the current KSR to be in compliance with the configured policy ('min_validity_overlap/max_validity_overlap').

##### Evidence

Test cases provides evidence that (a) if the overlap between signature expiry of the last bundle of the previous SKR and the inception of the first bundle of the current KSR is outside of the configured boundaries the KSR is rejected, and (b) if the overlap between signature expiry of the last bundle of the previous SKR and the inception of the first bundle of the current KSR is within of the configured boundaries the KSR is accepted.

### Sub Claim (1.2.6)

The signer software verifies that the signature algorithms and parameters provided in the the KSR are acceptable according to the configured policy.

#### Argument (1.2.6.1)

KSR-POLICY-ALG.1: The signer software (in 'check_zsk_policy_algorithm' of 'ksr/verify_policy.py') checks the 'RequestPolicy' section of the KSR and denies the use of deprecated algorithms ('common/data.py') according to RFC 8624.

##### Evidence

Test cases provides evidence that if a deprecated algorithm is listed in the RequestPolicy section of the KSR the KSR is rejected.

#### Argument (1.2.6.2)

KSR-POLICY-ALG.2: The signer software (in 'check_zsk_policy_algorithm' of 'ksr/verify_policy.py') checks the 'RequestPolicy' section of the KSR and denies the use of unspported algorithms ('common/data.py').

##### Evidence

Test cases provides evidence that if an unsupported algorithm is listed in the RequestPolicy section of the KSR the KSR is rejected.

#### Argument (1.2.6.3)

KSR-POLICY-ALG.3: The signer software (in 'check_zsk_policy_algorithm' of 'ksr/verify_policy.py') checks to ensure that each occurrence of an algorithm in the 'RequestPolicy' section of the KSR is acceptable according to the configured policy ('approved_algoritms').

##### Evidence

Test cases provides evidence that (a) if an algorithm is listed in the 'RequestPolicy' section which is not listed in the configured policy ('approved_algorithms') the KSR is rejected, and (b) if an algorithm is listed in the 'RequestPolicy' section which is listed in the configured policy ('approved_algorithms') the KSR is accepted.

#### Argument (1.2.6.4)

KSR-POLICY-ALG.4: The signer software (in 'check_zsk_policy_algorithm' of 'ksr/verify_policy.py') checks, if algorithm is RSA, that the modulus length is acceptable according to the configured policy ('rsa_approved_key_sizes').

##### Evidence

Test cases provides evidence that if the algorithm listed in the RequestPolicy section is RSA and (a) if the provided modulus length is not in compliance with the configured policy ('rsa_approved_key_sizes') the KSR is rejected, and (b) if the provided modulus length is in compliance with the configured policy ('rsa_approved_key_sizes') the KSR is accepted.

#### Argument (1.2.6.5)

KSR-POLICY-ALG.5: The signer software (in 'check_zsk_policy_algorithm' of 'ksr/verify_policy.py') checks, if algorithm is RSA, that the exponent is acceptable according to the configured policy ('rsa_approved_exponents').

##### Evidence

Test cases provides evidence that if the algorithm listed in the 'RequestPolicy' section is RSA and (a) if the provided exponent is not in compliance with the configured policy ('rsa_approved_exponents') the KSR is rejected, and (b) if the provided exponent is in compliance with the configured policy ('rsa_approved_exponents') the KSR is accepted.

#### Argument (1.2.6.6)

KSR-POLICY-ALG.6: The signer software (in 'check_keys_match_zsk_policy' of 'ksr/verify_budles.py') checks to ensure that the signature algorithms and key parameters of each key in each key bundle is in compliance with the 'RequestPolicy' section of the KSR.

##### Evidence

Test cases provides evidence that (a) if the algorithm of a key within a key bundle is not RSA the KSR is rejected, and (b) if the algorithm of all keys of all bundles is RSA the KSR is accepted.

##### Evidence

Test cases provides evidence that (a) if the algorithm or parameters of a RSA key within a key bundle is not listed in the RequestPolicy section of the KSR the KSR is rejected, and (b) if the algorithm of all keys of all bundles is RSA and the algorithm and parameters is listed in the RequestPolicy section the KSR is accepted.

### Sub Claim (1.2.7)

The signer software verifies that the domain name provided in the KSR is acceptable according to the configured policy.

#### Argument (1.2.7.1)

KSR-DOMAIN: The signer software (in 'check_domain' of 'ksr/verify_header.py') checks that the domain name in the KSR header is in compliance with the configured policy ('acceptable_domains').

##### Evidence

Test cases provides evidence that (a) if the domain name provided in the KSR header is not in compliance with the configured policy ('acceptable_domains') the KSR is rejected, and (b) if the domain name provided in the KSR header is in compliance with the configured policy ('acceptable_domains') the KSR is accepted.

## Claim (1.3)

The signer system will only output a SKR with valid signatures.


### Sub Claim (1.3.1)

The signer software verifies that keys are properly pre- and post-published according to policy.

Context: These controls assumes that the duration of the time slots have taken into account the requirements for pre- and post-publishing, so that it is only required to pre- and post publish one (1) time slot and that any roll-overs of the ZSKs takes place at the edges of each cycle, in which case post-publishing always takes place at the first time slot and pre-publishing in the last time slot.

#### Argument (1.3.1.1)

KSR-POLICY-SAFETY.1: The signer system (in 'check_publish_safety' of 'signer/policy.py') checks that all keys used for signing the first bundle of the KSR was present (published) in the last bundle of the last SKR.

##### Evidence

Test cases provides evidence that if a signing key from the last bundle of the last SKR is missing in the first bundle of the current SKR, an error is raised and execution is aborted.

#### Argument (1.3.1.2)

KSR-POLICY-SAFETY.2: The signer system (in 'check_publish_safety' of 'signer/policy.py') checks that the time difference between the inception times of the signatures of the first bundle of the current SKR and the last bundle of the previous SKR is greater than the PublishSafety period.

##### Evidence

Test cases provides evidence that if the 'retire_safety' time interval is greater than the time difference between the inception of the last bundle of the last SKR and the first bundle of the current SKR, and error is raised and execution is aborted.

#### Argument (1.3.1.3)

KSR-POLICY-SAFETY.3: The signer system (in 'check_retire_safety' of 'signer/policy.py') checks that all keys used for signing the last bundle of the last SKR is present (published) in the first bundle of the current SKR.

##### Evidence

Test cases provides evidence that if a signing key in the first bundle of the current SKR is not published in the last bundle of the last SKR, an error is raised and execution is aborted.

#### Argument (1.3.1.4)

KSR-POLICY-SAFETY.4: The signer system (in 'check_retire_safety' of 'signer/policy.py') checks that the time difference in the inception times of the signatures of the first and second bundle of the current SKR is greater than or equal to the RetireSafety period.

##### Evidence

Test cases provides evidence that if the 'retire_safety' time interval is greater than the time difference between the inception of the first and second bundle of the current SKR, and error is raised and execution is aborted.

### Sub Claim (1.3.2)

The signer system verifies that the signatures of a resulting SKR can be validated using the public component of the KSK held within the HSM.

#### Argument (1.3.2.1)

SKR-VERIFY: The signer system (in '_sign_keys' of 'signer/sign.py') checks that for each signature made by the HSM, this signature can be validated using the software cryptographic library and the public key retrieved from the HSM using the PKCS#11 interface.

##### Evidence

Test cases provides evidence that (a) if a signature received from the HSM can not be validated using the software library no SKR will be produced, and (b) if all signature received from the HSM can be validated using the software library a SKR will be produced.

# Mapping of requirements from DPS


## Key's usage:

- **KSR-DOMAIN**: The signer software shall verify that the domain name provided in the KSR is correct to ensure the RZ KSK is only used for signing the root zone's DNSKEY RRset (DPS 5.1.4).

## Key's integrity:

- **KSR-BUNDLE-KEYS**: The signer software shall verify that the keys and parameters provided in the KSR are consistent across all bundles to ensure that ZSKs are only changed according to the roll-over scheme, and is not modified during the quarterly time cycle (DPS 6.6).

## Key's authenticity and secure import:

- **KSR-BUNDLE-POP**: The signer software shall, for each key bundle in KSR(n), verify the signature made by each ZSK to confirm proof-of-possession of the private component of each ZSK (DPS 6.7).

- **KSR-CHAIN**: To cryptographically authenticate the KSR, the signer software shall first verify the authenticity of all keys in the last SKR, SKR(n-1) using the KSK stored in the HSM. Then, to establish a chain of trust linking the previous set of keys to the current, the pre-published ZSK from the last key bundle of SKR(n-1) must match the ZSK published in the first key bundle of KSR(n), and the post-published ZSK from the first key bundle of KSR(n) must match the ZSKs published in the last key bundle of SKR(n-1). The signature's validity periods must also overlap. (DPS 1.3.5(3) and 6.7)


## Signing schema:

- **KSR-BUNDLE-COUNT**: The signer software shall verify that the time cycle (~90 day) is is divided into slots (9 slots of 10 days each) in compliance with policy (DPS 6.6).

- **KSR-BUNDLE-KEYS**: The signer software shall verify that only the first and the last slots are used by the RZ maintainer for ZSK roll-overs in compliance with policy and to accommodate for KSK roll-overs (DPS 6.6).


- **KSR-BUNDLE-CYCLE-DURATION**: The signer software shall verify that the time cycle covered by the KSR is in compliance with policy (DPS 6.6).

- **KSR-POLICY-SAFETY**: The signer software shall verify that keys are properly pre- and post-published to ensure the availability of the root zone to validating resolvers (DPS 6.6).

- **KSR-POLICY-ALG**: The signer software shall verify that the signature algorithms and parameters provided in the RequestPolicy section on the KSR are acceptable, agreed and used within each key bundle in the request. (RZ ZSK Op. DPS 5.1.3, 6.1, RZ Maintainer Agreement)

- **KSR-POLICY-KEYS**: The signer software shall verify that the key sets in the request have acceptable TLL according to the configured policy (48 hours) (DPS 6.9).

- **KSR-POLICY-SIG-VALIDITY**: The signer software shall verify that each requested signature has a validity period compliant with policy (<= 21 days) (DPS 5.1.4).

- **KSR-POLICY-SIG-HORIZON**: To ensure the timely interaction between the RZ KSK manager and operator, the signer software shall verify that each requested signature has a maximum validity horizon, counting from the time of signing (180 days) (DPS 5.1.4).

- **KSR-POLICY-SIG-OVERLAP**: The signer software shall verify that the requested signature inception- and expiration time has sufficient overlaps, in order to ensure the continuous operation and availability of the root zone to validating resolvers.

## Response validation:

- **SKR-VERIFY**: The signer system shall verify that each resulting response bundle matches the corresponding request bundle, and that the signatures can be validated using the currently published RZ TA (DPS 6.8).


[figure1]: ksr-signer.svg "Architectural overview of the KSR Signer software"
