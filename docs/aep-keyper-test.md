# Testing with the AEP Keyper HSM

This document contains documentation for how to test KSR Signer with the the AEP Keyper.

## Keyper setup

### Install AEP software.

**Install software as per ICANN instructions**

**Note**: The PKCS#11 module is installed as `/opt/Keyper/PKCS11Provider/pkcs11.linux_gcc_4_1_2_glibc_2_5_x86_64.so.5.05`,
  but the inittoken application seemed to want to find it as '...libc_2_5_...' rather than '...glibc_2_5_...'.
  Create a symbolic link to please everyone:

    root@vm-1804:~# ln -s /opt/Keyper/PKCS11Provider/pkcs11.linux_gcc_4_1_2_glibc_2_5_x86_64.so.5.05 /opt/Keyper/PKCS11Provider/pkcs11.linux_gcc_4_1_2_libc_2_5_x86_64.so.5.05
    root@vm-1804:~# ls -l /opt/Keyper/PKCS11Provider/
    total 7476
    -rwxr-x--- 1 root root 3344741 jun 10 20:23 pkcs11.linux_gcc_4_1_2_glibc_2_5_x86_64.so.5.05
    lrwxrwxrwx 1 root root      74 jun 10 20:52 pkcs11.linux_gcc_4_1_2_libc_2_5_x86_64.so.5.05 -> /opt/Keyper/PKCS11Provider/pkcs11.linux_gcc_4_1_2_glibc_2_5_x86_64.so.5.05


### Configure connectivity

Add HSM IP address to /etc/hosts and test connectivity:

    root@vm-1804:~# grep HSM /etc/hosts
    10.36.230.88 HSM
    root@vm-1804:~# ping -c 1 hsm
    PING HSM (10.36.230.88) 56(84) bytes of data.
    64 bytes from HSM (10.36.230.88): icmp_seq=1 ttl=252 time=171 ms

    --- HSM ping statistics ---
    1 packets transmitted, 1 received, 0% packet loss, time 0ms
    rtt min/avg/max/mdev = 171.377/171.377/171.377/0.000 ms


### Initialize the HSM token

    root@vm-1804:~# inittoken



    ********************************************
    InitToken for Linux v5.05 P4=72898
    ********************************************
    Built on Thu_May_28_12:12:44_BST_2015
    Copyright (c) Ultra Electronics AEP Networks Ltd 2012
    ********************************************
    WARNING: inittoken will erase any keys currently mapped
    Enter Ctrl and C to abort if this is not desired
    ********************************************

    Loading /usr/local/lib/pkcs11.so...
    Failed so trying /usr/local/lib/pkcs11.linux_gcc_4_1_2_libc_2_5_x86_64.so.5.05...
    Failed so trying /opt/Keyper/PKCS11Provider/pkcs11.so...
    Failed so trying /opt/Keyper/PKCS11Provider/pkcs11.linux_gcc_4_1_2_libc_2_5_x86_64.so.5.05...
    Shared library loaded

    PKCS11 API v:2.11
    Manufacturer ID:Ultra Electronics AEP Networks
    The slots that are available are between 0 and 0

    Enter the slot number to initialise :0

    Enter the PKCS11 Token Name :kirei-test

    Enter the PKCS11 User PIN, it must be between 4 and 32 digits : 123456
    Re-enter the PKCS11 User PIN : 123456
    Enter the PKCS11 Security Officer PIN, it must be between 4 and 32 digits : 123456
    Re-enter the PKCS11 Security Officer PIN : 123456

    PKCS11 Slot     : 0
    PKCS11 Label    : kirei-test
    Keyper Model    : Keyper 9860-2
    Keyper Serial   : H1404001
    Keyper version  : 3.4
    App             : 034
    ABL             : 011
    AL              : 00
    --------------------------------------------
    Token initialised OK
    ********************************************


### Show HSM token

    root@vm-1804:~# displaytoken


    Display Token for Linux rev 72898
    Built on Thu_May_28_12:12:44_BST_2015
    Copyright (c) Ultra Electronics AEP Networks Ltd 2012

    Loading /usr/local/lib/pkcs11.so...
    Failed so trying /usr/local/lib/pkcs11.linux_gcc_4_1_2_libc_2_5_x86_64.so.5.05...
    Failed so trying /opt/Keyper/PKCS11Provider/pkcs11.so...
    Failed so trying /opt/Keyper/PKCS11Provider/pkcs11.linux_gcc_4_1_2_libc_2_5_x86_64.so.5.05...
    Shared library loaded

    PKCS11 API v:2.11
    Manufacturer ID:Ultra Electronics AEP Networks
    Description:PKCS#11 Provider Rel64 P4=72898
    1 slots found
    The slots that are available are between 0 and 0
    Enter the slot number :0


    PKCS11 Slot     : 0
    PKCS11 Label    : kirei-test
    Keyper Model    : Keyper 9860-2
    Keyper Serial   : H1404001
    Keyper version  : 3.4
    App             : 034
    ABL             : 011
    AL              : 00


## Install KSKM Signer

Packages likely required:

    apt-get install python3.7 python3.7-venv python3.7-dev swig

Git clone icann-kskm:

    git clone git@github.com:iana-org/dnssec-keytools-2019-dev.git


### Basic configuration

Use 'make venv' to create a Python virtualenv.

    root@vm-1804:~# cd dnssec-keytools-2019-dev
    root@vm-1804:~/dnssec-keytools-2019-dev# make venv


Create a `ksrsigner.yaml` configuration file for KSKM:

    root@vm-1804:~# cat > ksrsigner.yaml << EOF
    ---
    hsm:
      aep:
        module: /opt/Keyper/PKCS11Provider/pkcs11.linux_gcc_4_1_2_libc_2_5_x86_64.so.5.05
        pin: 123456
        env:
          KEYPER_LIBRARY_PATH: /opt/dnssec
          PKCS11_LIBRARY_PATH: /opt/Keyper/PKCS11Provider/pkcs11.linux_gcc_4_1_2_glibc_2_5_x86_64.so.5.05
          LD_LIBRARY_PATH: /opt/Keyper/PKCS11Provider
    EOF


### Generate a KSK keypair

Activate the KSR signer venv using `. ~/dnssec-keytools-2019-dev/venv/bin/activate`.

<!-- TODO: run ksk-keymaster here to check connectivity? -->


Generate a KSK keypair using `kskm-keymaster`:

    (venv) root@vm-1804:~# kskm-keymaster keygen --label test1 --algorithm RSASHA256 --size 2048
    2019-06-10 21:22:57,384: kskm.common.config: INFO Loaded configuration from file ksrsigner.yaml SHA-256 b7f33386853cc35510ba238c0d1e5951b8d44cfa372843dda6e10598b77e3297 WORDS seabird vertigo chisel letterhead music crossover snowcap equipment assume puberty blowtorch megaton ancient Burlington endow enchanting select souvenir drainage whimsical clamshell cellulose crucial tambourine rematch tolerance adult narrative seabird insurgent checkup mosquito
    2019-06-10 21:22:57,411: kskm.misc.hsm: INFO Initializing PKCS#11 module aep using /opt/Keyper/PKCS11Provider/pkcs11.linux_gcc_4_1_2_libc_2_5_x86_64.so.5.05
    2019-06-10 21:22:59,100: kskm.misc.hsm: INFO HSM Label:           kirei-test
    2019-06-10 21:22:59,102: kskm.misc.hsm: INFO HSM ManufacturerID:  Ultra Electronics AEP Networks
    2019-06-10 21:22:59,104: kskm.misc.hsm: INFO HSM Model:           Keyper
    2019-06-10 21:22:59,105: kskm.misc.hsm: INFO HSM Serial:          No slot selected
    2019-06-10 21:22:59,106: keymaster: INFO Generate key
    2019-06-10 21:23:04,094: kskm.keymaster.keygen: INFO Generated key: key_label=test1 alg=RSA bits=2048 exp=65537
    2019-06-10 21:23:04,097: keymaster: INFO Generated key test1 has key tag 64315 for algorithm=AlgorithmDNSSEC.RSASHA256, flags=0x101
    2019-06-10 21:23:04,098: keymaster: INFO Generated key test1 has key tag 64443 with the REVOKE bit set (flags 0x181)

    Take note of the second to last line, saying the generated key has key tag 64315.


### Check HSM inventory

Try the key inventory mode using `kskm-keymaster`:

    (venv) root@vm-1804:~# kskm-keymaster inventory
    2019-06-10 21:23:21,506: kskm.common.config: INFO Loaded configuration from file ksrsigner.yaml SHA-256 b7f33386853cc35510ba238c0d1e5951b8d44cfa372843dda6e10598b77e3297 WORDS seabird vertigo chisel letterhead music crossover snowcap equipment assume puberty blowtorch megaton ancient Burlington endow enchanting select souvenir drainage whimsical clamshell cellulose crucial tambourine rematch tolerance adult narrative seabird insurgent checkup mosquito
    2019-06-10 21:  23:21,534: kskm.misc.hsm: INFO Initializing PKCS#11 module aep using /opt/Keyper/PKCS11Provider/pkcs11.linux_gcc_4_1_2_libc_2_5_x86_64.so.5.05
    2019-06-10 21:23:23,220: kskm.misc.hsm: INFO HSM Label:           kirei-test
    2019-06-10 21:23:23,221: kskm.misc.hsm: INFO HSM ManufacturerID:  Ultra Electronics AEP Networks
    2019-06-10 21:23:23,221: kskm.misc.hsm: INFO HSM Model:           Keyper
    2019-06-10 21:23:23,221: kskm.misc.hsm: INFO HSM Serial:          No slot selected
    2019-06-10 21:23:23,221: keymaster: INFO Show HSM inventory
    2019-06-10 21:23:24,351: keymaster: INFO Key inventory:
    HSM aep:
      Slot 0:
        Signing key pairs:
          test1   id=() alg=RSA bits=2048 exp=65537 -- Matching KSK not found in configuration


### Add generated KSK to configuration

Add the generated KSK key to the configuration (with the key tag from the generation step above):

    (venv) root@vm-1804:~# cat >> ksrsigner.yaml << EOF

    keys:
      ksk_current:
        description: AEP keyper test key 1
        label: test1
        key_tag: 64315
        algorithm: RSASHA256
        rsa_size: 2048
        rsa_exponent: 65537
        valid_from: 2010-07-15T00:00:00+00:00
        ds_sha256: XXX
    root@vm-1804:~/kirei/icann-kskm#
    EOF


The correct DS SHA256 value is not known yet. List the inventory again to get it (in the form of an error message):

    (venv) root@vm-1804:~# /usr/local/bin/kskm-keymaster inventory
    2019-06-10 21:26:21,246: kskm.common.config: INFO Loaded configuration from file ksrsigner.yaml SHA-256 6e07845a291d2a65d3ca037b13dd3309b0157917d38bc039de3f825d9316e3aa WORDS goldfish amusement mural existence breakup breakaway brickyard glossary stapler revenue acme inferno Aztec tambourine chisel applicant ruffled bifocals jawbone bookseller stapler Medusa slowdown corporate tactics customer miser filament playhouse bodyguard tissue pedigree
    2019-06-10 21:26:21,263: kskm.misc.hsm: INFO Initializing PKCS#11 module aep using /opt/Keyper/PKCS11Provider/pkcs11.linux_gcc_4_1_2_libc_2_5_x86_64.so.5.05
    2019-06-10 21:26:22,899: kskm.misc.hsm: INFO HSM Label:           kirei-test
    2019-06-10 21:26:22,901: kskm.misc.hsm: INFO HSM ManufacturerID:  Ultra Electronics AEP Networks
    2019-06-10 21:26:22,903: kskm.misc.hsm: INFO HSM Model:           Keyper
    2019-06-10 21:26:22,903: kskm.misc.hsm: INFO HSM Serial:          No slot selected
    2019-06-10 21:26:22,904: keymaster: INFO Show HSM inventory
    2019-06-10 21:26:24,048: kskm.common.config_ksk: ERROR Configured KSK key test1 DS SHA256 XXX does not match computed DS SHA256 B50A9024EFD906135AAF3CFC83422FE8CF61716386616836AEA7CF2A13ADE6BE for DNSSEC key: Key(key_identifier='test1', key_tag=64315, ttl=0, flags=257, protocol=3, algorithm=<AlgorithmDNSSEC.RSASHA256: 8>)
    2019-06-10 21:26:24,049: keymaster: INFO Key inventory:
    HSM aep:
      Slot 0:
        Signing key pairs:
          test1   id=() alg=RSA bits=2048 exp=65537 -- BAD KSK 'test1/AEP keyper test key 1': Key test1 has unexpected DS (B50A9024EFD906135AAF3CFC83422FE8CF61716386616836AEA7CF2A13ADE6BE, not XXX)


Update ksrsigner.yaml with the correct DS:

    (venv) root@vm-1804:~# sed -ie s/XXX/B50A9024EFD906135AAF3CFC83422FE8CF61716386616836AEA7CF2A13ADE6BE/g


Show the inventory again:

    (venv) root@vm-1804:~# kskm-keymaster inventory
    2019-06-10 21:27:08,656: kskm.common.config: INFO Loaded configuration from file ksrsigner.yaml SHA-256 4f8de3ed1a46d29663396250f0b34cebf3856b6dcc37c645ca949bcc221dc2e1 WORDS dropper microscope tissue unify beehive detergent standard monument flatfoot corporate flagpole embezzle unearth pocketful drainage underfoot upset leprosy glitter hazardous spigot consensus southward detector spellbind molecule puppy revolver blockade breakaway snapshot tolerance
    2019-06-10 21:27:08,684: kskm.misc.hsm: INFO Initializing PKCS#11 module aep using /opt/Keyper/PKCS11Provider/pkcs11.linux_gcc_4_1_2_libc_2_5_x86_64.so.5.05
    2019-06-10 21:27:10,307: kskm.misc.hsm: INFO HSM Label:           kirei-test
    2019-06-10 21:27:10,308: kskm.misc.hsm: INFO HSM ManufacturerID:  Ultra Electronics AEP Networks
    2019-06-10 21:27:10,308: kskm.misc.hsm: INFO HSM Model:           Keyper
    2019-06-10 21:27:10,308: kskm.misc.hsm: INFO HSM Serial:          No slot selected
    2019-06-10 21:27:10,308: keymaster: INFO Show HSM inventory
    2019-06-10 21:27:11,398: keymaster: INFO Key inventory:
    HSM aep:
      Slot 0:
        Signing key pairs:
          test1   id=() alg=RSA bits=2048 exp=65537 -- KSK 'test1/AEP keyper test key 1', key tag 64315, algorithm=RSASHA256


## KSR signing

First, add a simple 'schemas' section to the ksrsigner.yaml in use:

    schemas:

      # normal key bundle
      normal:
        1:
          publish: ksk_current
          sign: ksk_current
        2:
          publish: ksk_current
          sign: ksk_current
        3:
          publish: ksk_current
          sign: ksk_current
        4:
          publish: ksk_current
          sign: ksk_current
        5:
          publish: ksk_current
          sign: ksk_current
        6:
          publish: ksk_current
          sign: ksk_current
        7:
          publish: ksk_current
          sign: ksk_current
        8:
          publish: ksk_current
          sign: ksk_current
        9:
          publish: ksk_current
          sign: ksk_current



Secondly, the bundled example KSR ksr-root-2018-q1-0-d_to_e.xml used in tests has bundle overlaps not conforming
to the stated policy, and will be rejected unless the bundle overlap check is disabled. Add this request_policy
to the configuration:

    request_policy:
      check_bundle_overlap: False


### Actually sign a KSR:

    (venv) root@vm-1604:~# kskm-ksrsigner --config ksrsigner.yaml ~/dnssec-keytools-2019-dev/src/kskm/ksr/tests/data/ksr-root-2018-q1-0-d_to_e.xml
    2019-06-17 14:21:41,725: kskm.common.config: INFO Loaded configuration from file ksrsigner.yaml SHA-256 405c0be19a7a42910c893fee88029beed150091d50a40499682b44be52284b9c WORDS crackdown fascinate alone tolerance pupil infancy crowfoot miracle ammo matchmaker cowbell universe newborn aftermath puppy universe stairway embezzle Algol breakaway drumbeat Pandora adrift nebula frighten Cherokee crumpled racketeer Dupont cellulose dragnet October
    2019-06-17 14:21:41,730: kskm.ksr.load: INFO Loaded KSR from file ../src/kskm/ksr/tests/data/ksr-root-2018-q1-0-d_to_e.xml SHA-256 d9f3e4e9ed8ed27d7d3d8cfc2d05f4f0470dbd22ac238d0c9ac728d1e2908a9b WORDS sugar vertigo tonic ultimate tunnel microwave standard insincere klaxon crucifix offload Wilmington button almighty upshot upcoming dashboard asteroid skullcap candidate ribcage cannonball optic article pupil retraction breadline scavenger tiger millionaire Oakland Norwegian
    2019-06-17 14:21:41,731: kskm.ksr.load.ksr: INFO ../src/kskm/ksr/tests/data/ksr-root-2018-q1-0-d_to_e.xml 000: <KSR domain="." id="4fe9bb10-6f6b-4503-8575-7824e2d66925" serial="0">
    2019-06-17 14:21:41,731: kskm.ksr.load.ksr: INFO ../src/kskm/ksr/tests/data/ksr-root-2018-q1-0-d_to_e.xml 001:   <Request>
    2019-06-17 14:21:41,731: kskm.ksr.load.ksr: INFO ../src/kskm/ksr/tests/data/ksr-root-2018-q1-0-d_to_e.xml 002:     <RequestPolicy>
    2019-06-17 14:21:41,731: kskm.ksr.load.ksr: INFO ../src/kskm/ksr/tests/data/ksr-root-2018-q1-0-d_to_e.xml 003:       <ZSK>
    2019-06-17 14:21:41,731: kskm.ksr.load.ksr: INFO ../src/kskm/ksr/tests/data/ksr-root-2018-q1-0-d_to_e.xml 004:         <PublishSafety>P10D</PublishSafety>
    ... about 600 lines of output ...

The resulting SKR is written to stdout unless a second positional argument is provided:

    kskm-ksrsigner --config ksrsigner.yaml ksr-root-2018-q1-0-d_to_e.xml skr-out.xml

or something like this is added to ksrsigner.yaml:

    filenames:
      output_skr: skr-out.xml



**#WIN**
