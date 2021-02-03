# DNSSEC KSK Management Tools


## KSR Signer

### Configuration File

The _KSR Signer_ configuration is written YAML. The following parameters can be set:

### Command Line Usage

    usage: kskm-ksrsigner [-h] [--schema NAME] [--previous_skr SKRFILE]
                          [--log-ksr] [--log-skr] [--log-previous-skr]
                          [--config CFGFILE] [--debug] [--syslog] [--force]
                          [KSRFILE] [SKRFILE]

    KSK request signer

    positional arguments:
      KSRFILE               KSR request to process (default: None)
      SKRFILE               SKR output filename (default: None)

    optional arguments:
      -h, --help            show this help message and exit
      --schema NAME         Name of schema (defined in config) to follow (default:
                            normal)
      --previous_skr SKRFILE
                            Path to the previous SKR to use for validation
                            (default: None)
      --log-ksr             Log KSR contents (default: False)
      --log-skr             Log SKR contents (default: False)
      --log-previous-skr    Log previus SKR contents (default: False)
      --config CFGFILE      Path to the KSR signer configuration file (default:
                            ksrsigner.yaml)
      --debug               Enable debug operation (default: False)
      --syslog              Enable syslog output (default: False)
      --force               Don't ask for confirmation (default: False)


### Configuration

The _KSR Receiver_ configuration is written YAML. See annotated [ksrsigner.yaml](../config/ksrsigner.yaml) configuration file example.




## Keymaster

_Keymaster_ is a tool to create and delete keys as well as perform a key inventory.

### Command Line Usage

    usage: kskm-keymaster [-h] [--config CFGFILE] [--hsm HSM] [--debug]
                          {inventory,keygen,keydelete}
                          ...

    Keymaster

    positional arguments:
      {inventory,keygen,keydelete}

    optional arguments:
      -h, --help            show this help message and exit
      --config CFGFILE      Path to the KSR signer configuration file (default:
                            ksrsigner.yaml)
      --hsm HSM             HSM to operate on (default: None)
      --debug               Enable debug operation (default: False)


### Configuration

_Keymaster_ uses the `hsm` section from the _KSR Signer_ configuration file.



## Trust Anchor Exporter

The _Trust Anchor Exporter_ exports the current set of trust anchors in [RFC 7958](https://tools.ietf.org/html/rfc7958) XML format. The keys are fetched from the HSM as specified in the KSR Signer configuration file.

### Command Line Usage

    usage: kskm-trustanchor [-h] [--config CFGFILE] [--debug]
                            [--trustanchor XMLFILE] [--id ID]

    DNSSEC Trust Anchor exporter

    optional arguments:
      -h, --help            show this help message and exit
      --config CFGFILE      Path to the KSR signer configuration file (default:
                            ksrsigner.yaml)
      --debug               Enable debug operation (default: False)
      --trustanchor XMLFILE
                            Path to write trust anchor XML to (default: None)
      --id ID               Trust anchor identifier (default: None)


### Configuration

_Trust Anchor Exporter_ uses the `hsm` and `keys` sections from the _KSR Signer_ configuration file.



## KSR Receiver

The _KSR Receiver_ (aka wksr) is a simple web server that will receive upload KSR files and validate them using the KSR signer's validation logic. The result will be return as a web page together with an optional notification email.

### Command Line Usage

    usage: kskm-wksr [-h] [--config filename] [--port PORT] [--debug]

    KSR Web Server

    optional arguments:
      -h, --help         show this help message and exit
      --config filename  Configuration file (default: wksr.yaml)
      --port PORT        Port to listen on (default: 8443)
      --debug            Enable debugging (default: False)


### Configuration

The _KSR Receiver_ configuration is written YAML. See annotated [wksr.yaml](../config/wksr.yaml) configuration file example.




## SHA-256 PGP Words calculator

_SHA-256 PGP Words calculator_ reads data from STDIN and emits a SHA-256 checksum as hex and PGP words on STDOUT.

### Command Line Usage

    kskm-sha2wordlist < [file]

### Example Command

     > echo "hello, world" | kskm-sha2wordlist

### Example Output

     SHA-256:    853ff93762a06ddbf722c4ebe9ddd66d8f63ddaea97f521c3ecc20da7c976020
     PGP Words:  music customer waffle consensus flagpole Orlando goggles suspicious virus candidate snowslide underfoot treadmill tambourine stockman hazardous payday Galveston swelter performance revenge integrate Dupont Brazilian concert revolver bison surrender kiwi mosquito facial butterfat
