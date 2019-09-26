# DNSSEC KSK Management Tools


## KSR Signer

### Configuration File

### Command Line Usage




## Keymaster

...

### Configuration File

_Keymaster_ uses the `hsm` section from the _KSR Signer_ configuration file.


### Command Line Usage


## Trust Anchor Exporter

The _Trust Anchor Exporter_ exports the current set of trust anchors in [RFC 7958](https://tools.ietf.org/html/rfc7958) XML format. The keys are fetched from the HSM as specified in the KSR Signer configuration file.

### Configuration File

_Trust Anchor Exporter_ uses the `hsm` and `keys` sections from the _KSR Signer_ configuration file.

### Command Line Usage

    kskm-trustanchor [-h] --config CFGFILE [--debug] [--trustanchor XMLFILE]




## KSR Receiver

The _KSR Receiver is a simple web server that will receive upload KSR files and validate them using the KSR signer's validation logic. The result will be return as a web page together with an optional notification email.

### Configuration File

The _KSR Receiver Web Server_ configuration is written YAML. The following parameters can be set:

- tls:
    - cert: TLS certificate file
    - key: TLS key file
    - ca\_cert: TLS CA certificates bundle file
    - ciphers: List of allowed TLS ciphers (OpenSSL syntax)
    - require\_client\_cert: True if TLS client authentication is required
- ksr:
    - max\_size: Max number of bytes in upload KSR files
    - content\_type: Content type of uploaded KSR files
    - prefix: Prefix of saved uploaded KSR files
- notify: Optional email notification configuration
    - subject: Subject 
    - from: Notification email sender
    - to: Notification email receipient
    - smtp_server: Mail server for notification email
- templates:
    - upload: upload HTML page template file
    - result: result HTML page template file
    - email: email notification template file
- ksrsigner_configfile: KSR signer configuration file
- client_whitelist: List of SHA-256 fingerprints of allowed TLS clients

### Command Line Usage

     kskm-wksr [-h] [--config filename] [--port PORT] [--debug]




## SHA-256 PGP Words calculator

_SHA-256 PGP Words calculator_ reads data from STDIN and emits a SHA-256 checksum as hex and PGP words on STDOUT.

### Command Line Usage

    kskm-sha2wordlist < [file]

### Example Command

     > echo "hello, world" | kskm-sha2wordlist

### Example Output

     SHA-256:    853ff93762a06ddbf722c4ebe9ddd66d8f63ddaea97f521c3ecc20da7c976020
     PGP Words:  music customer waffle consensus flagpole Orlando goggles suspicious virus candidate snowslide underfoot treadmill tambourine stockman hazardous payday Galveston swelter performance revenge integrate Dupont Brazilian concert revolver bison surrender kiwi mosquito facial butterfat
