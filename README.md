# DNSSEC KSK Management Tools

This repository contains source code for the software used by PTI to manage
the DNSSEC Key Signing Key (KSK) for the Root Zone.

More information about Root Zone Management is available at
https://www.iana.org/domains/root.


## Dependencies

This tool depends on the following software:

- [Python 3.7](https://www.python.org/) with [mypy](http://mypy-lang.org/)
- [pykcs11](https://github.com/LudovicRousseau/PyKCS11)
- [cryptography](https://cryptography.io/) (for DNSSEC validation of KSRs)
- [PyYAML](https://pyyaml.org/) (to load configuration files)
- [SWIG](http://www.swig.org/) (for pykcs11)
- [Voluptuous](https://github.com/alecthomas/voluptuous)

For the KSR submission webserver (wksr), the following extras are required:

- [Flask](http://flask.pocoo.org/)
- [pyOpenSSL](https://pyopenssl.org/)

## Additional test dependencies

For testing and independent DNSSEC validation of KSRs, the following modules are used:

- [dnspython](http://www.dnspython.org/)
- [pycryptodome](https://pycryptodome.readthedocs.io/)

### Debian Dependencies

    apt-get install python3 python3-dev python3-venv swig


## Setup

To create a virtual environment for testing, use `make venv`.

N.B. You will need to ensure that SWIG is installed, as pykcs11 depends on it.


## Code Documentation

- Code documentation through the use of [Doxygen](http://www.doxygen.nl/).
- Documentation include core method's description, arguments and return values in line with the code.
- The code shall be a [PEP 8](https://www.python.org/dev/peps/pep-0008/) compliant and docstring conventions [PEP 257](https://www.python.org/dev/peps/pep-0257/).


## Design choices

- The **Python XML library** (Expat) is not used for reading/writing XML data in order to limit the amount of code.
- **DNS Python** is only used for testing as we do not need to parse or output DNS data. The required functions for signing are provided by PKCS#11 and the few functions needed for DNSSEC processing are reimplemented.
- **Flask** is used as a webserver in _wksr_. ICANN uses Django for several projects, but since this project only requires a very small subset of Django functionality Flask has been considered a better fit. From an auditing perspective, Flask consists of ca 10k source code lines whereas Django consist of ca 240k source code lines.
- **YAML** was chosen as the configuration file format for increased readability compared to **JSON**.
