# DNSSEC KSK Management Tools

This repository contains source code for the software used by PTI to manage
the DNSSEC Key Signing Key (KSK) for the Root Zone.

More information about Root Zone Management is available at
https://www.iana.org/domains/root.


## Dependencies

This tool depends on the following software:

- [Python 3.11](https://www.python.org/) with [poetry](https://python-poetry.org/) and [mypy](http://mypy-lang.org/)
- [pykcs11](https://github.com/LudovicRousseau/PyKCS11)
- [cryptography](https://cryptography.io/) (for DNSSEC validation of KSRs)
- [PyYAML](https://pyyaml.org/) (to load configuration files)
- [SWIG](http://www.swig.org/) (for pykcs11)
- [Pydantic](https://pydantic.dev/)

For the KSR submission webserver (wksr), the following extras are required:

- [FastAPI](https://fastapi.tiangolo.com)

## Additional test dependencies

For testing and independent DNSSEC validation of KSRs, the following modules are used:

- [dnspython](http://www.dnspython.org/)

### Debian Dependencies

    apt-get install python3 python3-dev python3-venv swig


## Development Setup

To create a virtual environment for testing with poetry, use `make depend` or use a [VS Code](https://code.visualstudio.com/) devcontainer.

N.B. You will need to ensure that SWIG and SoftHSM are installed, as pykcs11 and tests depends on them.


## Code Documentation

- Code formatted using [Ruff](https://docs.astral.sh/ruff/) and [isort](https://github.com/timothycrosley/isort). Use `make reformat` to tidy up source code before committing changes.
- Code documentation through the use of [Doxygen](http://www.doxygen.nl/).
- Documentation include core method's description, arguments and return values in line with the code.
- The code shall be a [PEP 8](https://www.python.org/dev/peps/pep-0008/) compliant and docstring conventions [PEP 257](https://www.python.org/dev/peps/pep-0257/).


## Design choices

- The **Python XML library** (Expat) is not used for reading/writing XML data in order to limit the amount of code.
- **DNS Python** is only used for testing as we do not need to parse or output DNS data. The required functions for signing are provided by PKCS#11 and the few functions needed for DNSSEC processing are reimplemented.
- **FastAPI** is used as a webserver in _wksr_. ICANN uses Django for several projects, but since this project only requires a very small subset of Django functionality FastAPI has been considered a better fit.
- **YAML** was chosen as the configuration file format for increased readability compared to **JSON**.

## Containers

The `make container` target will create containers for both the core tools as as well the webserver (wksr).

### Running

Example of how to run a tool with the Luna HSM using the `kskm` container:

    docker run --rm -it \
        --mount readonly,type=bind,source=/etc/Chrystoki.conf,target=/etc/Chrystoki.conf \
        --mount readonly,type=bind,source=/usr/safenet/lunaclient,target=/usr/safenet/lunaclient \
        --device=/dev/g70 \
        kskm:latest \
        /usr/safenet/lunaclient/bin/cmu list
