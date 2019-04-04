# DNSSEC KSK Management Tools

## Dependencies

- Python 3.7 with mypy
- pykcs11
- cryptography (for DNSSEC validation of KSRs)
- PyYAML (to load configuration files)


## Additional test dependencies

- dnspython + pycryptodome (for independent DNSSEC validation of KSRs)


## Design choices

- The **Python XML library** (Expat) is not used for reading/writing XML data in order to limit the amount of code.
- **DNS Python** is only used for testing as we do not need to parse or output DNS data. The required functions for signing are provided by PKCS#11 and the few functions needed for DNSSEC processing are reimplemented.
- **Flask** is used as a webserver in _wksr_. ICANN uses Django for several projects, but since this project only requires a very small subset of Django functionality Flask has been considered a better fit. From an auditing perspective, Flask consists of ca 10k source code lines whereas Django consist of ca 240k source code lines.
- **YAML** was chosen as the configuration file format for increased readability compared to **JSON**.


## Code Documentation

- Code documentation through the use of [Doxygen](http://www.doxygen.nl/).
- Documentation include core method's description, arguments and return values in line with the code.
- The code shall be a [PEP 8](https://www.python.org/dev/peps/pep-0008/) complaint and docstring conventions [PEP 257](https://www.python.org/dev/peps/pep-0257/).

