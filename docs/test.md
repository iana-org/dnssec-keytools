# Test Framework

The included test framework provides a comprehensive set of unit tests. Unit testing is a level of software testing where individual components (units) of the software are tested. The purpose is to validate that each unit of the software performs as designed. The unit tests uses some test data (KSRs) from previous key signing ceremonies to verify certain functionality.

## Python unit testing framework (unittest)

The unittest unit testing framework supports test automation, sharing of setup and shutdown code for tests, aggregation of tests into collections, and independence of the tests from the reporting framework. The unittest module provides a rich set of tools for constructing and running tests.

## Running unit testing

Unit testing is executed using `make test`.

In order to perform unit testing with an archive of previous KSR/SKR, set `KSKM_KSR_ARCHIVE_PATH` to KSR archive directory with the KSR files in subdirectory `${KSKM_KSR_ARCHIVE_PATH}/ksr`.

## Code Coverage

Code coverage analysis is performed using the Coverage.py tool. The tool monitors the program, noting which parts of the code have been executed, then analyzes the source to identify code that could have been executed but was not. It shows which parts of the code which are being exercised by tests, and which are not. The aim for the project is to have 100% test coverage for all security-related functions.

Code coverage analysis is executed using `make coverage`, resulting in a coverage report being generated in the `htmlcov` directory. Open the file `htmlcov/index.html` to review the report.

