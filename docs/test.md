# Test Framework

## Python unit testing framework (unittest)

The unittest unit testing framework supports test automation, sharing of setup and shutdown code for tests, aggregation of tests into collections, and independence of the tests from the reporting framework. The unittest module provides a rich set of tools for constructing and running tests.

## Running unit testing

Unit testing is executed using `make test`.

In order to perform unit testing with an archive of previous KSR/SKR, set `KSKM_KSR_ARCHIVE_PATH` to KSR archive directory with the KSR files in subdirectory `${KSKM_KSR_ARCHIVE_PATH}/ksr`.

## Code Coverage

Code coverage analysis is performed using `make coverage`, resulting in a coverage report being generated in the `htmlcov` directory. The aim for the project is to have 100% test coverage for all security functions.
