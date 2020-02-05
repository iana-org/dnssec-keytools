# Test Framework

## Unit Testing

Unit testing is written using the standard Python unittest suite and executed using `make test`.

In order to perform unit testing with an archive of previous KSR/SKR, set `KSKM_KSR_ARCHIVE_PATH` to KSR archive directory with the KSR files in subdirectory `${KSKM_KSR_ARCHIVE_PATH}/ksr`.

## Code Coverage

Code coverage testing is performed using `make coverage`, resulting in a coverage report in the `htmlcov` directory. Security functions should have 100% test coverage.
