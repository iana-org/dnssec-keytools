from enum import Enum


class EXIT_CODES(Enum):
    success = 0  # Success
    interrupt = 1  # Ctrl+C pressed
    config = 2  # Configuration error
    fatal = 3  # Fatal error
