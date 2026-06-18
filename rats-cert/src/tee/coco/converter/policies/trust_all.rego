package policy

import rego.v1

# Debug / test only: every dimension is affirming regardless of input.
# Use this template ONLY for development and testing, never in production,
# because it asserts trustworthiness without verifying any evidence.
default executables := 2
default hardware := 2
default configuration := 2
default file_system := 2
