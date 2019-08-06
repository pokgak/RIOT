# wolfssl tests and benchmarks

This test can be used to validate the usability and performance of a wolfcrypt/wolfssl
port to a specific target.

## Compile options

Specific modules can be enabled/disabled using the `USEMODULE` variable in `Makefile`.

To disable full-benchmark test, comment out the line `USEMODULE += wolfssl-benchmarks`.

## Running

