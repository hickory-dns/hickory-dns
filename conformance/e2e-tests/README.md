# `e2e-tests`

These are end-to-end, binary-level tests that use the `dns-test` framework.

Unlike the `conformance-tests`, these tests are not meant to be run against different DNS implementations. They are only meant to test `hickory-dns`.

Therefore the `DNS_TEST_SUBJECT` and `DNS_TEST_PEER` environment variables must not be set.
