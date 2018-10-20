# Overview

TRust-DNS Native-TLS is a library which implements the DNS over TLS protocol and client side functions.

This library allows for TLS connections to be established to remote DNS servers. It can replace the standard `ClientConnection` in the TRust-DNS library. This allows the host default TLS library to be used for handling TLS communications.

## Versioning

TRust-DNS does it's best job to follow semver. TRust-DNS will be promoted to 1.0 upon stabilization of the publicly exposed APIs. This does not mean that TRust-DNS will necessarily break on upgrades between 0.x updates. Whenever possible, old APIs will be deprecated with notes on what replaced those deprecations. TRust-DNS will make a best effort to never break software which depends on it due to API changes, though this can not be guaranteed. Deprecated interfaces will be maintained for at minimum one major release after that in which they were deprecated (where possible), with the exception of the upgrade to 1.0 where all deprecated interfaces will be planned to be removed.