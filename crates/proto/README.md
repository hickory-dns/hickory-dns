# Overview

`hickory-proto` is a safe and secure low-level DNS library. 
This is the foundational DNS protocol library used by the other higher-level Hickory DNS crates.

Unless you want to manipulate the DNS packets directly, it is likely not the library you want.
For higher-level interfaces, refer to the [`hickory-server`], [`hickory-client`],
[`hickory-resolver`] and [`hickory-recursor`] library crates instead.

[`hickory-server`]: ../server
[`hickory-client`]: ../client
[`hickory-resolver`]: ../resolver
[`hickory-recursor`]: ../recursor

## Versioning

Hickory DNS does it's best job to follow semver. Hickory DNS will be promoted to 1.0 upon stabilization of the publicly exposed APIs. This does not mean that Hickory DNS will necessarily break on upgrades between 0.x updates. Whenever possible, old APIs will be deprecated with notes on what replaced those deprecations. Hickory DNS will make a best effort to never break software which depends on it due to API changes, though this can not be guaranteed. Deprecated interfaces will be maintained for at minimum one major release after that in which they were deprecated (where possible), with the exception of the upgrade to 1.0 where all deprecated interfaces will be planned to be removed.
