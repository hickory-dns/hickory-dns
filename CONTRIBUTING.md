# Contributing to Hickory DNS

Before contributing, please consider the terms of the licenses (Apache License 2.0 or MIT). We chose these licenses for two reasons:

- To be more compatible with the general Rust ecosystem
- So that this software can be liberally used with few restrictions

After ensuring the license options are compatible with the aims of the contribution, then please submit your PR for review and we will review as soon as possible. My only ask is that you do not do this for free, unless it's something that is a passion or learning project for you. Please, find a way to be paid for your work. You are worth it.

## Understanding the design

Please read the [Architecture](ARCHITECTURE.md) to understand the general design and layout of the Hickory DNS projects.

## Submitting PRs

Before submitting a PR it would be good to discuss the change in an issue so as to avoid wasted work, also feel free to reach out on the Discord channel listed on the front page of the GitHub project. Please, consider keep PRs focused on one issue at a time. While issues are not required for a PR to be accepted they are encouraged, especially for anything that would change behavior, change an API, or be a medium to large change.

When submitting PRs please keep refactoring commits separate from functional change commits. Breaking up the PR into multiple commits such that a reviewer can follow the change improves the review experience. This is not necessary, but can make it easier for a reviewer to follow the changes and will result in PRs getting merged more quickly.

### Test policy

All PRs *must* be passing all tests. Ideally any PR submitted should have more than 85% code coverage, but this is not mandated. When tests are failing, especially on previous branches this is often due to checked in testing keys for the DoH and DoT tests. See **Updating Security Related Tests**.

## Releases

Hickory DNS tries to follow semver versioning semantics. Major versions will not break APIs in a current major revision. If changes are being made to the current `main` branch, double check the current status of the Major release. Until `1.x.x`, all `0.x.x` minor releases are treated as major releases with breaking changes allowed. Releases are performed on an ad-hoc/on-demand basis.

*Maintainers*: If changes are needed to previous releases, then there should exist a `release/x.x`. If this does not exist, then go to the previous most recent tag (release) and create a new branch at that tag `release/x.x`, for example the branch `release/0.19`:

```shell
> git fetch origin
> git checkout v0.19
> git branch release/0.19
> git push --set-upstream origin release/0.19
```

Previous release can fail due to time-lapse, please see **Updating Security Related Tests**.

## Performing a Release, for Maintainers

Releases are somewhat automated. The github action, `publish`, watches for any tags on the project. It then attempts to perform a release of all the libraries, this does not always work, for various reasons.

1. Create a new branch like `git checkout -b prepare-0.20.1`
1. Update all Cargo.toml files to the new version, `version = 0.20.1`
1. Update dependencies, `cargo update`
1. Update all inter-dependent crates, i.e. hickory-resolver to use `hickory-proto = 0.20.1`
1. Update [CHANGELOG.md](CHANGELOG.md) to include all PR's (of consequence) since the previous release
1. Push to Github, create a PR and merge in `main` or the target release branch.
1. Go to [Releases](https://github.com/hickory-dns/hickory-dns/releases) and `Draft a new release`
1. Give it a `Tag Version` of `vX.x.x`, e.g. `v0.20.1`, *make sure this is tagging the correct branch, e.g. `main` or `release/0.19`*
1. Give it a  `Release Title` of something key to the release
1. Copy and pase the part of the CHANGELOG.md for this release into `Describe this release`
1. `Publish Release`, this will kick off the publish workflow

After approximately 45 minutes it should be published. This may fail.

**TBD**: add instructions about using Makefile.toml to skip already published crates

## Updating Security Related Tests

### All TLS tests are failing

TBD: add notes on updating certificates in test directories

### Windows OpenSSL tests are failing

When the OpenSSL related tests fail on Windows, this is often due to a new minor version of the OpenSSL implementation there being increased. There is no good way to get this updated automatically right now. The library for Windows is maintained by Shining Light Productions, available here: [slproweb.com/products/Win32OpenSSL](https://slproweb.com/products/Win32OpenSSL.html). On that page the currently published version can be seen, e.g. `Win64 OpenSSL v1.1.1j Light`. The version downloaded is specified in [Makefile.toml](Makefile.toml), look for `OPENSSL_VERSION = "1_1_1j"` and replace with the correct string.

## FAQ

- Why are there so few maintainers?

There have not been that many people familiar with DNS internals, networking, security, and Rust that the list of maintainers has been relatively small.

- Will new maintainers be considered?

Yes! There is no formal process, and generally it's a goal to open up to anyone who's been committing regularly to the project. We'd ask that you are committed to the goals of an open DNS implementation that anyone can freely use as they see fit. Please reach out on Discord if you'd like to become a maintainer and discuss with us.

## Thank you!

Seriously, thank you for contributing to this project. Hickory DNS would not be where it is today without the support of contributors like you.
