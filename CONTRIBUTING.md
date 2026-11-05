# Contributing to Hickory DNS

Before contributing, please consider the terms of the licenses (Apache License 2.0 or MIT). We chose these licenses for two reasons:

- To be more compatible with the general Rust ecosystem
- So that this software can be liberally used with few restrictions

After ensuring the license options are compatible with the aims of the contribution, then please submit your PR for review and we will review as soon as possible. My only ask is that you do not do this for free, unless it's something that is a passion or learning project for you. Please, find a way to be paid for your work. You are worth it.

## Understanding the design

Please read the [Architecture](ARCHITECTURE.md) to understand the general design and layout of the Hickory DNS projects.

## Submitting PRs

Before submitting a PR it would be good to discuss the change in an issue so as to avoid wasted work, also feel free to reach out on the Discord channel listed on the front page of the GitHub project. Please keep PRs focused on one issue at a time. While issues are not required for a PR to be accepted they are encouraged, especially for anything that would change behavior, change an API, or be a medium to large change.

When submitting PRs, please keep refactoring commits separate from functional change commits. Breaking up the PR into multiple commits such that a reviewer can follow the change improves the review experience, and will result in PRs getting merged more quickly. The codebase should remain functional at each commit, both to ensure that each commit can be reviewed as a self-contained unit, and to aid in bisecting and debugging in the future. When addressing review comments, please amend the relevant commit instead of adding a subsequent commit. We prefer to keep git history linear, so please rebase your PR branch when needed instead of adding a merge commit.

### Test policy

All PRs *must* pass all tests. Ideally any PR submitted should have more than 85% code coverage, but this is not mandated.

## Build tools

Hickory DNS uses [just](https://github.com/casey/just) and [cargo-workspaces](https://github.com/pksunkara/cargo-workspaces) to orchestrate checks and tests in CI. We recommend installing these to ease local development. Docker is required for some test suites.

## Code style

We follow rustfmt's formatting rules, and check them in CI. You can check formatting locally with `just fmt`. Try to wrap comments and other long lines at 100 columns where possible.

Item names should generally follow the conventions in the [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/naming.html). We make some exceptions for structs and enum variants that are named after DNS mnemonics, using all uppercase characters instead of camel case.

Items in the same module should generally be in topological order, with the main exposed APIs at the top, and leaf functions below all their callers. Constants and unit test modules should be at the bottom of the file.

Import statements inside function bodies are discouraged, as are fully-qualified names. Both should be replaced with import statements at the top of the relevant module.

## Releases

Hickory DNS tries to follow semver versioning semantics. Major versions will not break APIs in a current major revision. If changes are being made to the current `main` branch, double check the current status of the Major release. Until `1.x.x`, all `0.x.x` minor releases are treated as major releases with breaking changes allowed. Releases are performed on an ad-hoc/on-demand basis.

*Maintainers*: If changes are needed to previous releases, then there should exist a `release/x.x`. If this does not exist, then go to the previous most recent tag (release) and create a new branch at that tag `release/x.x`. For example, for the branch `release/0.19`:

```shell
> git fetch origin
> git checkout v0.19
> git branch release/0.19
> git push --set-upstream origin release/0.19
```

## Performing a Release, for Maintainers

Releases are somewhat automated. The github action, `publish`, watches for any tags on the project. It then attempts to perform a release of all the libraries. This does not always work, for various reasons.

1. Create a new branch like `git checkout -b prepare-0.20.1`
1. Update all Cargo.toml files to the new version, `version = 0.20.1`
1. Update dependencies, `cargo update`
1. Update all inter-dependent crates, i.e. hickory-resolver to use `hickory-proto = 0.20.1`
1. Push to Github, create a PR and merge in `main` or the target release branch.
1. Go to [Releases](https://github.com/hickory-dns/hickory-dns/releases) and `Draft a new release`
1. Give it a `Tag Version` of `vX.x.x`, e.g. `v0.20.1`, *make sure this is tagging the correct branch, e.g. `main` or `release/0.19`*
1. Give it a  `Release Title` of something key to the release
1. Generate release notes
1. `Publish Release`, this will kick off the publish workflow

After approximately 45 minutes it should be published. This may fail.

**TBD**: add instructions to skip already published crates

## FAQ

- Why are there so few maintainers?

There have not been that many people familiar with DNS internals, networking, security, and Rust that the list of maintainers has been relatively small.

- Will new maintainers be considered?

Yes! There is no formal process, and generally it's a goal to open up to anyone who's been committing regularly to the project. We'd ask that you are committed to the goals of an open DNS implementation that anyone can freely use as they see fit. Please reach out on Discord if you'd like to become a maintainer and discuss with us.

## Configuring rust-analyzer

This repository contains multiple workspaces, so rust-analyzer will require additional configuration to provide hints in all files. If you are using the VS Code extension, create a `.vscode` directory inside the repository if it doesn't exist already, and edit `.vscode/settings.json` as follows:

```jsonc
{
    "rust-analyzer.linkedProjects": [
        "/path/to/hickory-dns/Cargo.toml",
        "/path/to/hickory-dns/conformance/Cargo.toml",
        "/path/to/hickory-dns/fuzz/Cargo.toml"
    ],
    "rust-analyzer.cargo.features": "all"
    // etc.
}
```

## Thank you!

Seriously, thank you for contributing to this project. Hickory DNS would not be where it is today without the support of contributors like you.
