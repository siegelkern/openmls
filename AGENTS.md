# Instructions for coding agents

Read [FORK.md](FORK.md) first. It describes the branches, the releases and the rules of this fork.

The rules that matter most:

- Never push to `openmls/openmls`, and never open a pull request or an issue there, without the go-ahead of this fork's maintainer.
- This repository is a public fork of `openmls/openmls`. Commit messages, pull requests and comments here name no upstream issue or pull request (see [Rules](FORK.md#rules)).
- Never move or delete a pushed tag (see [Releases](FORK.md#releases)).
- The consumer of this fork is `siegelkern-sdk`. It pins a release tag in its workspace `Cargo.toml`, so a change reaches it only with a new tag.
