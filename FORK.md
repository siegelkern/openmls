# Fork of OpenMLS

This repository, `siegelkern/openmls`, is a public fork of [openmls/openmls](https://github.com/openmls/openmls). Our releases are OpenMLS releases plus a few changes, and our consumers pin a release tag (see [Releases](#releases)). Every change that is useful for OpenMLS goes upstream as a pull request, so that our own patchset stays small and easy to tell apart from upstream.

## Repositories

| Repository | What it is for |
|---|---|
| `openmls/openmls` | Upstream. |
| `siegelkern/openmls` (public, this one) | The release branches, the changes that stay in this fork, and our releases. |
| `SchwarzDigits/openmls` (public) | The branches of pull requests to upstream. |

## Branches

| Branch | What it is |
|---|---|
| `main` | Mirror of upstream's `main`. Fast-forward only; never commit to it. |
| `digits/<version>` | A release branch: upstream's release tag `v<version>` plus our changes and the fork-only commits. Releases are tagged here (see [Releases](#releases)). The newest one is the default branch. |
| `digits/<topic>` | One change that stays in this fork, based on the current release branch. |

In `SchwarzDigits/openmls`, each change for upstream has its own branch `fix/<topic>`, based on upstream's `main` or on the change it builds on.

There is no integration branch. Each release branch is built from upstream's release and our changes, and it only grows.

## What a release branch contains

On top of upstream's release tag, in this order:

1. **Backports**: changes upstream has merged after its release, which our consumers need before upstream's next release. They are cherry-picked with `-x` and adapted to the release where needed.
2. **Our changes**: changes that upstream does not have, as listed in [Our changes](#our-changes).
3. **The fork-only commits**, titled `chore(fork): …`. They never go upstream. Today these are `FORK.md` and `AGENTS.md`.

The whole deviation from upstream is the commit list of the release branch:

```sh
git log --oneline v<version>..digits/<version>                                         # everything we add to the release
git diff v<version> digits/<version> -- . ':(exclude)FORK.md' ':(exclude)AGENTS.md'     # our changes as one diff
```

## Our changes

Update this table with every change to a release branch and with every new release branch. A backport and a change that upstream has merged since are left out of the first release branch whose upstream release contains them.

| Change | Kind | Upstream |
|---|---|---|
| The leaf node lifetime policy passed per call | Backport | Merged after `v0.9.2`. The backport leaves out what `v0.9.2` does not have: the branch and reinit builders, `PublicGroup::validate_key_package_for_add` and the async mode. |
| Safe AAD items in external commits: `ExternalCommitBuilder::with_safe_aad` | Change | Proposed as a pull request. |
| A member of a past epoch's tree: `MlsGroup::member_at_epoch` | Change | Not proposed yet. |
| Epoch read secrets, feature `epoch-read-secrets`: `StagedCommit::epoch_read_secrets`, `MlsGroup::epoch_read_secrets`, `PublicGroup::process_message_with_epoch_secrets` | Change | Not proposed. Behind its feature flag; without it, an internal trait in the decryption path is the only difference. |

## Lifecycle of a change

A change for upstream:

1. In `SchwarzDigits/openmls`, create `fix/<topic>` from upstream's `main` and make the change, with tests and a `CHANGELOG.md` entry.
2. Go through [Before opening a pull request](#before-opening-a-pull-request).
3. Open the pull request against `main` of `openmls/openmls` once the branch is final, and only with the go-ahead of this fork's maintainer.
4. Only if our releases need the change before upstream releases it: create `digits/<topic>` from the current release branch, pick the commits of `fix/<topic>`, and adapt them to the release where needed. Then continue as for a change that stays in this fork.
5. Once upstream has merged it, delete `fix/<topic>`. The next release branch leaves the change out if upstream's release contains it.

A change that stays in this fork, or a backport:

1. Create `digits/<topic>` from the current release branch and make the change, with tests. A backport is `git cherry-pick -x` of the upstream commit, adapted to the release.
2. Go through [Before opening a pull request](#before-opening-a-pull-request).
3. Open a pull request from `digits/<topic>` into the release branch, and merge it with **Rebase and merge**, so the release branch stays linear. Then delete `digits/<topic>` and add the change to [Our changes](#our-changes).

If things go differently:

- **Upstream changes the change before merging it:** The next release branch takes upstream's version, wording included.
- **Upstream declines it:** It stays in our release branches. Keep `fix/<topic>` while a later attempt upstream is likely, and mark the change in [Our changes](#our-changes) as staying in this fork.
- **Upstream's `main` moves past an open pull request and conflicts:** Rebase the `fix/` branch. This rewrites a branch with an open pull request, so agree on it first.

## Rules

- One change per branch and per pull request. A change that needs another one is based on that branch, and its pull request says so.
- Release branches only grow and stay linear: no merge commits, never rebase or force-push them.
- Never commit to `main`, and don't force-push a branch with an open pull request without agreeing on it first.
- This repository is public and a fork of `openmls/openmls`. Commit messages, pull requests, issues and comments here name no upstream issue or pull request (`#…`, `openmls/openmls#…`, links to them): GitHub would show them upstream. A backport keeps the upstream commit hash from `cherry-pick -x` and drops the pull request number from its title.
- The pull request into a release branch and the one upstream don't reference each other.
- Text in code, changelog entries and commit messages of a `fix/` change must be true for upstream's code.
- Commit and pull request titles follow [Conventional Commits](https://www.conventionalcommits.org/), as upstream does: `fix: …`, `feat(<scope>): …`, `docs: …`. Fork-only commits use `chore(fork): …`.
- Commits and pull requests carry no references to AI tools: no co-author trailers, no session links.

## Before opening a pull request

- `cargo fmt --all --check`.
- Clippy as upstream's CI runs it. `interop_client` needs `protoc`, set `PROTOC` if it isn't on the path:

  ```sh
  cargo clippy -p openmls --tests --benches --examples -p openmls_basic_credential -p cli -p interop_client \
    -p mls-ds -p ds-lib -p openmls_libcrux_crypto -p openmls_memory_storage -p openmls_rust_crypto \
    -p openmls_test -p openmls-wasm -p openmls_traits -- -D warnings
  ```

- The tests of the crates you changed, at least `cargo test -p openmls`. `#[openmls_test]` runs only the mandatory ciphersuite by default; a change that touches ciphersuites also runs `cargo test -p openmls --features all-ciphersuites,draft-ietf-mls-pq-ciphersuites`.
- A change to the epoch read secrets also runs `cargo test -p openmls --features epoch-read-secrets`, and together with `extensions-draft,extensions-draft-test-dependencies` and with `virtual-clients-draft,virtual-clients-draft-test-dependencies`.
- `cargo build --release --target wasm32-unknown-unknown -p openmls -F js`. Upstream checks the wasm build, and it fails on missing documentation.
- For the pull request upstream, check that the branch carries the change and nothing of this fork:

  ```sh
  git fetch upstream main
  git log --oneline upstream/main..HEAD                     # only the commits of this change
  git log --oneline --grep='^chore(fork):' upstream/main..HEAD | grep . && echo "fork-only commit in this branch"
  git diff --name-only upstream/main...HEAD | grep -xE 'FORK.md|AGENTS.md' && echo "fork-only file in this branch"
  ```

## Following upstream

Our consumers build on released OpenMLS versions, so we follow upstream's releases, not upstream's `main`. When we take over an upstream release, it gets its own release branch (see [A new upstream release](#a-new-upstream-release)). In between, a change upstream has merged can come in as a backport.

`main` mirrors upstream's `main` for comparison. Fast-forward it now and then:

```sh
git remote add upstream https://github.com/openmls/openmls.git    # once
git fetch upstream main
git push origin upstream/main:main
```

### A new upstream release

Take over an upstream release when our consumers move to it, or when a release of ours should carry upstream's fixes. For upstream's release `v<version>`, with `<previous>` the version of the current release branch:

```sh
git fetch upstream tag v<version> --no-tags
git push origin v<version>      # the one upstream tag the release branch is based on
git switch -c digits/<version> v<version>
git log --reverse --oneline v<previous>..origin/digits/<previous>    # our commits, oldest first
git cherry-pick -x <commits>            # all of them, except what upstream's release contains
git push origin digits/<version>
```

- Leave out backports and changes that upstream's release already contains, and update [Our changes](#our-changes).
- Conflicts in one of our changes: adapt it to upstream's code. If its `fix/` branch has an open pull request upstream, that branch needs a rebase as well.
- A commit message can be corrected while picking it, with `git cherry-pick -x -e`.
- Push only single upstream tags, never `git push --tags`.

Then go through the checks of [Before opening a pull request](#before-opening-a-pull-request), tag (see below), and make the new branch the default branch:

```sh
gh repo edit siegelkern/openmls --default-branch digits/<version>
```

## Releases

A release is an annotated tag on a release branch, named `openmls-v<version>+fork.<n>`, for example `openmls-v0.9.2+fork.1`. `<version>` is the version of upstream's release the branch is built on, such as `0.9.2` for upstream's tag `v0.9.2`, and `<n>` counts our releases on it; a later release on the same branch takes the next `<n>`. The suffix marks the tag as our deviation from the upstream release it names.

1. Make sure the checks from [Before opening a pull request](#before-opening-a-pull-request) pass on the release branch.
2. Tag and push. The tag message names the upstream release and lists our changes since the previous release:

   ```sh
   git switch digits/<version> && git pull
   git log --oneline <previous tag>..HEAD    # our changes since the previous release
   git tag -a openmls-v<version>+fork.<n>
   git push origin openmls-v<version>+fork.<n>
   ```

Consumers pin the tag with Cargo:

```toml
openmls = { git = "https://github.com/siegelkern/openmls", tag = "openmls-v0.9.2+fork.1", features = ["epoch-read-secrets"] }
```

Tags without `+fork.` are upstream's; never create them here.

Never move or delete a pushed tag. Consumers pin it, and their `Cargo.lock` records its commit. Tags point at commits, not branches, so creating, renaming or deleting branches doesn't affect them.

## Fork-only files

`FORK.md` and `AGENTS.md` exist only in the release branches, in `chore(fork):` commits. Neither they nor any other `chore(fork):` commit belongs on a `fix/<topic>` branch. The check is part of [Before opening a pull request](#before-opening-a-pull-request).

## CI

Upstream's workflows are unchanged. They run for every pull request and for pushes to `main`, so a pull request into a release branch runs upstream's checks against our changes. The epoch read secrets are not part of upstream's test matrix; their tests run locally (see [Before opening a pull request](#before-opening-a-pull-request)).

## AI coding agents

The instructions for coding agents are in [AGENTS.md](AGENTS.md).
