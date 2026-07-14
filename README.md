# eos-pkgutils

**E-OS fork of [`redox-os/pkgutils`](https://gitlab.redox-os.org/redox-os/pkgutils).** Part of the [**E-OS**](https://github.com/Gh0s777tt/E-OS) ecosystem — a hardened, Crimson-branded downstream of [Redox OS](https://www.redox-os.org).

This repository is **`pkg`**, the Redox package manager / client.

## E-OS changes vs upstream

- **R-703** — the client verifies the `repo.toml` **manifest signature** (ed25519 layer of the hybrid `eos-repo-sign`) against an **in-image-pinned key** before trusting the index, blocking rollback / freeze / substitution attacks. _(On the `eos` branch; pin integration pending.)_

## How it's pinned

The E-OS build pins this fork in [`recipes/core/pkgutils/recipe.toml`](https://github.com/Gh0s777tt/E-OS/blob/main/recipes/core/pkgutils/recipe.toml):

- branch **`master`** · rev **`7e89ac2ebad6`**
- **2 commit(s) behind** upstream master

## Build standalone

This fork is normally built by the E-OS cookbook (`make CI=1 …` in the [main repo](https://github.com/Gh0s777tt/E-OS)). To build it on its own you need the Redox toolchain; see the main repo's [build guide](https://github.com/Gh0s777tt/E-OS/blob/main/docs/building.md).

## Hosting

**GitLab (source of truth):** https://gitlab.com/e-os/eos-pkgutils  
**GitHub (read-only mirror):** https://github.com/Gh0s777tt/eos-pkgutils

## License

MIT (inherited from upstream Redox). The E-OS project as a whole is AGPL-3.0; see the [main repo](https://github.com/Gh0s777tt/E-OS/blob/main/LICENSE).

---
[E-OS main repo](https://github.com/Gh0s777tt/E-OS) · [Docs](https://github.com/Gh0s777tt/E-OS/tree/main/docs) · [Upstream](https://gitlab.redox-os.org/redox-os/pkgutils)
