# Fuzzing the package index parser

`repo.toml` is the trust anchor of the whole repository: it lists every package's blake3 hash, and
a signature over it authenticates the lot. A device fetches it from a host it does not control, and
`Repository::from_toml` runs on those bytes — before any of them have been shown to be genuine.

```sh
cargo +nightly fuzz run repo_toml -- -max_total_time=60
```

Nightly is required: `cargo-fuzz` needs `-Zsanitizer=address`, and this repository pins stable.

## The corpus is not decoration

Measured 2026-09-04. A real bug was planted — `PackageName::new` stopped rejecting `/` — and run
against the target twice:

| corpus | result |
|---|---|
| one realistic `repo.toml` | **1 840 305 runs, NOT caught** |
| four shape-aware seeds | caught |

libFuzzer's byte-level mutations almost never produce valid TOML containing a *quoted key with a
specific character in it*. Without a seed that already has that shape, the mutator cannot reach the
states where the interesting assertions live, and the target proves nothing while looking busy.

The four seeds are therefore part of the test, not sample data:

| seed | the shape it teaches the mutator |
|---|---|
| `seed-real.toml` | a well-formed index with real-looking hashes |
| `seed-quoted-key.toml` | a quoted key containing a path separator |
| `seed-dotted.toml` | dots and an OS prefix — the `name.target` and `host:name` forms |
| `seed-empty-key.toml` | the empty key TOML permits and the name type rejects |
| `seed-traversal.toml` | `.` and `..` |

The corpus libFuzzer discovers is NOT committed — it reached 6 677 files in one 45-second run and
is a build product. Only the seeds are tracked.

## What the target asserts, and why it is not stricter

Three versions of this target existed before this one, and the first two reported CORRECT behaviour
as a crash. Both were written from a guess at the specification rather than a reading of it.

* v1 asserted no package name in the index may be empty. TOML permits `"" = "…"` and
  `Repository::from_toml` faithfully returns it — but `PackageName::new` rejects an empty name and
  `Library::get_all_package_names` filters every key through it, so such a key is inert. Not a
  defect.
* v2 asserted no name may be `.` or `..`. `..` *is* rejected, by the at-most-one-dot rule. A bare
  `.` is accepted.

So the contract was measured directly instead of assumed:

```
"."      ACCEPTED      "a.b"    ACCEPTED
".."     rejected      "a.b.c"  rejected      ""       rejected
"a/b"    rejected      "a\0b"   rejected      "a:b"    rejected     "x:y:z"  rejected
```

The target now asserts exactly that, plus determinism — the anti-rollback ratchet compares `serial`
across two fetches, so "the same index" has to be a fact about the bytes.

A bare `.` is a wart: it can never name a real package, and it forms URLs like `<repo>/.`. It is
not a traversal, so it is recorded in the E-OS roadmap rather than asserted here. **A target that
fires on behaviour the code intends teaches people to ignore fuzz crashes**, which costs more than
the wart does.
