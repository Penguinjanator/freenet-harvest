# Making the migration's I/O half testable

**Status: a plan, not a change. Nothing here is implemented.** Written
2026-09-05 while the migration security fixes were landing, so the findings
that motivate it are recorded while the evidence is fresh.

## The problem, and the evidence for it

`ui/src/gateway/migrate_ops.rs` decides whether a seller's store, mailbox and
reputation survive an upgrade. It is a little over a thousand lines and, as
shipped, **no automated check executes any of it**.

`ui/src/gateway/mod.rs` gates the module on `target_arch = "wasm32"`, so
`cargo test --workspace` and `cargo clippy --workspace --all-targets` skip it.
CI does run `clippy -p harvest-ui --target wasm32-unknown-unknown -- -D
warnings`, so it is type-checked and linted — but there is no
`wasm-bindgen-test` dev-dependency anywhere in the workspace, and nothing has
ever run a line of it outside a browser.

The cost is measurable rather than theoretical. Of the four defects found in
the 2026-09-05 review round, the one blocking issue and two of the three
majors were in this file, and every one was found by a human-directed
adversarial read. None could have been caught by a test, because no test can
reach the code.

The module's own doc conceded the point years ago — "this is the part that
cannot be unit-tested (it needs a browser and a node)" — and stopped there.
The conclusion it did not draw is that the DECISIONS therefore had to move
somewhere reachable. Two have since moved (`migrate_seal`, `migrate_gate`);
this note is about the rest.

## What the target actually is

`migrate_seal`'s tests are an exhaustive truth table over its inputs, and they
are good tests. They also could not have caught the `deliver_put_ack`
correlation defect, and the reason generalises:

> The extraction made the DECISION testable and left the EVIDENCE-GATHERING
> untested — and both of this file's majors lived in evidence-gathering.

`disposition` is handed an already-formed `ForwardPut`. The bug was in what
forms one: a `PutResponse` correlated on instance id alone, which cannot
distinguish this migration's put from a store creation's put to the same id.
No test over `disposition`'s inputs can see that.

So the target of this work is **the code that turns node responses into
evidence and drives the walk** — `start`, `pump`, `deliver_state`,
`deliver_absent`, `deliver_unknown`, `deliver_put_ack`, `settle_forward`,
`finish` — not the decision functions, which are already extracted and
covered.

## The surprising part: the wasm gate is not load-bearing

Measured, not assumed. Removing the gate from `mod.rs` and the inner
`#![cfg]` from the file:

```
cargo +1.94.1 check   -p harvest-ui                  -> 0 errors
cargo +1.94.1 clippy  -p harvest-ui --all-targets    -> clean under -D warnings
```

The module **already compiles for the host**. The gateway calls it makes
(`get_contract`, `put_contract`, `send_delegate_message`) each have a native
arm returning `Err("contract operations require WASM")`, and `APP_STATE` is
not wasm-gated either (only `WEB_API` is).

So the gate is not protecting a compilation boundary. It is protecting
against *running* the code, and only three things actually break at runtime.
Each was measured by calling it from a host test:

| Call | On the host |
|---|---|
| `deliver_put_ack` and the other map lookups | **runs** |
| `APP_STATE.write()` | fails — no dioxus runtime |
| `wasm_bindgen_futures::spawn_local` | fails — catchable panic |
| `gloo_timers::callback::Timeout::new` | **aborts the process** (SIGABRT) |

The timer is the worst of the three and worth calling out: wasm-bindgen's
panic there is non-unwinding, so it does not fail a test, it kills the test
binary and takes every unrelated test in the process with it. Any staging
that leaves the timer un-injected while adding host tests is unsafe.

That table is the whole scope of the work. Three effects, not a thousand
lines.

### If you repeat this measurement, assert that a test actually RAN

The first version of the table above was wrong, and wrong in the direction
that matters: it reported all four calls as working. The probe checked the
exit code of

```
cargo test -p harvest-ui <filter> -- --exact
```

and **a filter that matches nothing also exits 0.** Three of the four names
did not match, so the measurement reported success while measuring nothing.

The remedy generalises past cargo: check that the tool did the work, not that
it returned without complaining. Here that means parsing the
`test result: ok. N passed` line and requiring `N >= 1`; the corrected probe
also greps for `SIGABRT`, because the timer's non-unwinding panic does not
produce a failing test result at all.

This is the same shape as the defects this file's history is made of -- an
instrument reporting success because it was measuring the wrong thing -- and
it is worth noticing that it appeared in the tool used to investigate them,
not only in the code under investigation.

## The plan, in three landable stages

Each stage leaves the tree better than it found it and can be reviewed alone.

### Stage 1 — inject the three effects

Introduce a narrow trait for exactly what breaks:

```rust
trait MigrationIo {
    fn spawn(&self, task: BoxFuture<'static, ()>);
    fn arm_deadline(&self, ms: u32, on_expiry: Box<dyn FnOnce()>);
    fn adopt_migrated_id(&self, predecessor: &[u8], successor: Vec<u8>);
    fn notify(&self, message: String);
}
```

Two implementations: the wasm one (today's bodies verbatim) and a fake that
records calls and lets a test fire a deadline by hand rather than by waiting.
A deterministic clock is the point — the current timeout paths can only be
exercised today by waiting `PROBE_TIMEOUT_MS` in a browser.

No behaviour change, no gate change. The wasm build is unaffected.

### Stage 2 — make the correlation state ownable

The four `thread_local!`s (`PROBES`, `PENDING`, `SESSION_WALKS`, `FORWARDS`)
become fields of one `Migrations` struct. The `thread_local` holds an instance
rather than four separate maps, so a test can build its own and drive it
without touching process-global state.

This is the stage that unlocks most of the value, and it is mechanical.

### Stage 3 — remove the gate

`mod.rs` stops gating the module; only the wasm `MigrationIo` impl stays
`#[cfg]`-ed. The file then joins `cargo test --workspace` and
`clippy --workspace --all-targets` like everything else.

Stage 3 is deliberately last: it is the smallest diff and the one with no
value until 1 and 2 have given tests something to hold.

## What this unlocks

Tests that cannot be written today, starting with the two that had to be
verified by reading during the 2026-09-05 fixes:

- a `GhostKeyList` reaches `start`, and `start` consults `SessionWalks`
- a second `GhostKeyList` does not restart a completed walk *through the real
  entry point* (today only the `SessionWalks` predicate is covered)
- a `NotFound` routes to `on_absent` while a timeout routes to `on_unknown` —
  the "silence is not absence" rule that the whole design rests on, and which
  is currently enforced only by a comment and a careful reader
- an unconfirmed forward put neither adopts nor notifies (today only the
  `disposition` output is covered, not that the effects are skipped)
- `deliver_put_ack` settles exactly one forward, exactly once, and ignores an
  id nothing is waiting on
- the marker-query timeout releases a pending probe exactly once, whichever of
  the three releases arrives first
- `adopt_recovered` records every probed generation, end to end

## What stays unreachable, permanently

The `MigrationIo` wasm implementation itself — the actual `WebApi` send, the
dioxus signal write, the browser timer. That is a thin adapter with no
branching, which is the point of pushing everything else out of it.

`tests/rehearsal/` remains the only thing that exercises the real network
path, and it needs a live node, so it is not a CI substitute. It is a useful
precedent though: it already compiles the real `ui/src/migrate.rs` via
`#[path]` rather than duplicating it.

## Risk, honestly

The argument against doing this is real: it is a refactor of the
highest-risk file in the app, and every defect it has had has been a silent
one — nothing crashed, data quietly did not survive an upgrade. A refactor
can introduce another of exactly that kind, and the tests that would catch it
are the ones this work is trying to create, so they are not there to protect
the work itself.

What contains it:

- Stages 1 and 2 are behaviour-preserving by construction — moving bodies
  behind a trait and moving four maps into a struct. Any diff hunk that
  changes a condition, an ordering, or a log line is out of scope and should
  be a separate commit.
- The wasm clippy gate still runs, and `-D warnings` catches the mechanical
  slips.
- `tests/rehearsal/` against a live node is the end-to-end check before and
  after; a rehearsal run that behaves identically is the acceptance criterion.
- The extracted decision functions (`migrate_seal`, `migrate_gate`) already
  have tests, so the parts most likely to be *reasoned* about wrongly are
  pinned before the move starts.

The honest residual: nothing catches a subtle reordering of the effects
themselves until Stage 2's tests exist. That argues for keeping Stage 1 tiny
and reviewing it as a diff-by-inspection rather than trusting CI.

## Why it was deferred

Decided 2026-09-05: land the security fixes first, refactor under its own
review. The fixes were on a branch already carrying a long run of
security-sensitive commits, and doing both at once would have meant reviewing
a refactor and a set of fixes in the same pass, on code whose failures are
invisible. `finish-the-fix` says fix every cause of the bug you were asked
about; it does not say take every adjacent refactor into the same change.
