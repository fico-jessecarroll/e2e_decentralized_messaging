# Contributing

## License

This project is licensed under the **GNU Affero General Public License v3.0
(AGPLv3)** — see [`LICENSE`](./LICENSE). The license choice follows directly
from depending on [`libsignal`](https://github.com/signalapp/libsignal),
which is itself AGPLv3-licensed (see `PLAN.md` §10, "Key Risks & Open
Questions"). By submitting a contribution, you agree it is licensed under
AGPLv3 as part of this project.

### What AGPLv3 means for forks and downstream use

AGPLv3 is GPLv3 plus one additional obligation: the **network-use clause**
(AGPLv3 §13). Concretely, for everyone building on or operating this code:

- **Source availability is required even for network-only use.** GPLv3 only
  requires sharing source when you *distribute* a binary. AGPLv3 closes that
  gap: if you run a modified version of any component here — most notably
  the **relay** binary — and let other users interact with it over a
  network, you must offer those users the corresponding source, including
  your modifications. You cannot operate a closed-source fork of the relay
  as a hosted service.
- **No proprietary forks.** Any fork, derivative client, or redistributed
  build must also be AGPLv3 (or a license the FSF considers AGPLv3-compatible).
  Closed-source or proprietary forks of this codebase are not permitted.
- **Dependencies must stay license-compatible.** New dependencies added to
  `/core`, `/clients`, or `/relay` must be compatible with AGPLv3
  (permissive licenses such as MIT/Apache-2.0/BSD are fine; GPL-incompatible
  or more restrictive licenses are not). Flag any dependency whose license
  you are unsure about before adding it.

This is a deliberate trade-off, consistent with the project's stated goal of
being **open-source**: it guarantees that anyone who can reach a node or
relay operated under this project can also obtain its source, at the cost of
ruling out closed-source commercial forks.

### Known constraint: app-store distribution of the mobile clients

**Flag:** the iOS client cannot be assumed clear to ship through the Apple
App Store under AGPLv3 without further legal review. The FSF has long held
that the App Store's Terms of Service impose usage restrictions (notably
around redistribution and DRM) that conflict with GPL/AGPL §6's "no further
restrictions" requirement — the dispute that got VLC pulled from the App
Store in 2011. Practically:

- Other AGPL/GPL-licensed apps have shipped on the App Store since (Apple's
  enforcement has been inconsistent), but it is not a settled legal
  guarantee, and it is a risk specific to the **iOS** client — Android
  (Play Store), Desktop, Web, and the self-hosted relay do not have this
  constraint.
- This must be revisited before the iOS client (Phase 8) ships, e.g. by
  re-confirming current App Store policy, or by distributing the iOS app
  through a channel without this conflict (TestFlight/enterprise/sideload,
  or an organizational exception) if needed.
- This risk is tracked in `PLAN.md` §10 and should be re-validated, not
  assumed resolved, when Phase 8 (iOS) is scheduled.

## Development workflow

See `CLAUDE.md` for the mandatory engineering workflow (pipeline-driven
stories, TDD, commit standards, and review gates) that governs all
contributions to this repository.
