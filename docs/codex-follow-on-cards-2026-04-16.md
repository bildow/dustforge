# Codex Follow-On Cards — 2026-04-16

These are the larger items raised after wake-up that should be handled as separate cards rather than one blended pass.

## Card 1 — Brain onboarding audit

Goal:
- verify whether Brain onboarding actually works as intended

Questions:
- did fingerprinting work in practice during Brain onboarding
- could Brain actually store and use a Blindkey/secret safely
- is the resonance score meaningful enough to be shown or relied on

Deliverables:
- code + live-path audit
- confirmed working / not working matrix
- recommended fixes or de-scoping

## Card 2 — Capacity cap and waitlist

Goal:
- define a safe activation cap for this phase and enforce it before growth outruns the backend

Questions:
- how many accounts can Dustforge onboard and serve in current phase without operator pain or backend instability
- where are the true choke points: Stalwart provisioning, Stripe fulfillment, SQLite write pressure, email relay, per-call billing, rate limiting
- what number becomes the hard activation threshold for a waitlist

Deliverables:
- stress-test estimate and operating cap
- waitlist policy
- implementation plan for activation freeze / waitlist mode
- founding-tier pricing update proposal:
  - `$20` package temporarily becomes `30` keys for first `100` purchases
  - `$100` partnership package becomes `$88` and includes beta key for Whisper Hook + Sightless on release

## Card 3 — security research / zero-day awards program

Goal:
- define the deeper security posture and a public-facing reporting/reward framework

Questions:
- what exploit surfaces still deserve focused audit after P0
- how should zero days be reported, verified, rewarded, and publicly credited
- what boundaries define allowed research vs prohibited abuse

Deliverables:
- deeper security audit scope
- vulnerability disclosure policy
- awards page requirements
- optional hall-of-fame / public recognition policy
