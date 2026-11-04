# Triage Labels

The triage skills use five canonical state roles and two category roles. Every
triaged issue should have exactly one category label and one state label.

## State roles

| Canonical role | Tracker label | Meaning |
| --- | --- | --- |
| `needs-triage` | `needs-triage` | Maintainer needs to evaluate this issue |
| `needs-info` | `needs-info` | Waiting on the reporter for more information |
| `ready-for-agent` | `ready-for-agent` | Fully specified and ready for an AFK agent |
| `ready-for-human` | `ready-for-human` | Requires human implementation or review |
| `wontfix` | `wontfix` | Will not be actioned |

## Category roles

| Canonical role | Tracker label | Meaning |
| --- | --- | --- |
| `bug` | `bug` | Something is broken |
| `enhancement` | `enhancement` | A new feature or improvement |

When a skill mentions a canonical role, use the corresponding tracker label.
