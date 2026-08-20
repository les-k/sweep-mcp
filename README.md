# sweep-mcp

[![CI](https://github.com/les-k/sweep-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/les-k/sweep-mcp/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.11%20%E2%80%93%203.13-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

> **In plain terms:** this lets an AI clear out the junk folders that pile up
> on a developer's machine, and makes it incapable of touching anything else. It
> works only inside folders you name, only deletes things it found itself, and
> checks again in the instant before deleting — so nothing can be swapped in at
> the last second.

An MCP server that deletes directories — and the guard rails that make handing
that capability to a language model something other than reckless.

It exposes [`sweep`](https://github.com/les-k/sweep) over the Model Context
Protocol, so an agent can find and reclaim `node_modules`, `.venv`, `target`,
`__pycache__` and friends. The interesting part is not the deleting. It is
everything that has to be true before a delete is allowed to happen.

Research published in 2026 found security issues in **66% of 1,808 scanned MCP
servers**, with 30+ CVEs filed against MCP implementations in a single quarter.
This repository is one server written the other way round: the refusals first,
the feature second.

---

## The threat model

An MCP server that can delete directories is a loaded gun pointed at whatever
the process can reach. Five things could go wrong, and each has a control and a
test that makes it fire.

| Risk | Control | Test |
|---|---|---|
| Agent scans `/` or `C:\` and deletes the machine | **Root allowlist**, fixed at server start. The agent cannot set, extend or read past it. No roots configured → every request refused | `test_empty_allowlist_denies_every_path` |
| `../../` or a symlink used to escape the allowlist | Every path is `resolve()`d **before** the containment check, so it is judged on where it really points | `test_dotdot_traversal_is_denied`, `test_symlink_pointing_outside_root_is_denied` |
| Agent asks to delete a path it never scanned | **`reclaim` accepts ids, not paths.** There is no path-shaped route to deletion anywhere in the API | `test_there_is_no_way_to_delete_by_path` |
| The directory changes between scan and delete | Every find is **re-checked against the live filesystem** at deletion time — still contained, still a directory, still not a link, marker file still present | `test_revalidate_refuses_a_directory_swapped_for_a_symlink` |
| Accidental destruction | **Dry run is the default.** Deletion requires `confirm="delete"` exactly; anything else is treated as no | `test_a_wrong_confirmation_string_stays_a_dry_run` |

Two smaller ones, for the same reason:

- **Ticket ids are random, not sequential.** `f-3a91c02b77de`, not `1`. A
  counting id invites an agent to iterate until something deletes.
- **Tool descriptions are string literals.** They are never assembled from
  anything read off disk, so a directory named `ignore-previous-instructions`
  reaches the model as data rather than as a sentence
  (`test_tool_descriptions_are_static`).

## What it does *not* protect against

The controls above are worth exactly what they cover, and no more.

- **A misconfigured root.** Start it with `--root /` and it will happily work
  through your filesystem. The allowlist is only as good as what you put in it,
  and nothing here second-guesses that choice.
- **A malicious client.** The guard constrains *what* may be deleted, never
  *who* is asking. A client that scans legitimately and then confirms
  legitimately gets exactly what it asked for.
- **An agent that has been talked into it.** Static tool descriptions keep
  filesystem content out of the model's instructions, but nothing here can stop
  an agent that decides, for its own bad reasons, to delete a real
  `node_modules` it genuinely found.
- **The last few milliseconds.** `revalidate()` narrows the window between check
  and delete; it does not close it. Closing it properly needs directory file
  descriptors held across the operation, which `shutil.rmtree` does not offer
  portably. **This is a real race, and it is smaller, not absent.**
- **Windows junctions on Python 3.11.** `os.path.isjunction` arrived in 3.12.
  Below that, junction detection degrades to symlinks only — the same compromise
  `sweep` itself makes, stated here rather than buried.
- **Privilege.** This is not a sandbox. It runs as whoever started it.

## Scanner results

Run against [`agent-audit`](https://pypi.org/project/agent-audit/) 0.19.2 on
18 August 2026.

**Static scan — 0 findings, risk score 0.0 (LOW), 7 files.**

One low finding appeared on the first pass: `AGENT-110`, source-map artifacts not
excluded from distribution. This package ships no JavaScript, so there were no
source maps to leak, but the exclusion is now declared in `pyproject.toml`
anyway — it costs nothing, and arguing with a supply-chain checklist is a poor
use of anyone's afternoon.

**Tool inspection — 0 tool findings.** No tool-poisoning, cross-origin or
rug-pull patterns detected in any of the three definitions.

The risk ratings it assigned are worth reproducing, because they are wrong in an
instructive way:

| Tool | Rated | Inferred permissions |
|---|---|---|
| `list_targets` | MEDIUM | SHELL_EXEC, FILE_READ |
| `scan` | **HIGH** | **FILE_DELETE**, SHELL_EXEC, FILE_READ |
| `reclaim` | HIGH | FILE_DELETE, SHELL_EXEC, FILE_READ |

`scan` cannot delete anything. It is read-only, declared `read_only_hint=True`,
and there is a test asserting it stays that way. It was rated HIGH with a
`FILE_DELETE` permission because **the scanner matches keywords against the
description**, and this server's `scan` description contains the sentence:

> "Read-only: this never deletes anything."

The word *deletes* is on the `FILE_DELETE` keyword list. `SHELL_EXEC` comes from
the word *command*, in "the command that regenerates it" — this server never
executes a shell command at all.

The description could be reworded to score better. It has not been, because the
description's audience is a language model deciding whether to call the tool,
and "this never deletes anything" is the single most useful sentence in it. **A
keyword scanner is a smoke detector, not a judge** — a clean run is worth having
and worth publishing, and a rating derived from string matching on prose is not
evidence about behaviour in either direction.

Two scanners were tried and one could not be run: Invariant Labs' `mcp-scan` has
been renamed `snyk-agent-scan` following the Snyk acquisition and now requires a
`SNYK_TOKEN`. Cisco's `mcp-scanner` is not published to PyPI. `agent-audit`'s own
stdio transport also times out against this server on Windows while a hand-driven
handshake to the identical binary returns in milliseconds, so its analyser was
fed the real `tools/list` output directly — the transport was bypassed, the
analysis was not.

## Install

```bash
pip install -e .
```

## Configure

The server takes one or more `--root` directories. **It has no default.**
Starting it without a root is an error rather than an invitation to scan
everything:

```json
{
  "mcpServers": {
    "sweep": {
      "command": "sweep-mcp",
      "args": ["--root", "/home/you/code", "--root", "/home/you/work"]
    }
  }
}
```

## The tools

| Tool | Destructive | What it does |
|---|---|---|
| `list_targets` | no | The kinds of directory it knows how to reclaim, and the command that regenerates each |
| `scan` | no | Finds reclaimable directories under a path inside the roots. Returns ids, sizes, and the regenerate command |
| `reclaim` | **yes** | Deletes finds by id. Dry run unless `confirm="delete"` |

All three carry MCP `ToolAnnotations`, so a client that gates destructive tools
behind a confirmation prompt has what it needs: `reclaim` declares
`destructive_hint=True`, the other two declare `read_only_hint=True`. That is
asserted in the suite too — a hint that silently regressed would be worse than
none.

## A session

```
scan(path="/home/you/code")
  → 12 finds, 3.4 GB
    f-3a91c02b77de  /home/you/code/api/node_modules   1.9 GB  npm install
    f-8e0244fd1b6c  /home/you/code/ml/.venv           842 MB  python -m venv .venv

reclaim(ids=["f-3a91c02b77de"])
  → dry_run: true
    would_delete: 1 path, 1.9 GB
    note: Nothing was deleted. Call again with confirm='delete'.

reclaim(ids=["f-3a91c02b77de"], confirm="delete")
  → deleted: 1 path, reclaimed 1.9 GB
```

## Tests

**38 tests. 34 run on Windows; all 38 run on Linux.**

The four that skip locally need to create symlinks, which Windows refuses
without developer mode — and one of them covers the swap-between-scan-and-delete
attack, which is the single most important test here. Skipping it quietly would
make the suite a decoration, so **CI runs on Linux and fails the build if those
tests report as skipped there.**

```bash
pytest -q --cov=sweep_mcp
```

Coverage sits at **83%**. The gap is mostly `main()` and the argparse wiring,
which the suite drives through `build_server` instead — the transport is the
part least worth mocking and least likely to be where the damage comes from.

Nothing in the suite mocks the filesystem. A mocked `Path` would pass every test
in here while the server still deleted the wrong directory.

## Layout

```
src/sweep_mcp/
  guard.py    212 lines - the allowlist, the tickets, the re-check. Imports no MCP.
  server.py   280 lines - three tools. Translation only.
tests/
  test_guard.py    23 tests - one per rule, each named for the attack it stands in for
  test_server.py   15 tests - driven through call_tool, the way a client would
```

`guard.py` deliberately knows nothing about MCP. Every decision that could lose
someone their data is testable without a client, a transport or an agent in the
loop. If a rule looks like it is enforced in `server.py`, that is a bug — it
belongs one layer down, where the tests can reach it.

## Licence

MIT.
