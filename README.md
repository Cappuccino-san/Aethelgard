# Project Aethelgard v1.0.0

Sovereign Cognitive Twin & Cryptographic Provenance Engine.

What is the significance?

Foundation models are going to get cheaper, better, and more interchangeable. They commoditize. What doesn't commoditize is your context: the decisions you made, why you made them, what you rejected, what you tried, what actually happened when you ran it.

Right now that context is scattered and fragile. It's in chat histories that reset, in markdown notes you forget to update, in Git commits with no reason attached, in your head. A new model starts from zero, guesses at your past, and hallucinates it confidently.

Aethelgard is meant to fix that by keeping one local, verifiable record, and letting any model plug into it.

How that works, in purpose terms:

Ledger: a diary that can't be silently edited. Every decision, note, commit, and file change gets hashed to the previous one, so if someone edits the middle, verify fails. Now signed with your persistent Ed25519 key, so new events are signed, not just hashed.

Airlock: secrets are scrubbed before anything is stored, so your memory doesn't become a leak.
Views: the same ledger is indexed three ways, so recall actually works. FTS5 finds exact words, sqlite-vec with Ollama finds meaning even if you phrase it differently, and KùzuDB finds relationships and timelines, like what superseded what, and what involved which project.

RRF: those three are combined, with old superseded decisions penalized, so you get the current answer, not a dead one.

MCP: that's the plug. Antigravity today, any other agent tomorrow, can call recall_context, commit_decision, trace_entity_history, log_execution_artifact, and verify_provenance, all from the same local store. You're not locked to one vendor's memory.

Hook and daemon: passive capture, so you don't have to remember to log. A git commit becomes a git_commit event automatically, a file change becomes a file_change event, without you writing a note.

A concrete example:

In 2026 you decide to use persistent signing over unsigned events, and you reject plain markdown notes. In 2029 you ask a totally different model, "why do we sign events?" It shouldn't guess. It should recall that exact decision, show you the rejected alternatives, show you that ADR-003 superseded the earlier unsigned approach, and show you verify still passes for that chain.

That's the compounding part. Every year you use it, the record gets more useful, not more stale, and it stays yours, local, offline-first, not in someone else's cloud, not lost when a platform changes pricing or shuts down.

What it is not, honestly:

It's tamper-evident, not tamper-proof. If someone has both your ledger and your key on the same machine, they could rewrite and re-sign. It doesn't prove who you are to the outside world, and its timestamps are local, not trusted time. That's why the backups matter, and why verify is about detecting middle edits, not claiming absolute proof.

In short: models will come and go. Aethelgard is the part that stays, remembers, and can prove what it remembers.
This is the Gemini-built v1 code, packaged unchanged for Antigravity.

## Open in Antigravity

1. Download the zip and extract it with your operating system (right-click, Extract, or double-click on Mac). Do not run unzip commands in a chat window, those only work in a terminal.
2. In Antigravity, choose Open Folder, then select the extracted `aethelgard` folder.
3. Open a terminal inside Antigravity (Terminal menu, New Terminal) and run the commands below from inside that folder.

## Run the tests

```bash
python3 -m venv .venv
.venv/bin/pip install blake3 cryptography pytest
PYTHONPATH=src .venv/bin/pytest -v
```

On Windows, use `.venv\Scripts\activate` instead of `.venv/bin/`, then `python -m pytest` with `PYTHONPATH=src` set in the same way for your shell.

## Use the CLI

After installing the package, or with PYTHONPATH set:

```bash
twin commit --title "Use SQLite WAL" --context "Local durability" --decision "SQLite 3 in WAL mode"
twin note "First note"
twin rebuild-views
twin verify
```

Default ledger location is `~/.local/share/aethelgard/ledger.db`. Use `--db <path>` to use a different database file.

## Layout

- `src/aethelgard/airlock.py` - secret scrubber
- `src/aethelgard/canonical.py` - RFC 8785 canonical JSON
- `src/aethelgard/ledger.py` - BLAKE3 chain, Ed25519, SQLite WAL ledger
- `src/aethelgard/views.py` - decoupled FTS5 view, rebuildable from the ledger
- `src/aethelgard/cli.py` - `twin` CLI
- `tests/test_aethelgard.py` - 5 tests
