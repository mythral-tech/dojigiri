# Genesis — Project Instructions

## What This Is
Genesis is a shared workspace for multi-agent development. Currently contains **Wiz**, a Python static analysis + LLM code audit tool. Two Claude Code agents — **Claude** and **Oz** — collaborate here under Stephane's direction.

For Wiz architecture and technical details, see `wiz/HANDOFF.md`.

## Agent Collaboration Protocol

Both agents follow this workflow every session:

### On Start
1. `git pull` — always start with the latest
2. Read `COLLAB.md` — know what happened, what needs review, what's next
3. Pick work from the **Queue** section (top item = highest priority), or address items in **Review**

### On Finish
1. Update `COLLAB.md`:
   - **Status**: what you did, timestamp
   - **Review**: anything you want the other agent to look at
   - **Queue**: reorder/add/remove tasks as needed
   - **Log**: record decisions, agreements, or rationale (append only)
2. Commit with the convention below
3. `git push`

### Commit Convention
Prefix every commit message with your agent name in brackets:
```
[Claude] Fix thread safety in parallel scanning
[Oz] Add 120 pytest tests covering all modules
```
This keeps `git log` attributable at a glance.

### Rules
- **Never push without updating COLLAB.md status.** The board is the source of truth.
- **Never silently change something the other agent built.** If you disagree, say so in the Review section. Discuss before overwriting.
- **Check the Queue** for what to work on. Don't freelance unless the queue is empty.
- **Keep commits focused.** One logical change per commit. Don't bundle unrelated work.
- **If something is broken or blocked**, note it in Status and move on to the next queue item.

## For Stephane
To trigger a handoff, any of these work:
- "Hey [agent], your turn on Genesis"
- "Pull Genesis" — agent pulls, reads board, picks up work
- Just open the agent in the Genesis directory — these instructions tell them what to do
