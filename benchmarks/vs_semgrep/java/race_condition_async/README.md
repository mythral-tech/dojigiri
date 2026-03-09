# TOCTOU Race Condition in Async Handler

**CWE-367** | Time-of-Check Time-of-Use Race Condition

## Vulnerability

`processUpload` and `deleteUpload` are `@Async` Spring methods — they execute in separate threads from the thread pool. Both check file ownership with `isOwner()` then perform file operations. The `@Async` annotation means multiple calls run concurrently, creating a race window between the permission check and the file operation.

Attack scenarios:
- Thread A checks ownership of `report.pdf` (passes), Thread B replaces `report.pdf` with a symlink to `/etc/shadow`, Thread A overwrites the symlink target
- Thread A checks a file exists and is owned by attacker, Thread B deletes it and replaces it with a different user's file, Thread A deletes the wrong file

## Why Semgrep Misses It

Semgrep is fundamentally single-threaded in its analysis model. It has no concept of concurrent execution, thread interleaving, or race conditions. It cannot reason about:
1. `@Async` creating concurrent execution contexts
2. The time gap between `Files.exists()`/`isOwner()` and `Files.copy()`/`Files.delete()`
3. The non-atomicity of check-then-act patterns

TOCTOU requires temporal reasoning — understanding that state can change between two operations. This is outside the scope of pattern-matching or taint-tracking analysis.

## Attack

Send concurrent requests: one to upload a file, another to replace it with a symlink, exploiting the race window between the ownership check and the file write.
