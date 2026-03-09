# Pickle Deserialization via Redis

**CWE-502** | Deserialization of Untrusted Data

## Vulnerability

`cache_store.py` pickles user-supplied JSON and stores it in Redis. `cache_load.py` reads from Redis and calls `pickle.loads()` on the raw bytes. An attacker who controls the Redis key (via the store endpoint or direct Redis access) can inject a malicious pickle payload that executes arbitrary code on deserialization.

## Why Semgrep Misses It

Two barriers: (1) the data crosses a persistence boundary (Redis) between files, and (2) Semgrep doesn't model Redis `get`/`set` as a taint passthrough. Even with inter-file analysis, the serialization-store-retrieve-deserialization chain through an external data store is outside Semgrep's taint model. Semgrep would flag `pickle.loads()` on direct `request` data but not on data retrieved from Redis.

## Attack

1. POST crafted pickle payload as JSON to `/settings`
2. Or: directly write malicious pickle bytes to `user:{id}:prefs` key
3. GET `/settings?user_id={id}` triggers `pickle.loads()` on attacker-controlled bytes
