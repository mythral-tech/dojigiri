# Second-Order SQL Injection

**CWE-89** | SQL Injection

## Vulnerability

User-controlled input (`request.POST["username"]`) is stored safely via Django ORM in `views_store.py`. A separate view in `views_query.py` retrieves that stored value and interpolates it directly into a raw SQL query.

The injection payload never touches SQL in request A. It detonates in request B when the stored value is read back and used unsafely.

## Why Semgrep Misses It

Semgrep's taint analysis is intra-file and single-request scoped. It cannot track data that flows through a persistence layer (database write in file A, database read in file B). The taint source (`request.POST`) and the taint sink (`cursor.execute`) exist in different files with a database boundary between them. Semgrep has no model for "data stored now, used later."

## Attack

1. POST `username=' OR 1=1--` to `UpdateProfileView`
2. GET `ProfileSearchView` — the stored payload executes in the raw query
