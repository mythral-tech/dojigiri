# Case 12: Stored XSS via React dangerouslySetInnerHTML

**CWE:** CWE-79 (Improper Neutralization of Input During Web Page Generation)

## Vulnerability

User-submitted bio content is stored unsanitized in the database (`api.js`), then fetched and rendered via `dangerouslySetInnerHTML` in `Profile.jsx`. An attacker stores `<img src=x onerror=alert(document.cookie)>` as their bio, which executes in every visitor's browser.

## Why Semgrep Misses It

Semgrep detects `dangerouslySetInnerHTML` with direct user input in the same file, but this is a **cross-file stored XSS** pattern. The taint source (`req.body.bio`) is in `api.js`, stored to a database, retrieved via a separate API call, and rendered in `Profile.jsx`. Semgrep's single-file analysis cannot:

1. Track taint across the storage boundary (write → DB → read)
2. Connect the API response in React's `fetch()` back to the original user input
3. Correlate the backend endpoint with the frontend consumer

The `dangerouslySetInnerHTML` rule fires only when the value is visibly derived from props/state that came from user input within the same component — not from an opaque API response.

## Detection Requirements

- Cross-file taint tracking through database storage
- API endpoint modeling (POST stores, GET retrieves same data)
- Recognition that API response data in `dangerouslySetInnerHTML` is a stored XSS vector
