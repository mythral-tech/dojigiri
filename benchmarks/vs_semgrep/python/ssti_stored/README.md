# Stored Server-Side Template Injection

**CWE-1336** | Improper Neutralization of Special Elements Used in a Template Engine

## Vulnerability

Users create email templates via POST with arbitrary Jinja2 syntax in `body` and `subject`. These are stored in the database. The preview endpoint retrieves the stored template and passes it to `jinja_env.from_string()`, which compiles and renders it. A standalone `jinja2.Environment()` (not Flask's sandboxed one) is used, enabling full RCE.

## Why Semgrep Misses It

The taint source is `request.json` in `create_template`, but the sink `jinja_env.from_string()` is in `preview_template` — a completely separate request handler. The data flows through SQLAlchemy ORM (write in handler A, read in handler B). Semgrep cannot track taint across database persistence boundaries or across separate HTTP request lifecycles. It would catch `jinja_env.from_string(request.json["body"])` directly, but not the stored variant.

## Attack

```json
POST /templates
{"name": "evil", "subject": "Hi", "body": "{{ ''.__class__.__mro__[1].__subclasses__() }}", "user_id": 1}
```
Then `GET /preview/1` executes the payload.
