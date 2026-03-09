# Case 15: NoSQL Injection via MongoDB

**CWE:** CWE-943 (Improper Neutralization of Special Elements in Data Query Logic)

## Vulnerability

Both endpoints pass user-controlled values directly into MongoDB query objects. The `/api/login` endpoint is exploitable with:

```json
{"email": {"$gt": ""}, "password": {"$gt": ""}}
```

Express's `express.json()` middleware parses nested objects, so `req.body.email` becomes a MongoDB operator object instead of a string. This bypasses authentication by matching any user with email and password greater than empty string.

The `/api/users` endpoint is similarly vulnerable — `req.query.role` could contain a serialized operator via query string parsing.

## Why Semgrep Misses It

Semgrep's NoSQL injection rules primarily look for string interpolation in query strings or explicit `$where` usage. The pattern `db.collection("users").findOne({email: email})` looks like safe parameterized usage — there's no string concatenation or template literal. The vulnerability is semantic: Express parses JSON request bodies into arbitrary objects, and MongoDB interprets object-typed values as query operators.

Semgrep cannot reason about the runtime type of `req.body.email` — it sees a variable reference in a query field, which looks identical to safe usage with a string value.

## Detection Requirements

- Understanding that `req.body.*` fields from `express.json()` can be objects, not just strings
- MongoDB query operator injection modeling (object-typed values in query predicates)
- Type-aware taint analysis distinguishing `string` vs `object` flow into query fields
