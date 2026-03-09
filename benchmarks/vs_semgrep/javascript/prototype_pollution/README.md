# Case 11: Prototype Pollution via Deep Merge

**CWE:** CWE-1321 (Improperly Controlled Modification of Object Prototype Attributes)

## Vulnerability

User-controlled JSON from `req.body.preferences` is passed directly to `_.merge(config, userPrefs)`. An attacker sends:

```json
{"preferences": {"__proto__": {"isAdmin": true}}}
```

This pollutes `Object.prototype`, making `config.isAdmin` truthy for all subsequent requests.

## Why Semgrep Misses It

Semgrep rules for prototype pollution focus on direct property assignment patterns like `obj[key][nested] = value` or explicit `__proto__` access in code. The taint flows through a library call (`_.merge`) that performs the recursive assignment internally. Semgrep's pattern matching cannot follow taint into third-party function implementations — it sees `_.merge(config, userPrefs)` as an opaque call, not a prototype-polluting sink.

The lodash-specific rule `javascript.lang.security.audit.prototype-pollution.prototype-pollution-lodash` exists but only matches `_.defaultsDeep`, missing `_.merge`, `_.mergeWith`, and `_.set`.

## Detection Requirements

- Taint tracking from `req.body` through library call arguments
- Knowledge that `_.merge` performs recursive property assignment (sink modeling)
- Understanding that recursive merge on user input enables prototype pollution
