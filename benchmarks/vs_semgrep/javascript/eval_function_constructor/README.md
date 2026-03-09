# Case 13: Code Injection via Function Constructor

**CWE:** CWE-94 (Improper Control of Generation of Code)

## Vulnerability

Two endpoints use `new Function()` with user-controlled strings. The `Function` constructor is functionally equivalent to `eval()` — it compiles and executes arbitrary JavaScript. An attacker sends:

```json
{"expression": "process.mainModule.require('child_process').execSync('id').toString()"}
```

This achieves full RCE through the calculator endpoint.

## Why Semgrep Misses It

Semgrep's JavaScript eval rules target `eval()`, `setTimeout(string)`, and `setInterval(string)`. The `Function` constructor is a less common code execution sink that most rulesets don't cover comprehensively. While some community rules match `new Function(...)`, they typically look for direct `new Function(userInput)` patterns. The string concatenation `"return " + expression` creates an intermediate value that breaks simple pattern matching.

The `/api/transform` endpoint is even harder — the user-controlled `code` parameter is passed as the function body argument, which is the second positional argument to `Function()`, making positional pattern matching unreliable.

## Detection Requirements

- `new Function()` modeled as a code execution sink equivalent to `eval()`
- Taint tracking through string concatenation into constructor arguments
- Recognition that any positional argument to `Function()` containing user input is dangerous
