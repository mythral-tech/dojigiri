# Spring Expression Language Injection

**CWE-917** | Improper Neutralization of Special Elements Used in an Expression Language Statement

## Vulnerability

User input from `@RequestParam filter` flows through three files: `UserController` -> `UserFilterService.applyFilter()` -> `ExpressionEvaluator.evaluate()`. The filter string is concatenated into a SpEL expression and evaluated with `StandardEvaluationContext`, which allows arbitrary method calls including `Runtime.exec()`.

## Why Semgrep Misses It

The taint flows across three files through method calls: controller -> service -> evaluator. Semgrep's inter-procedural taint analysis has a depth limit and struggles with Spring's dependency injection pattern (`@Autowired` fields). The `SpelExpressionParser.parseExpression()` sink is two hops away from the source, with the tainted string being concatenated in the middle layer (`UserFilterService`), not at the source or sink. Semgrep's Pro engine can handle some cross-file flows but reliably misses 3-file chains with DI-injected intermediaries.

## Attack

```
GET /api/users/search?filter=T(java.lang.Runtime).getRuntime().exec('calc')
```
