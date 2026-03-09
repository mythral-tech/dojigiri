# Deserialization Gadget Chain

**CWE-502** | Deserialization of Untrusted Data

## Vulnerability

`EntryPoint` deserializes HTTP request body via `ObjectInputStream.readObject()`. The classpath contains `CacheEntry`, which has a custom `readObject()` that calls `Runtime.exec()`, and `TransformProxy`, an `InvocationHandler` that can trigger arbitrary method calls during deserialization. Together they form a simplified gadget chain: deserialize proxy -> invoke handler -> trigger CacheEntry.readObject() -> RCE.

## Why Semgrep Misses It

Semgrep flags `ObjectInputStream.readObject()` on untrusted input (the entry point). But that's only half the story. The actual severity depends on what's on the classpath — the gadget chain. Semgrep has no concept of "reachable gadgets" or deserialization chain analysis. It can't determine that `CacheEntry.readObject()` calls `Runtime.exec()` and is reachable through the `TransformProxy` invocation handler. A proper SAST tool should trace the chain: entry point -> available Serializable classes -> custom readObject/readResolve -> dangerous sinks.

## Attack

Craft a serialized `TransformProxy` wrapping a `CacheEntry("calc.exe")` and POST it to the servlet.
