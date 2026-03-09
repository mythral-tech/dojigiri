# XXE via Cross-File Parser Configuration

**CWE-611** | Improper Restriction of XML External Entity Reference

## Vulnerability

`XmlParserFactory.createParser()` returns a `SAXParser` without disabling external entities or DTD processing. `ImportHandler` uses this factory to parse user-uploaded XML, enabling XXE attacks for file disclosure, SSRF, or denial of service.

## Why Semgrep Misses It

Semgrep's XXE rules look for `SAXParserFactory.newInstance()` + `newSAXParser()` without `setFeature()` calls — but in the same method or file. Here, the insecure configuration is in `XmlParserFactory.createParser()` and the user input parsing is in `ImportHandler.importXml()`. Semgrep analyzes each file independently and sees: (1) a factory that returns a parser (no user input — no flag), and (2) a handler that calls `parser.parse(file.getInputStream(), ...)` on a parser returned from a method call (no visible misconfiguration — no flag). The vulnerability only exists when you connect the dots across files.

## Attack

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root><record>&xxe;</record></root>
```
