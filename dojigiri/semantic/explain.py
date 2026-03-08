"""Tutorial mode: generate beginner-friendly explanations of code files.

`doji explain <file>` generates file summaries, structure breakdowns, design
pattern recognition, finding explanations in plain language, and learning notes.
Two modes: offline (default, structural + heuristic) and deep (LLM-powered).

Called by: mcp_server.py, __main__.py, mcp_format.py
Calls into: semantic/core.py, semantic/types.py, config.py, compliance.py
Data in → Data out: (source content, filepath, language) → FileExplanation
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from ..types import Finding
from .core import FileSemantics, FunctionDef, ClassDef
from .types import FileTypeMap


# ─── Data structures ─────────────────────────────────────────────────

@dataclass
class ExplainSection:
    title: str
    content: str
    code_snippet: Optional[str] = None


@dataclass
class FileExplanation:
    filepath: str
    language: str
    summary: str
    structure: list[ExplainSection] = field(default_factory=list)
    patterns: list[ExplainSection] = field(default_factory=list)
    findings_explained: list[ExplainSection] = field(default_factory=list)
    learning_notes: list[str] = field(default_factory=list)


# ─── Finding explanation templates ───────────────────────────────────

_FINDING_EXPLANATIONS: dict[str, str] = {
    "taint-flow": (
        "Data from user input reaches a dangerous function without being cleaned first. "
        "Think of accepting a package from a stranger without checking inside — it might "
        "contain something harmful. Always validate and sanitize user input before using it "
        "in sensitive operations like database queries or system commands."
    ),
    "resource-leak": (
        "A resource (like a file or network connection) is opened but never properly closed. "
        "Imagine leaving water taps running — eventually you'll run out of water (or memory). "
        "Always close resources when you're done, or use a context manager ('with' statement) "
        "that handles cleanup automatically."
    ),
    "null-dereference": (
        "Code tries to use a value that might be None/null — like trying to open a door "
        "that might not exist. This will crash your program. Always check if a value is "
        "None before using it, especially with values from functions that might not find "
        "what they're looking for."
    ),
    "unused-variable": (
        "A variable is created but never used — like buying groceries you never cook. "
        "This suggests either dead code that should be cleaned up, or a bug where "
        "you meant to use the variable but forgot."
    ),
    "unused-import": (
        "A module is imported but never used in this file. This adds unnecessary overhead "
        "and makes the code harder to read. Remove it to keep things clean."
    ),
    "possibly-uninitialized": (
        "A variable might be used before it has a value — like trying to read a page "
        "from a book that hasn't been written yet. Make sure every variable has a value "
        "before you try to use it."
    ),
    "variable-shadowing": (
        "A variable name is reused in an inner scope, hiding the outer variable — like "
        "having two people with the same name in a room. It's confusing and can lead to "
        "bugs. Use a different name to avoid confusion."
    ),
    "god-class": (
        "This class is doing too many things — like a restaurant that's also a gym, "
        "a library, and a car wash. Classes should have one clear responsibility. "
        "Consider splitting it into smaller, focused classes."
    ),
    "feature-envy": (
        "This method uses another object's data more than its own — like a worker who "
        "spends more time at someone else's desk. Consider moving this method to the "
        "class whose data it uses most."
    ),
    "long-method": (
        "This function is very long, making it hard to understand and maintain. "
        "Like a single-paragraph essay that covers 10 topics — break it into "
        "smaller functions, each doing one thing well."
    ),
    "exception-swallowed": (
        "An error is caught but silently ignored (except: pass). This hides problems — "
        "like unplugging a smoke detector. At minimum, log the error so you can see "
        "when things go wrong."
    ),
    "mutable-default": (
        "A mutable object (list, dict) is used as a default argument. In Python, "
        "default arguments are shared across all calls, so modifications persist "
        "between calls. Use None as default and create the object inside the function."
    ),
    "shadowed-builtin": (
        "A variable name shadows a Python builtin like 'list' or 'dict'. This means "
        "you can no longer use the builtin in this scope. Use a different name."
    ),
    "hardcoded-secret": (
        "A password, API key, or secret is written directly in the code. Anyone who "
        "can read the code can see it. Use environment variables or a secrets manager "
        "instead."
    ),
    "near-duplicate": (
        "Two functions have very similar structure — they probably do almost the same "
        "thing. Consider combining them into one function with a parameter for the "
        "differences (DRY principle — Don't Repeat Yourself)."
    ),
    "semantic-clone": (
        "Two functions have very similar behavior patterns even though they may look "
        "different on the surface. This is a deeper form of code duplication that "
        "suggests a shared abstraction waiting to be extracted."
    ),
    "high-complexity": (
        "This function has many branches (if/else/for/while), making it hard to "
        "follow all possible paths. High complexity means more bugs and harder testing. "
        "Simplify by extracting parts into helper functions."
    ),
    "unreachable-code": (
        "Code appears after a return/break/continue statement, so it will never run. "
        "This is dead code — either remove it or restructure the control flow."
    ),
    "syntax-error": (
        "The code has a syntax error — it's not valid Python/JavaScript/etc. "
        "Fix the error before the code can run."
    ),
}

# Default explanation for unknown rules
_DEFAULT_EXPLANATION = (
    "The static analyzer flagged a potential issue here. Review the message "
    "and suggestion for details on what to fix."
)


# ─── Pattern recognition ────────────────────────────────────────────

_PATTERN_DESCRIPTIONS: dict[str, tuple[str, str]] = {
    "factory": (
        "Factory Pattern",
        "A function that creates and returns different objects based on input. "
        "This centralizes object creation logic and makes it easy to add new types.",
    ),
    "singleton": (
        "Singleton Pattern",
        "A class designed so only one instance can exist. Often used for "
        "configuration, logging, or shared resources.",
    ),
    "decorator": (
        "Decorator Pattern",
        "A function that wraps another function to add behavior (like logging "
        "or authentication) without modifying the original function.",
    ),
    "builder": (
        "Builder Pattern",
        "A pattern where an object is constructed step-by-step through method "
        "calls, allowing complex configuration in a readable way.",
    ),
    "observer": (
        "Observer Pattern",
        "A publish-subscribe mechanism where objects register to be notified "
        "when something changes. Common in event-driven systems.",
    ),
    "iterator": (
        "Iterator Pattern",
        "A way to access elements of a collection one at a time without "
        "exposing the underlying structure. Python's for loops use this.",
    ),
}


def _detect_patterns(
    semantics: FileSemantics,
    lines: list[str],
) -> list[ExplainSection]:
    """Detect common design patterns using heuristic analysis."""
    patterns = []

    # Factory: function that returns different types based on condition
    for fdef in semantics.function_defs:
        if any(kw in fdef.name.lower() for kw in ("create", "make", "build", "factory", "get_instance")):
            # Count different return values
            returns_in_func = sum(
                1 for i in range(fdef.line - 1, min(fdef.end_line, len(lines)))
                if lines[i].strip().startswith("return ")
            )
            if returns_in_func >= 2:
                name, desc = _PATTERN_DESCRIPTIONS["factory"]
                patterns.append(ExplainSection(
                    title=name,
                    content=f"Function '{fdef.name}' appears to be a factory. {desc}",
                ))

    # Singleton: class with __new__ or _instance pattern
    for cdef in semantics.class_defs:
        class_lines = [
            lines[i] for i in range(cdef.line - 1, min(cdef.end_line, len(lines)))
        ]
        class_text = "\n".join(class_lines)
        if "_instance" in class_text or "__new__" in class_text:
            name, desc = _PATTERN_DESCRIPTIONS["singleton"]
            patterns.append(ExplainSection(
                title=name,
                content=f"Class '{cdef.name}' appears to be a singleton. {desc}",
            ))

    # Decorator: function that takes a function and returns a function
    for fdef in semantics.function_defs:
        if fdef.name.startswith("_"):
            continue
        # Check if it returns a nested function
        func_lines = [
            lines[i].strip() for i in range(fdef.line - 1, min(fdef.end_line, len(lines)))
        ]
        func_text = " ".join(func_lines)
        if ("def wrapper" in func_text or "def inner" in func_text or
                "def decorated" in func_text):
            name, desc = _PATTERN_DESCRIPTIONS["decorator"]
            patterns.append(ExplainSection(
                title=name,
                content=f"Function '{fdef.name}' appears to be a decorator. {desc}",
            ))

    # Builder: class with method chaining (returns self)
    for cdef in semantics.class_defs:
        return_self_count = 0
        for i in range(cdef.line - 1, min(cdef.end_line, len(lines))):
            if lines[i].strip() == "return self":
                return_self_count += 1
        if return_self_count >= 3:
            name, desc = _PATTERN_DESCRIPTIONS["builder"]
            patterns.append(ExplainSection(
                title=name,
                content=f"Class '{cdef.name}' appears to use the builder pattern. {desc}",
            ))

    # Observer: class with subscribe/register/on_ methods
    for cdef in semantics.class_defs:
        observer_methods = sum(
            1 for fd in semantics.function_defs
            if fd.parent_class == cdef.name and
            any(kw in fd.name.lower() for kw in ("subscribe", "register", "on_", "emit", "notify", "publish"))
        )
        if observer_methods >= 2:
            name, desc = _PATTERN_DESCRIPTIONS["observer"]
            patterns.append(ExplainSection(
                title=name,
                content=f"Class '{cdef.name}' appears to use the observer pattern. {desc}",
            ))

    # Iterator: class with __iter__ and __next__
    for cdef in semantics.class_defs:
        has_iter = any(
            fd.name in ("__iter__", "__next__")
            for fd in semantics.function_defs
            if fd.parent_class == cdef.name
        )
        if has_iter:
            name, desc = _PATTERN_DESCRIPTIONS["iterator"]
            patterns.append(ExplainSection(
                title=name,
                content=f"Class '{cdef.name}' implements the iterator pattern. {desc}",
            ))

    return patterns


# ─── Structure extraction ───────────────────────────────────────────

def _explain_function(fdef: FunctionDef, lines: list[str]) -> ExplainSection:
    """Generate an explanation for a function."""
    length = fdef.end_line - fdef.line + 1

    # Get the signature line
    sig_line = lines[fdef.line - 1].strip() if fdef.line - 1 < len(lines) else ""

    # Build description
    parts = []
    if fdef.parent_class:
        parts.append(f"Method of class '{fdef.parent_class}'.")
    else:
        parts.append("Standalone function.")

    parts.append(f"Takes {len(fdef.params)} parameter(s): {', '.join(fdef.params) if fdef.params else 'none'}.")
    parts.append(f"Spans {length} lines ({fdef.line}-{fdef.end_line}).")

    if fdef.has_varargs:
        parts.append("Accepts variable arguments (*args/**kwargs or ...rest).")

    # Try to infer purpose from name
    name_lower = fdef.name.lower()
    if name_lower.startswith("get") or name_lower.startswith("fetch"):
        parts.append("Appears to retrieve/return data.")
    elif name_lower.startswith("set") or name_lower.startswith("update"):
        parts.append("Appears to modify/update data.")
    elif name_lower.startswith("is_") or name_lower.startswith("has_") or name_lower.startswith("can_"):
        parts.append("Appears to check a condition (returns boolean).")
    elif name_lower.startswith("__"):
        parts.append("Special/magic method (part of Python's data model).")
    elif name_lower.startswith("_"):
        parts.append("Private/internal method (not meant to be called from outside).")
    elif name_lower.startswith("test"):
        parts.append("Appears to be a test function.")

    return ExplainSection(
        title=f"{'Method' if fdef.parent_class else 'Function'}: {fdef.qualified_name}",
        content=" ".join(parts),
        code_snippet=sig_line,
    )


def _explain_class(cdef: ClassDef, semantics: FileSemantics, lines: list[str]) -> ExplainSection:
    """Generate an explanation for a class."""
    length = cdef.end_line - cdef.line + 1

    parts = [
        f"Class with {cdef.method_count} method(s) and "
        f"{len(cdef.attribute_names)} attribute(s).",
        f"Spans {length} lines ({cdef.line}-{cdef.end_line}).",
    ]

    if cdef.attribute_names:
        parts.append(f"Attributes: {', '.join(cdef.attribute_names[:10])}")

    # Get class signature line
    sig_line = lines[cdef.line - 1].strip() if cdef.line - 1 < len(lines) else ""

    return ExplainSection(
        title=f"Class: {cdef.name}",
        content=" ".join(parts),
        code_snippet=sig_line,
    )


# ─── Learning notes ─────────────────────────────────────────────────

def _generate_learning_notes(
    semantics: FileSemantics,
    content: str,
    language: str,
    lines: list[str],
) -> list[str]:
    """Generate learning notes based on what the code demonstrates."""
    notes = []

    # Check for common learning opportunities
    if any(fd.name.startswith("__") and fd.name.endswith("__") for fd in semantics.function_defs):
        notes.append(
            "This code uses Python 'dunder' (double underscore) methods — "
            "special methods that let classes work with Python operators and builtins "
            "(e.g., __init__ for construction, __str__ for string representation)."
        )

    if any(a.value_text.strip().startswith("[") for a in semantics.assignments if not a.is_parameter):
        notes.append(
            "Uses list comprehensions or list literals — a concise way to create lists "
            "that's often more readable than building lists with loops."
        )

    if "lambda" in content:
        notes.append(
            "Uses lambda functions — small anonymous functions defined in a single line. "
            "Good for short operations passed to functions like map(), filter(), or sorted()."
        )

    if "yield" in content:
        notes.append(
            "Uses generators (yield keyword) — a memory-efficient way to produce items "
            "one at a time instead of creating an entire list in memory."
        )

    if any(fd.parent_class for fd in semantics.function_defs):
        notes.append(
            "Demonstrates object-oriented programming (OOP) — organizing code into "
            "classes that bundle data (attributes) with behavior (methods)."
        )

    if language == "python" and "with " in content:
        notes.append(
            "Uses 'with' statements (context managers) — a safe way to handle resources "
            "like files that need to be cleaned up, even if errors occur."
        )

    if "async " in content or "await " in content:
        notes.append(
            "Uses async/await for asynchronous programming — a way to write code that "
            "can handle multiple tasks concurrently without blocking."
        )

    if any("@" in line and not line.strip().startswith("#") for line in lines):
        notes.append(
            "Uses decorators (@decorator_name) — a way to modify or enhance functions "
            "without changing their code. Common for logging, authentication, caching."
        )

    return notes


# ─── Main entry point ───────────────────────────────────────────────

def explain_file(
    content: str,
    filepath: str,
    language: str,
    semantics: Optional[FileSemantics] = None,
    findings: Optional[list[Finding]] = None,
    type_map: Optional[FileTypeMap] = None,
) -> FileExplanation:
    """Generate a beginner-friendly explanation of a code file.

    This is the offline mode — uses structural analysis, heuristic pattern
    recognition, and finding explanation templates. No LLM required.

    Args:
        content: File content.
        filepath: File path.
        language: Programming language.
        semantics: Pre-extracted semantics (optional — will extract if None).
        findings: Static analysis findings (optional).
        type_map: Type inference results (optional).

    Returns:
        FileExplanation with sections for structure, patterns, findings, and learning.
    """
    # Extract semantics if not provided
    if semantics is None:
        from .core import extract_semantics
        semantics = extract_semantics(content, filepath, language)

    lines = content.splitlines()

    # Build summary
    summary_parts = [f"A {language} file with {len(lines)} lines."]
    if semantics:
        func_count = len(semantics.function_defs)
        class_count = len(semantics.class_defs)
        if class_count:
            summary_parts.append(f"Contains {class_count} class(es) and {func_count} function(s).")
        elif func_count:
            summary_parts.append(f"Contains {func_count} function(s).")
        else:
            summary_parts.append("Appears to be a script or configuration file.")
    summary = " ".join(summary_parts)

    explanation = FileExplanation(
        filepath=filepath,
        language=language,
        summary=summary,
    )

    if semantics is None:
        explanation.learning_notes.append(
            f"This is a {language} file. Install tree-sitter for deeper analysis."
        )
        return explanation

    # Structure: explain each class and function
    for cdef in semantics.class_defs:
        explanation.structure.append(_explain_class(cdef, semantics, lines))

    for fdef in semantics.function_defs:
        explanation.structure.append(_explain_function(fdef, lines))

    # Pattern recognition
    explanation.patterns = _detect_patterns(semantics, lines)

    # Explain findings in beginner-friendly language
    if findings:
        seen_rules = set()
        for f in findings:
            if f.rule in seen_rules:
                continue
            seen_rules.add(f.rule)

            beginner_text = _FINDING_EXPLANATIONS.get(f.rule, _DEFAULT_EXPLANATION)

            explanation.findings_explained.append(ExplainSection(
                title=f"Issue: {f.rule} (line {f.line})",
                content=f"{beginner_text}\n\nSpecific: {f.message}",
                code_snippet=f.snippet,
            ))

    # Learning notes
    explanation.learning_notes = _generate_learning_notes(semantics, content, language, lines)

    return explanation
