"""Fixture: taint sanitization should clear taint.

When scanned by dojigiri, the `process()` function should NOT produce a taint-flow
finding because `sanitized` passes through html.escape() — a configured sanitizer.
"""
import html


def process():
    user_input = input("Enter name: ")
    sanitized = html.escape(user_input)
    # This should be safe — sanitized is no longer tainted
    eval(sanitized)


def still_tainted():
    user_input = input("Enter cmd: ")
    # No sanitization — this SHOULD produce a taint-flow finding
    eval(user_input)
