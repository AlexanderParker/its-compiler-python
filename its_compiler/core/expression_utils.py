"""Utilities for conditional expression handling."""


def translate_condition_operators(expression: str) -> str:
    """Translate the specification's condition operators to Python equivalents.

    The ITS specification documents JavaScript-style operators (&&, || and
    unary !) in conditional expressions. Python's ast cannot parse them, so
    they are rewritten to and/or/not before parsing. Content inside string
    literals is left untouched, and != is preserved. The translation is
    idempotent: expressions already using Python operators pass through
    unchanged.
    """
    result = []
    i = 0
    quote = None

    while i < len(expression):
        ch = expression[i]

        if quote is not None:
            result.append(ch)
            if ch == quote:
                quote = None
            i += 1
            continue

        if ch in ("'", '"'):
            quote = ch
            result.append(ch)
            i += 1
            continue

        if expression.startswith("&&", i):
            result.append(" and ")
            i += 2
            continue

        if expression.startswith("||", i):
            result.append(" or ")
            i += 2
            continue

        if ch == "!" and not expression.startswith("!=", i):
            result.append(" not ")
            i += 1
            continue

        result.append(ch)
        i += 1

    return "".join(result).strip()
