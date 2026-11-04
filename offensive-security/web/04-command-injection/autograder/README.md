# Autograder

**Category:** web / Python sandbox escape (class-hierarchy gadget) · **Course:** Offensive Security (PoliTo)

## Challenge

A "submit your `fibonacci(n)` implementation" grader that executes user-submitted Python inside some kind of restricted sandbox — not a shell, but a Python execution context with `open`/`import`/file access presumably blocked or unavailable directly.

## Vulnerability

Classic **Python sandbox escape via the class hierarchy**: even with `open`, `__import__`, and other obvious builtins locked down, every Python object still exposes `__class__`, and from there `__base__.__subclasses__()` walks every class currently loaded in the interpreter — including ones that provide file I/O, reachable without ever calling a blacklisted name directly.

## Exploitation

Submitted "solution" that never actually computes Fibonacci — it walks the subclass tree to find a file I/O class and uses it to read `/flag.txt` directly:

```python
def fibonacci(n):
    f = ().__class__.__base__.__subclasses__()[114].__subclasses__()[1].__subclasses__()[0]("/flag.txt")
    return list(f)
```

Traced manually: `().__class__.__base__` is `object`; `object.__subclasses__()[114]` lands on `_io._IOBase`, whose own subclasses include `_io._RawIOBase`, whose subclass is `_io.FileIO` — a class that can be instantiated directly with a filename to open it, entirely bypassing a builtins/keyword blacklist that never accounted for reaching file I/O through the class graph instead of `open()`.

## Flag

`offsec{...redacted...}` — captured against the remote instance; redacted here per standard write-up etiquette.

## Note

Only the solution notes were preserved for this challenge (no app source retained). The exact subclass index (`114`) is environment-specific — it depends on which classes happen to be loaded in that Python interpreter and would need to be re-enumerated against a different environment/version.
