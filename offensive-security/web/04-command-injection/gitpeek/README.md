# GitPeek

**Category:** web / command / argument injection (`git log --format`) · **Course:** Offensive Security (PoliTo)

## Challenge

A "browse this git repo" style tool that runs something like `sh -c "git log <input>"` server-side, where `<input>` is attacker-controlled and intended to be a commit ref or similar.

## Vulnerability

`git log` supports a `--format` flag that can embed **command substitution** in its pretty-print format string. Because the raw input is spliced into the shell command unsanitised, supplying a `--format=...` argument isn't filtered out as a flag injection, and the shell expands `$(...)` inside it before `git` even sees the string.

## Exploitation

```
main --format=$(printenv FLAG)
```

`main` keeps the command a valid git invocation (a real ref), while `--format=$(printenv FLAG)` gets expanded by the shell *before* `git log` runs — substituting the `FLAG` environment variable's value directly into the command line, which `git log` then happily prints back as the "commit format".

## Flag

`offsec{...redacted...}` — captured against the remote instance; redacted here per standard write-up etiquette.

## Note

Only the solution notes were preserved for this challenge (no app source retained).
