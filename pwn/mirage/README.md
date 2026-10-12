# Mirage

**Category:** pwn · **Flag:** `isfcr{bl1nd_f0rmat_str1ng_h4s_n0_b1n4ry}`

## Challenge

> An echo that repeats back a little more than you said.

Authored by NotKnox. This was a pure black-box challenge: we were handed only a
network address (`nc 0.cloud.chals.io <port>`) — no binary, no source. The first
job was simply to talk to the service and figure out what kind of bug it had.

## Initial Analysis

Connecting gives a tiny prompt that behaves like a normal echo server:

```console
$ nc 0.cloud.chals.io 23023
> hello
hello
>
```

The description's hint about echoing "a little more" is the tell. Feeding it a
format specifier instead of plain text:

```console
> %p
0x48725b
>
```

Instead of echoing the literal `%p`, the server printed a hex address. That
confirms a **format-string vulnerability** — our input is being used as the
format argument of a `printf`-family call.

## Vulnerability / Core Concept

The safe way to echo user text in C is `printf("%s", user_input)`, where the
programmer owns the format string and the user's text is only data. The unsafe
version is `printf(user_input)` — now our input *is* the format string, so
conversion specifiers get interpreted as instructions:

- `%p` / `%x` print a value off the stack/registers in hex,
- `%s` treats a value as a pointer and prints the string it points to,
- `%N$s` reads the *N*-th argument specifically (positional).

Even though the program never intended to pass 135 arguments, `printf` happily
walks saved registers and stack memory looking for them, which lets us read
memory the program never meant to reveal.

A pointer probe (`probe.py`) dumps a range of positions and shows both program
data and our own input sitting on the stack:

```text
0x48725b.(nil).0x71.(nil).(nil).0x70252e70252e7025...
```

The `0x7025...` words are recognizable as our own `%p.%p...` input (`0x70`=`p`,
`0x25`=`%`). Pointers alone aren't the goal though — we want a pointer that aims
at the flag string, then dereference it with `%s`.

## Exploitation

Since an invalid `%N$s` can crash a single connection, the safe black-box
approach is to scan each positional `%s` over a **fresh connection** per index.
`leakargs.py` / `leakrange.py` do exactly that, sweeping positions and printing
any that return readable strings:

```python
payload = f"START%{position}$sEND\n".encode()
```

Position **135** returns the flag:

```text
135 b'STARTisfcr{bl1nd_f0rmat_str1ng_h4s_n0_b1n4ry}END\n> '
```

So the 135th value available to `printf` was a pointer straight to the flag
string. With the position known, the full exploit is a single specifier:

```console
$ printf '%%135$s\n' | nc 0.cloud.chals.io 23023
> isfcr{bl1nd_f0rmat_str1ng_h4s_n0_b1n4ry}
>
```

(The shell's `printf` needs `%%` to emit one literal `%`, so the service
receives `%135$s`.)

- `probe.py` — sweeps `%N$p` in blocks to map out stack/register contents.
- `leakargs.py` / `leakrange.py` — scan positional `%N$s`, one connection per
  index, to find the pointer that lands on the flag.

## Flag

```
isfcr{bl1nd_f0rmat_str1ng_h4s_n0_b1n4ry}
```

## Key Takeaways

- A format-string bug (`printf(user_input)`) turns a basic echo service into an
  arbitrary memory reader — no ROP chain or binary needed.
- Blind/black-box format strings are very tractable: probe `%N$p` to map memory,
  then scan `%N$s` positions (one fresh connection each, since bad pointers
  crash the connection) until one dereferences the flag.
- Read the flavor text. "Repeats back a little more than you said" was a direct
  pointer at the bug class.
