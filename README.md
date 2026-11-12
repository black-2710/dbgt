# dbgt

A TUI debugger for dissecting Linux x86_64 ELF binaries — a GEF-style always-on dashboard, an
r2-style control-flow graph that follows RIP, and a pwn-focused toolset (ROP gadgets, cyclic
patterns, a libc/ret2libc helper, bookmarks, and more) in one terminal window.

Builds and runs with `cargo build --release` — confirmed on a real build as of this writing.

## What's in here

- **Always-on dashboard**: registers, a 48-slot stack telescope with pointer-chain resolution,
  a colourised hexdump with a per-byte data inspector, and the target's own terminal, live.
- **Control-flow graph**: recovers basic blocks, lays them out, and follows the instruction
  pointer as you step — select a call and jump into it, then back out.
- **Static ELF browser**: sections, segments, the full symbol table, imports/GOT, and a string
  scan, all browsable the moment you open a binary — no need to run it first.
- **Pwn workflow**: `rop` (gadget search), `cyclic` (De Bruijn patterns with automatic
  crash-offset detection), `bt` / `finish`, a `libc` helper for ret2libc (base + system +
  execve + `/bin/sh`, plus scoped `onegadget`-style candidates), `checksec`, `find`, hardware
  watchpoints, memory/register patching.
- **Depth**: bookmarks and notes saved alongside the binary, an ImHex-style struct overlay for
  the hexdump, and a `dbgt init` subcommand for pwninit-style libc/ld patching.

See **[docs/user/USER_GUIDE.md](docs/user/USER_GUIDE.md)** for the full command reference, key
bindings, and feature walkthroughs, and **[docs/dev/ARCHITECTURE.md](docs/dev/ARCHITECTURE.md)**
for how it's put together if you want to extend it.

## Quick start

```
cargo build --release
./target/release/dbgt ./some_binary
```

Inside: `:start` to run to `main`, `s`/`n`/`c` to step/step-over/continue, `Tab` to move
between panes, `:` to open the command line, `?` for a full command list.

## Status

Linux x86_64 ELF only. No threads/forks yet, no DWARF variable/type info, frame-pointer-only
backtraces (wrong on `-fomit-frame-pointer` builds). See the User Guide's Limitations section
and the Architecture doc's Known Limitations section for the complete, honest list — several
features here are deliberately scoped down from what a full-strength tool would do, and say so
in their own output, not just in these docs.

## License

GPL-3.0 — see [LICENSE](LICENSE).
