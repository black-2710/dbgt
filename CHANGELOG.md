# Changelog

All notable changes to dbgt are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/).

## [0.2.0] - 2026-11-12

Static analysis, a pwn-focused workflow, and depth features. No changes to the debugger core's
existing behaviour — everything below is additive.

### Added

**Static ELF browser (no running process needed)**
- `sections`, `segments` (real program headers with r/w/x), `symtab [filter]`, `imports [filter]`
  / `got` / `plt`, `strings [filter]` — a binsider-style tabbed browser (`6` or `g` to open,
  `[`/`]` to switch tabs), computed once and cached per binary.

**ROP and pwn workflow**
- `rop [filter]` — gadget search (`ret`/indirect `jmp`/`call` tails, backward-decoded with
  iced-x86, deduplicated).
- `cyclic <N>`, `cyclic send <N>`, `cyclic -l <leak>` — pwntools-compatible De Bruijn patterns,
  plus automatic crash-offset detection against every general-purpose register on
  SIGSEGV/SIGBUS/SIGILL.
- `bt` / `finish` — frame-pointer backtrace and run-until-return, reusing `next`'s one-shot
  breakpoint mechanism.
- `libc <path> <symbol> [leaked addr]` — offline ret2libc helper: symbol offset, predicted base
  and `system`/`execve`/`"/bin/sh"` addresses, plus **onegadget-lite**: a scoped, single-path
  constant-propagation scan for `execve`/`system` call sites (explicitly not a replacement for
  real `one_gadget` — see the User Guide, §7.10).
- hexyl-style hexdump byte-class colouring, and a two-line ImHex-style data inspector
  (`h`/`l` to move the byte cursor) showing every integer/float interpretation of the selected
  byte plus a string preview.

**Depth**
- Bookmarks and notes (`bookmark`, `note`), saved to a small hand-rolled text file next to the
  executable (`<exe>.dbgt-session`) and reloaded automatically.
- `struct load <path>` / `struct <Name> [@<addr>]` / `struct clear` — an ImHex-style struct
  overlay for the hexdump pane, with its own small C-like definition language.
- `dbgt init` — a separate, non-TUI subcommand for pwninit-style libc/ld patching (shells out to
  `patchelf`).

### Fixed

- A `Cmd::Finish`/`Cmd::Backtrace` enum-declaration gap that broke the release build (the match
  arms and call sites were added without adding the variants themselves) — see the Architecture
  doc's "Extending dbgt" section for the check that now guards against this recurring.

### Known issues

- Still no automated tests (see [0.1.0]'s known issues — now with substantially more pure,
  easily-testable code waiting for them: `gadgets`, `statics`, `cyclic`, `onegadget`,
  `session`, `structs`).
- `gimli::Dwarf::borrow` deprecation warning, unchanged from 0.1.0.
- See the User Guide, section 8, and the Architecture doc, section 6, for the complete,
  up-to-date limitations list.

## [0.1.0] - 2026-10-25

First release. Linux x86_64 ELF only.

### Added

**Debugger core**
- Launch a program under ptrace with ASLR disabled; step (`s`), step over calls (`n`),
  continue (`c`), interrupt with `Ctrl-C`.
- Software breakpoints (`b`, `d`), inserted only while the target runs.
- Hardware watchpoints through the debug registers: `watch`, `rwatch`, `awatch`, `unwatch`;
  four slots; value-change filtering for write watchpoints.
- `start` (run to `main` or the ELF entry point).
- Register and memory editing: `set $reg <expr>` and `write <addr> <bytes>`.

**Interface**
- Six panes (regs, main, stack, hexdump, log, target) with `Tab` / `Shift-Tab` focus, a focus
  highlight, per-pane keys, a per-pane key hint bar, and per-pane command prompts.
- Context commands whose meaning depends on the focused pane: `goto`, `follow`, `clear`; and
  `rax 0x41` shorthand in the Regs pane.
- `f` maximises the focused pane (full-screen tabs with `Tab`).
- Registers pane with change highlighting, decoded `eflags`, and a selectable cursor.
- Stack telescope with pointer chains (symbols, strings, pointer-to-pointer) and slot selection.
- Scrollable hexdump with pointer following; scrollable log; emulated target terminal.

**Control-flow graph**
- r2-style graph: coloured mnemonics, red `f` / green `t` / blue edges, loop edges, current
  block and instruction highlighted, per-block hit counters.
- Following calls into callee graphs with a back stack, including PLT-to-real-function
  resolution; `graph <expr>` opens any function.
- Layered layout with orthogonal routing, long-edge routing and edge lanes.

**Symbols and source**
- Symbols from the executable and every loaded library (libc, ld.so, ...), loaded as libraries
  are mapped; `name@plt` names for PLT stubs; global data names usable in expressions.
- DWARF line tables: `file.c:12` annotations, a source view, `b file.c:42`.
- `modules` and `sym` commands.

**Target I/O**
- The target runs on a pty: real terminal semantics, line-buffered output, working stdin.
- Input from the target pane or `send` / `sendline` with escapes.
- Terminal and pty resize with the pane; benign signals (SIGWINCH, SIGCHLD, ...) do not stop
  the debugger.

**Pwn tools**
- `checksec` (RELRO, canary, NX, PIE, fortify, RPATH, stripped).
- `vmmap` view with register tags.
- `find` over all readable mappings with text, hex and integer patterns and a mapping filter.

### Known issues

- `gimli::Dwarf::borrow` is deprecated in gimli 0.31 and produces a build warning.
- No automated tests.
- See the User Guide, section 8, for the full list of limitations.
