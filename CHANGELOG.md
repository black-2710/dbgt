# Changelog

All notable changes to dbgt are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/).

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
