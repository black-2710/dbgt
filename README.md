# dbgt

A terminal debugger for **Linux x86_64** that puts a GEF-style live dashboard and a
radare2-style control-flow graph on one screen. The graph follows the instruction pointer
as you step, so you always see where you are in the structure of the function.

```
+- regs ---------------+- main: graph / code / source / vmmap / find -------+
| rax ...   rbx ...    |  [0x401136] <main>                                 |
| rip  eflags [ZF cf]  |   push rbp ...                                     |
+- stack --------------+- hexdump ------------------------------------------+
+- log ----------------+- target (the program's own terminal) --------------+
+- status: stop reason, address, <symbol>, file:line -----------------------+
```

## Features

- **Live dashboard**: registers (changed ones in red), stack telescope with pointer chains,
  hexdump, log, and the target's own terminal, all visible at once.
- **Pane-based control**: `Tab` / `Shift-Tab` move focus between six panes; each pane has its
  own keys and context-aware commands. `f` maximises the focused pane.
- **r2-style graph**: basic blocks as boxes, red `f` / green `t` / blue edges, loop edges,
  current block highlighted, per-block hit counters, and following calls into callees.
- **Symbols everywhere**: the executable plus libc, ld.so and every loaded library, including
  `name@plt` stubs.
- **DWARF line info**: `file.c:12` annotations, a source view, and `b file.c:42`.
- **Real terminal for the target**: it runs on a pty, so programs that read input work and
  output is not block-buffered.
- **Hardware watchpoints** using the CPU debug registers.
- **Edit state**: `set $rax 0x41` and `write <addr> <bytes>`.
- **Pwn tools**: `checksec`, a colour-coded vmmap, memory `find`.

## Requirements

- Linux on x86_64 with `/proc` mounted
- A recent stable Rust toolchain (1.80 or newer recommended)
- A terminal of about 104 x 28 or larger with Unicode box-drawing and colour

## Build and run

```
cargo build --release
./target/release/dbgt ./yourbinary [args...]
```

Then press `:`, type `start`, press Enter. Use `s` to step, `n` to step over, `c` to continue,
`Tab` to change pane, `?` for help, `q` to quit.

Containers need `CAP_SYS_PTRACE`; see the [User Guide](docs/USER_GUIDE.md#2-installation) for
permissions.

## Keys at a glance

| Everywhere | |
|---|---|
| `Tab` / `Shift-Tab` | next / previous pane |
| `:` | command line (`Enter` on an empty line repeats the last command) |
| `s` `n` `c` (or `F7` `F8` `F5`) | step / step over / continue |
| `f` | maximise the focused pane |
| `?` | help in the log |
| `Ctrl-C` | interrupt a running target (quit when idle) |
| `q` | quit |

Each pane adds its own keys; the focused pane's keys are always shown on the bottom bar.
Full tables are in the [User Guide](docs/USER_GUIDE.md#5-panes-and-keys).

## Documentation

- [User Guide](docs/USER_GUIDE.md): installation, panes, keys, every command, feature guides,
  troubleshooting, cheat sheet
- [Architecture](docs/ARCHITECTURE.md): threads, protocol, module map, algorithms, how to extend
- [Changelog](CHANGELOG.md)

## Status

Early-stage (0.1.0). dbgt has no automated test suite yet, so behaviour on unusual binaries is
untested. If something misbehaves, open an issue with what you typed, what you saw (a
screenshot helps) and the output of `checksec` for the binary.

Not yet implemented: attaching to a running process, following forks and threads, conditional
breakpoints, `finish` / `until`, backtrace, DWARF variables and types, other architectures.

## License

GPL-3.0 license
