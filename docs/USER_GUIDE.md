# dbgt User Guide

Version 0.1.0 · Linux x86_64

## Contents

1. [Overview](#1-overview)
2. [Installation](#2-installation)
3. [Quick start](#3-quick-start)
4. [The screen](#4-the-screen)
5. [Panes and keys](#5-panes-and-keys)
6. [Command reference](#6-command-reference)
7. [Feature guide](#7-feature-guide)
8. [Limitations](#8-limitations)
9. [Troubleshooting](#9-troubleshooting)
10. [Cheat sheet](#10-cheat-sheet)

## 1. Overview

dbgt combines two things that usually live in separate tools: the always-on context
dashboard of GDB with GEF (registers, stack, hexdump, code and target output together) and the
block-based control-flow graph of radare2's visual mode. The graph follows the instruction
pointer as you step.

dbgt launches programs itself and debugs them with `ptrace`. It supports 64-bit x86 ELF
programs on Linux only.

## 2. Installation

**Requirements**

- Linux on x86_64 with `/proc` mounted
- Recent stable Rust (1.80 or newer recommended)
- A terminal of at least about 104 columns by 28 rows, with Unicode box-drawing characters and
  colour (256-colour or truecolor is best)

**Build**

```
cargo build --release
```

The binary is `target/release/dbgt`. Copy it onto your `PATH` if you like.

**Run**

```
dbgt <program> [arguments...]
```

The program starts stopped at its very first instruction (inside `ld.so` for dynamically linked
binaries). Use `start` to run to `main`.

**Permissions.** dbgt starts the target itself (the child asks the kernel to trace it), so the
common Yama setting `ptrace_scope=1` is fine. Inside containers you need `CAP_SYS_PTRACE`
(for example `--cap-add=SYS_PTRACE`) and a seccomp profile that permits `ptrace`. Hardware
watchpoints can be blocked by some virtual machines.

## 3. Quick start

```
cat > t.c <<'EOT'
#include <stdio.h>
int add(int a, int b){ return a+b; }
int main(){ int x = add(2,3); puts("hello dbgt"); return x; }
EOT
gcc -g -O0 -o t t.c
./target/release/dbgt ./t
```

1. Press `:`, type `start`, press Enter. You are stopped at `main` and the graph shows it.
2. Press `s` a few times. Registers that change turn red.
3. In the main pane press `]` to select a call (the row turns blue), then `o` to follow it into
   the callee. `u` goes back.
4. Type `:b add`, then `c` to run to the breakpoint.
5. Press `Tab` until the stack pane is focused (cyan border) and use `j` / `k` to select a slot;
   `Enter` shows what it points to in the hexdump.
6. Press `q` to quit. The target is killed with dbgt.

## 4. The screen

```
+- regs ---------------+- main pane ----------------------------------------+
|                      |                                                    |
+- stack --------------+- hexdump -----------------------------------------+
+- log ----------------+- target ------------------------------------------+
+- status line: stop reason, address, <symbol>, file:line / key hints -------+
```

| Pane | Contents |
|---|---|
| regs | 16 general registers in two columns, `rip` in yellow, `eflags` with flags decoded (set flags in capitals), segment registers, `fs_base` / `gs_base`. Registers that changed since the previous stop are red. |
| main | One of five views: graph, code, source, vmmap, find results. |
| stack | 48 qwords from `rsp` (or a chosen address) with pointer chains: `<symbol+off>` for code, `-> "text"` for strings, `-> 0x...` for pointers to pointers. |
| hexdump | 384 bytes, 8 per row, with an ASCII column. |
| log | Debugger messages and command output (the last 500 lines are kept). |
| target | The program's own terminal, emulated, with colours. |
| bottom bar | Stop reason, address, `<symbol+offset>` and `file:line` in its title; the focused pane's key hints inside; the command line while you type. |

The focused pane has a cyan border and a `▸` before its title. **`f` maximises the focused pane to
the full screen**; while maximised, `Tab` / `Shift-Tab` flip between panes full-screen, like tabs.

## 5. Panes and keys

`Tab` and `Shift-Tab` move focus between the panes in the order regs, main, stack, hexdump,
log, target. Keys that are not pane-specific work everywhere.

### Everywhere

| Key | Action |
|---|---|
| `Tab` / `Shift-Tab` | Next / previous pane |
| `:` | Open the command line (the prompt shows the focused pane, e.g. `stack>`) |
| `s` / `F7` | Step one instruction |
| `n` / `F8` | Step over calls |
| `c` / `F5` | Continue |
| `f` | Maximise / restore the focused pane |
| `?` | Print the command list in the log |
| `Ctrl-C` | Interrupt a running target; quit if nothing is running |
| `q` | Quit |

In the command line, `Enter` runs the command, `Esc` cancels, `Backspace` edits. An empty line
repeats the previous command.

### Main pane

| Key | Action |
|---|---|
| `g` | Cycle views: graph, code, source (if the binary has line info), vmmap |
| `1` `2` `3` `4` | Jump to graph / code / source / vmmap |
| `[` / `]` | Select the previous / next direct call in the graph |
| `o` | Follow the selected call (or the call at RIP) into the callee |
| `u` / `Backspace` | Go back one level |
| `Esc` | Return to the live function |
| `h` `j` `k` `l` / arrows | Scroll (graph, vmmap, find results, source) |
| `PgUp` / `PgDn` | Scroll faster |
| `z` | Recentre on the current instruction |
| `Enter` | Repeat the last command |

### Regs pane

| Key | Action |
|---|---|
| `h` `j` `k` `l` / arrows | Move the cursor over registers |
| `Enter` | Show the register's value in the hexdump (focus moves there) |
| `v` | Show the value as code in the main pane's graph |
| `p` | Show the value in the stack pane |
| `e` | Start a `set $reg ` command for the selected register |

### Stack pane

| Key | Action |
|---|---|
| `j` / `k` | Select a slot |
| `Enter` | Dereference: show the slot's *value* in the hexdump |
| `a` | Show the slot's *address* in the hexdump |
| `v` | Show the slot's value as code (for example a return address) |
| `e` | Start a `write <slot address> ` command to patch the slot |
| `PgUp` / `PgDn` | Scroll through memory |
| `Home` | Follow `rsp` again |

### Hexdump pane

| Key | Action |
|---|---|
| `j` / `k` | Scroll one row (8 bytes) |
| `PgUp` / `PgDn` | Scroll 64 bytes |
| `Enter` | Follow the pointer stored at the top address |
| `e` | Start a `write <address> ` command |
| `Home` | Follow `rsp` again |

### Log pane

| Key | Action |
|---|---|
| `j` / `k`, `PgUp` / `PgDn` | Scroll (the view stays put while new lines arrive) |
| `Home` / `End`, `G` | Oldest line / newest line |

### Target pane

| Key | Action |
|---|---|
| `Enter` / `i` / `t` | Type into the program. The border turns yellow. |
| `Ctrl-]` | Leave input mode |

In input mode every key goes to the program, including `Ctrl-C` (which sends SIGINT to the
target, not to dbgt).

## 6. Command reference

Press `:` to open the command line.

| Command | Purpose |
|---|---|
| `s`, `si`, `step` | Step one instruction |
| `n`, `ni`, `next` | Step over calls |
| `c`, `continue` | Continue |
| `start` | Run to `main` (or to the ELF entry point if there is no `main` symbol) |
| `b <expr>` | Set a breakpoint |
| `d <expr>` | Delete the breakpoint at an address |
| `x [expr]` | Point the hexdump at an address (no argument: follow `rsp`) |
| `tele [expr]` | Point the stack pane at an address (no argument: follow `rsp`) |
| `watch <expr> [1\|2\|4\|8]` | Hardware write-watchpoint; with no arguments, list watchpoints |
| `rwatch <expr> [len]`, `awatch` | Stop on any read or write |
| `unwatch <n>` | Delete watchpoint n |
| `graph <expr>`, `cfg` | Show the control-flow graph of the function at that address |
| `modules` | List loaded modules with symbol and line-row counts |
| `sym <expr>` | Show the symbol at an address |
| `vmmap [word]` | Open the memory-map view; with a word, list matching mappings in the log |
| `checksec` | Mitigation report for the executable |
| `find <pattern> [in <word>]` | Search memory |
| `send <text>` | Type text into the target (no newline added) |
| `sendline <text>` | Same, with a newline appended |
| `set $reg <expr>` | Change a register |
| `write <addr> <bytes>` (`patch`) | Patch memory |
| `help`, `?` | List commands in the log |
| `q`, `quit` | Quit |

### Context commands

These mean different things depending on the focused pane.

| Command | Main | Regs | Stack | Hexdump | Log | Target |
|---|---|---|---|---|---|---|
| `goto <expr>` | open that function's graph | not used | show the stack there | point the hexdump there | not used | not used |
| `follow [arg]` | not used | hexdump a register (`follow rax`) | hexdump slot n (`follow 3`) | follow the pointer at the top address | not used | not used |
| `clear` | not used | not used | not used | not used | empty the log | reset the terminal |

In the Regs pane, a bare register name followed by a value is shorthand for `set`:
`rax 0x41`.

### Expressions

Anywhere an address is expected you can use:

- Numbers: `0x401136`, `*0x401136` (a leading `*` is ignored), or decimal. Hex needs the `0x`
  prefix.
- Registers: `$rip`, `$rsp`, `$rax` ... `$r15`, `$eflags`, `$fs_base`; `$pc` and `$sp` are
  aliases for `$rip` and `$rsp`.
- Symbols: function names (`main`, `puts`), PLT stubs (`puts@plt`) and global data names
  (`counter`). Library symbols exist once the library is loaded, so run `start` first.
- Source lines: `main.c:42`. If that line has no code, the next line that does is used.
- Simple arithmetic with `+` and `-`: `main+0x10`, `$rsp+8`. No parentheses or multiplication,
  and no spaces in `write` addresses.

## 7. Feature guide

### 7.1 Control-flow graph

The graph shows the function containing the instruction pointer. Basic blocks are recovered by
descending from the function start: splitting at jump targets, adding fall-through blocks and
edges. Calls are not followed inside the graph. The code window is the symbol's size when
known, otherwise 2 KB from the current address; recovery stops after 6000 instructions.

Each block is a box:

- **Header**: `[0xaddress]`, then `<symbol>`, then `(indirect jmp)` if it ends in a jump whose
  target cannot be known statically, and `hit xN` once you have stopped at its first
  instruction N times.
- **Rows**: address (green), bytes (yellow), then the instruction. `call` is green, `ret` red,
  jumps yellow, `push`/`pop` magenta, `mov`/`lea` blue, `cmp`/`test` cyan.
- **Notes**: calls and jumps to known symbols get `; puts@plt`; the first instruction of each
  source line gets `; file.c:12`.

Highlights and edges:

- The block holding RIP has a yellow border and the current instruction row is highlighted.
- A selected call row is blue.
- Red `f` = conditional branch not taken, green `t` = taken, blue = unconditional jump or
  fall-through into a shared block.
- Loop edges run down the right margin and end in `◀` at the loop head.

After every stop the view recentres on RIP (`z` does it on demand).

### 7.2 Following calls

In the main pane, `]` / `[` select direct calls (`call 0x...`). `o` opens the callee's graph and
pushes it on a stack; the pane title shows the path, e.g. `main → puts`. `u` goes back and
`Esc` returns to the live function. `:graph <expr>` opens any function directly.

A call through the PLT (`call puts@plt`) jumps straight to the real function once its library
is loaded. Any real stop (`s`, `n`, `c`, a breakpoint) snaps the view back to the live function.
Calls through registers or memory (`call rax`) cannot be selected.

### 7.3 Symbols and modules

At start, and whenever the memory map changes, dbgt reads `/proc/<pid>/maps` and loads symbols
from every ELF file: the executable, `ld.so`, libc and others. `modules` lists them with load
base, symbol count and line-row count.

Loaded: function symbols (static and dynamic tables), `name@plt` names for PLT stubs (found by
following each stub's GOT slot to its relocation), and global data names for expressions and
watchpoints. Distribution libc builds usually export only public names, so internal functions
stay as raw addresses.

### 7.4 Source lines (DWARF)

If the binary or a loaded library has DWARF line tables, locations appear in the status line,
graph and code view, and the source view becomes available (`g` or `3` in the main pane). The
source file is read from disk using the path recorded in the DWARF; if it moved, the pane says
`cannot read <path>`. Breakpoints by line work wherever an expression is accepted:
`b main.c:42`. Only line info embedded in the binary is read.

### 7.5 The target's terminal

The target gets a pty as stdin, stdout, stderr and controlling terminal. `isatty()` is true,
stdout is line-buffered, and `scanf` / `read` work. The pty is resized with the target pane and
rendered by a terminal emulator, so prompts without newlines, carriage returns and colours
display correctly.

Give input by focusing the target pane and pressing `Enter`, or with `send` / `sendline`, which
accept the escapes `\n`, `\r`, `\t`, `\0`, `\\`, `\"` and `\xHH`: `:sendline AAAA\x41\x42`.

Targets run with address-space randomisation disabled, like gdb, so addresses are stable between
runs. They are killed if dbgt exits. These signals are passed to the target without stopping the
debugger: SIGWINCH, SIGURG, SIGCHLD, SIGALRM, SIGVTALRM, SIGPROF, SIGIO.

### 7.6 Watchpoints

Hardware watchpoints use the CPU debug registers, so the target runs at full speed. There are
four slots.

- `watch <expr> [len]` stops after a write that actually changes the value; writes of the same
  value are ignored.
- `rwatch` / `awatch` stop on any read or write (x86 cannot watch reads alone).
- Length is 1, 2, 4 or 8 bytes. The address must be aligned to the length, so dbgt shrinks the
  length and tells you if it is not. For a named global with a known size that size is used;
  otherwise the default is 8.
- When one fires, the log shows `watchpoint N: *addr old=... new=... (hit K)`.
- `watch` alone lists watchpoints with hit counts; `unwatch <n>` deletes one.

Only the main thread is watched. A ptrace error when setting one usually means the environment
blocks debug-register access.

### 7.7 Editing registers and memory

- `set $rax 0x41` or `set rax = main+4` changes a register.
- `write <addr> <bytes>` patches memory. Bytes may be hex digits (`41 42 43` or `414243`), a
  quoted string (`"hi\n"`), or `\x` escapes (`\x90\x90`). The address must not contain spaces.
  Writes to read-only code work.

The target stays stopped. The status line shows `edited`, changed registers turn red, and the
graph is rebuilt after a memory write in case code changed. Shortcuts: `e` in the Regs, Stack and
Hexdump panes pre-fills the command for the selected item.

### 7.8 Pwn tools

**checksec.** Reports on the executable: RELRO (none, partial, full), stack canary, NX, PIE (or
the fixed base address), fortified `*_chk` functions, RPATH / RUNPATH, and whether it is
stripped. Lines start with `[+]` (good), `[-]` (weak or missing) or `[ ]` (informational).
64-bit little-endian ELF only.

**vmmap.** A colour-coded memory map: executable red, writable green, read-only white,
no-access dim. A yellow `◀ rip rsp rax ...` tag marks mappings that registers currently point
into. It refreshes when the map changes. `vmmap libc` lists matching mappings in the log.

**find.** Searches every readable mapping and lists up to 500 hits in a scrollable view, each
with address, mapping name plus offset, symbol and a 24-byte ASCII preview.

| Example | Searches for |
|---|---|
| `find /bin/sh` | Text; escapes allowed |
| `find hex 4883ec08` | Raw bytes |
| `find u64 $rsp` | A little-endian 64-bit value (`u32`, `u16`, `u8` also work) |
| `find u64 system in stack` | Only mappings whose path contains the word (`libc`, `stack`, `heap`) |

Patterns are exact bytes, 1 to 64 long; there are no wildcards.

## 8. Limitations

- Linux x86_64 only. No ARM64, PE or Mach-O.
- You can launch programs but not attach to a running process. Only the main thread is
  debugged; forks and extra threads are not followed.
- No conditional or temporary breakpoints, `finish`, `until`, `display` or backtrace.
- No variable or type information (DWARF line tables only).
- The graph covers one function at a time. Indirect jumps have no outgoing edges, and the
  layout is simpler than radare2's, so large functions can show crossing edges.
- Hit counters count stops, not every pass through a block while running with `c`.
- Library symbols are limited to what a library exports unless it has a symbol table. There is
  no debuginfod support.

## 9. Troubleshooting

| Symptom | Likely cause and fix |
|---|---|
| `Operation not permitted` or a ptrace error at launch | Container or sandbox without `CAP_SYS_PTRACE`, or a restrictive seccomp profile |
| `watch failed` with a ptrace error | The environment blocks debug-register access; try on bare metal |
| `b puts` says `cannot resolve` | Libc is not loaded yet. Run `start` first, or use `b puts@plt` |
| Graph says `no code recovered` | Unmapped or unreadable code at that address. Press `g` for the linear view |
| Source view: `cannot read <path>` | The source moved since compilation; restore it at the recorded path |
| Source view: `no DWARF line info` | Build the target with `-g` |
| Panes cut off or overlapping | Terminal too small; enlarge it or press `f` to maximise a pane |
| The target seems stuck | It may be waiting for input: focus the target pane and press `Enter` to type, or `Ctrl-C` to interrupt |
| Keys do nothing | You may be in target input mode (yellow border): press `Ctrl-]` |
| Box characters look wrong | The terminal font lacks box-drawing glyphs; use a Unicode-capable font |

## 10. Cheat sheet

```
dbgt ./prog args              launch
:start                        run to main
s  n  c                       step / step over / continue
Tab  Shift-Tab                next / previous pane
f                             maximise the focused pane
g 1-4  [ ]  o  u  Esc         (main) view / select call / follow / back / live
hjkl  Enter  v p e            (regs/stack/hex) move / follow / code / stack / edit
:b main.c:42  :b puts         breakpoints
:watch counter  :rwatch $rsp+8
:x $rsp  :tele $rbp           hexdump / stack at an address
:set $rax 0x41  :write $rsp 41424344
:find /bin/sh in libc
:checksec  :vmmap  :modules
Enter (target pane) ... Ctrl-]    type into the program
:sendline AAAA\x41            scripted input
Ctrl-C                        interrupt (quit when idle)
q                             quit
```
