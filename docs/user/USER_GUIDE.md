# dbgt User Guide

Version 0.2.0 · Linux x86_64

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

dbgt combines the always-on context dashboard of GDB with GEF (registers, stack, hexdump, code
and target output together), the block-based control-flow graph of radare2's visual mode, and a
pwn-focused toolset inspired by pwndbg, pwntools, ROPgadget/ropper, hexyl, binsider, ImHex and
pwninit — in one terminal window.

dbgt launches programs itself and debugs them with `ptrace`. It supports 64-bit x86 ELF
programs on Linux only.

## 2. Installation

**Requirements**

- Linux on x86_64 with `/proc` mounted
- Recent stable Rust (1.80 or newer recommended)
- A terminal of at least about 104 columns by 28 rows, with Unicode box-drawing characters and
  colour (256-colour or truecolor is best)
- `patchelf` on `$PATH` if you want to use `dbgt init` (see [7.12](#712-dbgt-init))

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
binaries). Use `start` to run to `main`. Static-analysis commands (`sections`, `rop`, `strings`,
etc.) work the moment the program is loaded, before you run anything.

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

For the pwn workflow specifically, see [7.9](#79-pwn-tools) through [7.11](#711-bookmarks-and-notes).

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
| main | One of seven views: graph, code, source, vmmap, find results, rop gadgets, static ELF browser. |
| stack | 48 qwords from `rsp` (or a chosen address) with pointer chains: `<symbol+off>` for code, `-> "text"` for strings, `-> 0x...` for pointers to pointers. |
| hexdump | 384 bytes, 8 per row, with an ASCII column, a per-byte data inspector, and (when pinned) a struct overlay. See [7.7](#77-the-data-inspector-and-struct-overlay). |
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
| `g` | Cycle views: graph → code → source (if available) → vmmap → find results → rop → static browser → graph |
| `1`–`6` | Jump directly to graph / code / source / vmmap / rop / static browser |
| `[` / `]` | In graph/code: select the previous/next direct call. In the static browser: switch tab (sections/segments/symtab/imports/strings) |
| `o` | Follow the selected call (or the call at RIP) into the callee |
| `u` / `Backspace` | Go back one level |
| `Esc` | Return to the live function |
| `h` `j` `k` `l` / arrows | Scroll (graph, vmmap, find results, source, rop, static browser) |
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
| `h` / `l` or `←` / `→` | Move the data-inspector cursor one byte (see [7.7](#77-the-data-inspector-and-struct-overlay)) |
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

### Execution

| Command | Purpose |
|---|---|
| `s`, `si`, `step` | Step one instruction |
| `n`, `ni`, `next` | Step over calls |
| `c`, `continue` | Continue |
| `finish`, `fin` | Run until the current function returns (frame-pointer walk — see [7.6](#76-backtrace-and-finish)) |
| `bt`, `backtrace`, `where` | Frame-pointer backtrace |
| `start` | Run to `main` (or the ELF entry point if there is no `main` symbol) |
| `b <expr>` | Set a breakpoint |
| `d <expr>` | Delete the breakpoint at an address |

### Inspection

| Command | Purpose |
|---|---|
| `x [expr]` | Point the hexdump at an address (no argument: follow `rsp`) |
| `tele [expr]` | Point the stack pane at an address (no argument: follow `rsp`) |
| `watch <expr> [1\|2\|4\|8]` | Hardware write-watchpoint; with no arguments, list watchpoints |
| `rwatch <expr> [len]`, `awatch` | Stop on any read or write |
| `unwatch <n>` | Delete watchpoint n |
| `graph <expr>`, `cfg` | Show the control-flow graph of the function at that address |
| `modules` | List loaded modules with symbol and line-row counts |
| `sym <expr>` | Show the symbol at an address |
| `vmmap [word]` | Open the memory-map view; with a word, list matching mappings in the log |
| `find <pattern> [in <word>]` | Search memory |

### Static ELF browser (no running process needed — see [7.1](#71-static-elf-browser))

| Command | Purpose |
|---|---|
| `sections`, `secs` | Section table (address, size, kind, r/w/x) |
| `segments`, `phdrs` | Program headers (type, offset, vaddr, size, r/w/x) |
| `symtab [filter]`, `syms [filter]` | Full symbol table, optionally filtered by substring |
| `imports [filter]`, `got [filter]`, `plt [filter]` | Imported functions with GOT/PLT addresses |
| `strings [filter]` | Printable-string scan, optionally filtered |
| `checksec` | Mitigation report for the executable |

### Pwn workflow (see [7.9](#79-pwn-tools)–[7.10](#710-onegadget-lite))

| Command | Purpose |
|---|---|
| `rop [filter]` | ROP gadget search; `rop pop rdi` filters by disassembly text |
| `cyclic <N>` | Print N bytes of a De Bruijn pattern |
| `cyclic send <N>` | Generate N bytes and write them straight to the target |
| `cyclic -l <leak>` | Offset of a leaked value (e.g. `0x6161616c` or `laaa`) in the pattern |
| `libc <path> <symbol> [leaked addr]` | Offline ret2libc helper: symbol offset; with an address, predicted base + `system`/`execve`/`"/bin/sh"` + onegadget-lite candidates |

### Depth (see [7.11](#711-bookmarks-and-notes)–[7.12](#712-dbgt-init))

| Command | Purpose |
|---|---|
| `bookmark <addr\|sym> <label>` | Add/relabel a bookmark, saved to `<exe>.dbgt-session` |
| `bookmark del <addr>` | Remove a bookmark |
| `bookmark` | List bookmarks |
| `note [@<addr\|sym>] <text>` | Add a note (no `@`: attaches to the current PC, or general if nothing is running) |
| `note` | List notes |
| `struct load <path>` | Load struct definitions from a file |
| `struct <Name> [@<addr>]` | Pin a struct overlay on the hexdump at an address (default: the hexdump cursor) |
| `struct clear` | Unpin the overlay |
| `struct list` | List loaded struct definitions |

### Editing and misc

| Command | Purpose |
|---|---|
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

### 7.1 Static ELF browser

Press `6`, or run `sections` / `segments` / `symtab` / `imports` / `strings`, to open the
binsider-style static browser. It works the instant a binary is loaded, before `start`.
Switch tabs with `[` / `]` while the view is focused.

- **sections** — name, address, size, kind, and a rough r/w/x guess from the section kind
  (the authoritative permissions are on the *segment* that maps it, see below).
- **segments** — the real program headers: type (LOAD, DYNAMIC, GNU_RELRO, ...), offset,
  vaddr, file/mem size, and actual r/w/x flags.
- **symtab** — every symbol in the static and dynamic tables, with address, size, kind
  (function/data/...), and binding (LOCAL/GLOBAL/WEAK/UND). Filter with `symtab <text>`.
- **imports** / **got** / **plt** — undefined dynamic symbols with their GOT slot and, where
  resolvable, their PLT stub address.
- **strings** — printable-ASCII runs of 4+ characters across every section with file bytes,
  capped at 8000 entries. Filter with `strings <text>`.

Data is computed once per binary and cached; switching tabs is instant.

### 7.2 Control-flow graph

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

### 7.3 Following calls

In the main pane, `]` / `[` select direct calls (`call 0x...`). `o` opens the callee's graph and
pushes it on a stack; the pane title shows the path, e.g. `main → puts`. `u` goes back and
`Esc` returns to the live function. `:graph <expr>` opens any function directly.

A call through the PLT (`call puts@plt`) jumps straight to the real function once its library
is loaded. Any real stop (`s`, `n`, `c`, a breakpoint) snaps the view back to the live function.
Calls through registers or memory (`call rax`) cannot be selected.

### 7.4 Symbols and modules

At start, and whenever the memory map changes, dbgt reads `/proc/<pid>/maps` and loads symbols
from every ELF file: the executable, `ld.so`, libc and others. `modules` lists them with load
base, symbol count and line-row count.

Loaded: function symbols (static and dynamic tables), `name@plt` names for PLT stubs (found by
following each stub's GOT slot to its relocation), and global data names for expressions and
watchpoints. Distribution libc builds usually export only public names, so internal functions
stay as raw addresses.

### 7.5 Source lines (DWARF)

If the binary or a loaded library has DWARF line tables, locations appear in the status line,
graph and code view, and the source view becomes available (`g` or `3` in the main pane). The
source file is read from disk using the path recorded in the DWARF; if it moved, the pane says
`cannot read <path>`. Breakpoints by line work wherever an expression is accepted:
`b main.c:42`. Only line info embedded in the binary is read — there is no variable or type
information (see [8. Limitations](#8-limitations)).

### 7.6 Backtrace and finish

`bt` walks the chain of saved `rbp` values (`[rbp]` → next frame's saved rbp, `[rbp+8]` → return
address), symbolizing each return address. `finish` does one hop of the same walk to find the
current function's return address, then runs to it the same way `next` runs over a call (a
one-shot breakpoint plus a stack-pointer check, so a deeper recursive call to the same address
doesn't stop early).

**This is a frame-pointer walk, not DWARF/CFI unwinding.** It is wrong or stops early on
anything built with `-fomit-frame-pointer`, which is the default at `-O2` and above on x86-64.
Compile with `-fno-omit-frame-pointer` if `bt`/`finish` look wrong.

### 7.7 The data inspector and struct overlay

The hexdump pane has a byte cursor, moved with `h`/`l` or the arrow keys (independent of
`j`/`k`, which scroll the whole view by a row). Above the hex dump, two lines show the
selected byte decoded every which way: `u8`/`i8`/`u16`/`u32`/`u64` as hex and decimal on one
line, `i32`/`i64`/`f32`/`f64` and a 16-byte ASCII preview on the other.

**Struct overlay.** `struct load <path>` reads a small C-like definition file:

```
struct Header {
    u32 magic;
    u16 version;
    char name[16];
}
```

Supported field types: `u8`/`u16`/`u32`/`u64`, `i8`/`i16`/`i32`/`i64`, `f32`/`f64`,
`ptr`/`addr` (aliases for `u64`), and `char[N]`/`bytes[N]` fixed-size arrays (shown as a
NUL-trimmed string, or raw hex, respectively). **v1 limitation:** no arrays of scalar types
(`u32 values[4]` is rejected), no nested structs, no bitfields.

`struct <Name>` pins the overlay at the current hexdump cursor; `struct <Name> @<addr>` moves
the hexdump there first. While pinned, the overlay replaces the byte inspector in the hexdump
pane, decoding live as you scroll. `struct clear` unpins it. The overlay only decodes bytes
already visible in the hexdump view — it does not do a separate memory read, so if you pin it
somewhere out of view it says so rather than guessing.

### 7.8 Editing registers and memory

- `set $rax 0x41` or `set rax = main+4` changes a register.
- `write <addr> <bytes>` patches memory. Bytes may be hex digits (`41 42 43` or `414243`), a
  quoted string (`"hi\n"`), or `\x` escapes (`\x90\x90`). The address must not contain spaces.
  Writes to read-only code work.

The target stays stopped. The status line shows `edited`, changed registers turn red, and the
graph is rebuilt after a memory write in case code changed. Shortcuts: `e` in the Regs, Stack and
Hexdump panes pre-fills the command for the selected item.

### 7.9 Pwn tools

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

**rop.** Scans every executable section for `ret` / `ret imm16` / indirect `jmp`/`call` reg
"tails", then backward-decodes with iced-x86 from up to 12 bytes before each tail, keeping
sequences that land cleanly on the tail with no invalid instructions and no earlier
control-flow transfer. `rop pop rdi` filters the results by substring. Press `5` or cycle with
`g` to view the full list with jump/call tails highlighted yellow.

**cyclic.** `cyclic 200` prints 200 bytes of a pwntools-compatible De Bruijn pattern (26-letter
alphabet, 4-byte unique subsequences, period 456,976 bytes — patterns longer than that repeat
and stop being unique). `cyclic send 200` writes it straight to the target's stdin. `cyclic -l
0x6161616c` or `cyclic -l laaa` finds the offset of a leaked value in the pattern.

**Automatic crash-offset detection.** On SIGSEGV/SIGBUS/SIGILL, dbgt checks every general-purpose
register's low 4 bytes against the cyclic pattern and logs any match with its offset —
no command needed.

### 7.10 onegadget-lite

`libc <path> <symbol> [leaked addr]` is dbgt's offline ret2libc helper. Given a libc file and
one leaked symbol (plus its runtime address, if you have one), it:

1. Reports the symbol's static offset in that file.
2. If given an address, computes the predicted load base and prints `system`, `execve`,
   `__libc_system`, and the `"/bin/sh"` string's predicted runtime addresses.
3. Runs a scoped, honest substitute for `one_gadget`: it finds every call site into
   `execve`/`system` (plus the raw `execve` syscall inside libc's own wrapper), and for each one
   does a genuine **forward constant-propagation scan** — not a lookup table — from the
   enclosing function's start to that call, tracking `rdi`/`rsi`/`rdx` via `mov reg, imm` and
   `xor reg, reg`. Each candidate is reported as `rdi=NULL (fixed by this path)` where it can
   prove it, or `rdi=? — must be valid/NULL when you land here` where it can't.

**This is not real `one_gadget`.** Real `one_gadget` follows every path through a function's
control flow and proves constraints precisely; this follows exactly one path — straight-line,
no jumps followed. If the actual execution path to a call goes through a taken branch, this
scans the wrong bytes and a reported constraint can be wrong. Every candidate is a starting
point to verify by hand against the real disassembly, never a guarantee. The log output repeats
this caveat every time you run it.

### 7.11 Bookmarks and notes

`bookmark <addr|sym> <label>` names an address; it shows up as a `★ label` tag inline in the
disassembly pane from then on. `bookmark del <addr>` removes one, `bookmark` alone lists them.

`note [@<addr|sym>] <text>` adds a note — with no `@`, it attaches to the current PC if the
target is running, or is a general note otherwise. `note` alone lists them.

Both are saved to a small human-readable text file, `<executable-path>.dbgt-session`, loaded
automatically the next time you debug that binary. It's plain text on purpose — open it in an
editor if you want to edit bookmarks by hand:

```
bookmark 0x401136 win_function
note 0x4011a0 looks like the vulnerable strcpy
note - remember: libc is 2.31 on the remote
```

### 7.12 dbgt init

`dbgt init <binary> --libc <path> [--ld <path>] [-o <output>] [-c]` is a separate, non-TUI
subcommand — a pwninit-style helper for pointing a CTF binary at a specific libc/ld pair.

- If `--ld` is omitted, dbgt looks for a sibling `ld-linux*.so*` next to the given libc.
- The binary's actual libc `NEEDED` entry is auto-detected via `patchelf --print-needed` rather
  than assumed to be exactly `libc.so.6`.
- `-o <output>` copies the binary first rather than patching in place.
- `-c` makes the binary (and libc/ld, if given) executable.

**Requires `patchelf` on `$PATH`** (`apt install patchelf` or equivalent) — dbgt shells out to
it rather than reimplementing ELF interpreter/NEEDED rewriting, since getting that correct
without corrupting the file is a solved problem in a tool everyone already trusts for it.

```
dbgt init ./chall --libc ./libc.so.6 --chmod
```

## 8. Limitations

- Linux x86_64 only. No ARM64, PE or Mach-O.
- You can launch programs but not attach to a running process. Only the main thread is
  debugged; forks and extra threads are not followed.
- `bt`/`finish` are frame-pointer walks, not DWARF/CFI unwinding — wrong or incomplete on
  `-fomit-frame-pointer` builds (see [7.6](#76-backtrace-and-finish)).
- No conditional or temporary breakpoints, `until`, or `display` expressions.
- No variable or type information (DWARF line tables only, no `.debug_info` walk).
- `onegadget-lite` is single-path only (see [7.10](#710-onegadget-lite)) — not a replacement
  for real `one_gadget`.
- The struct overlay (see [7.7](#77-the-data-inspector-and-struct-overlay)) has no scalar
  arrays, nested structs, or bitfields, and only decodes bytes already in the hexdump view.
- No heap view (tcache/bins) — scoped out as too glibc-version-fragile for a first pass.
- The graph covers one function at a time. Indirect jumps have no outgoing edges, and the
  layout is simpler than radare2's, so large functions can show crossing edges.
- Hit counters count stops, not every pass through a block while running with `c`.
- Library symbols are limited to what a library exports unless it has a symbol table. There is
  no debuginfod support.
- No automated test suite yet — see the Architecture doc's Known Limitations.

## 9. Troubleshooting

| Symptom | Likely cause and fix |
|---|---|
| `Operation not permitted` or a ptrace error at launch | Container or sandbox without `CAP_SYS_PTRACE`, or a restrictive seccomp profile |
| `watch failed` with a ptrace error | The environment blocks debug-register access; try on bare metal |
| `b puts` says `cannot resolve` | Libc is not loaded yet. Run `start` first, or use `b puts@plt` |
| Graph says `no code recovered` | Unmapped or unreadable code at that address. Press `g` for the linear view |
| Source view: `cannot read <path>` | The source moved since compilation; restore it at the recorded path |
| Source view: `no DWARF line info` | Build the target with `-g` |
| `bt`/`finish` look wrong or stop immediately | Built with `-fomit-frame-pointer` (default at `-O2`+); rebuild with `-fno-omit-frame-pointer` |
| `dbgt init` says `patchelf` not found | Install it (`apt install patchelf` or your distro's equivalent) |
| Panes cut off or overlapping | Terminal too small; enlarge it or press `f` to maximise a pane |
| The target seems stuck | It may be waiting for input: focus the target pane and press `Enter` to type, or `Ctrl-C` to interrupt |
| Keys do nothing | You may be in target input mode (yellow border): press `Ctrl-]` |
| Box characters look wrong | The terminal font lacks box-drawing glyphs; use a Unicode-capable font |

## 10. Cheat sheet

```
dbgt ./prog args              launch
dbgt init ./prog --libc ./libc.so.6 --chmod     pwninit-style patching (needs patchelf)
:start                        run to main
s  n  c  finish  bt           step / step over / continue / return / backtrace
Tab  Shift-Tab                next / previous pane
f                             maximise the focused pane
g 1-6  [ ]  o  u  Esc         (main) view / select call-or-tab / follow / back / live
hjkl  Enter  v p e            (regs/stack/hex) move / follow / code / stack / edit
hl (hexdump)                  move the data-inspector byte cursor
:b main.c:42  :b puts         breakpoints
:watch counter  :rwatch $rsp+8
:x $rsp  :tele $rbp           hexdump / stack at an address
:set $rax 0x41  :write $rsp 41424344
:sections  :symtab puts  :strings flag  :imports        static ELF browser
:rop pop rdi                                            ROP gadgets
:cyclic 200  :cyclic send 200  :cyclic -l 0x6161616c    pattern / crash offset
:libc ./libc.so.6 printf 0x7f1234561100                 ret2libc base + onegadget-lite
:bookmark main.c:42 win  :note @main looks suspicious    bookmarks / notes
:struct load defs.txt  :struct Header @0x404000          hexdump struct overlay
:find /bin/sh in libc
:checksec  :vmmap  :modules
Enter (target pane) ... Ctrl-]    type into the program
:sendline AAAA\x41            scripted input
Ctrl-C                        interrupt (quit when idle)
q                             quit
```
