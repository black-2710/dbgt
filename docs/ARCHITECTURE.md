# dbgt Architecture

How dbgt is put together, for contributors. For usage see the [User Guide](USER_GUIDE.md).

## 1. Overview

dbgt is a single Rust binary with three kinds of threads and one rule: **only the backend thread
touches the target.**

```
        keys                     Cmd                       ptrace
 user ---------> UI thread ------------------> backend thread ----------> target
                 (app.rs, ui.rs)  <------------ (backend/)                 (on a pty)
                                     Event
                      ^
                      |  PtyOut bytes        pty reader thread <---- target's terminal output
                      +----------------------/
```

- **UI thread** (`main.rs`, `app.rs`, `ui.rs`, `graph.rs`): polls the terminal every 30 ms,
  drains `Event`s from the backend, redraws with ratatui. It never calls ptrace.
- **Backend thread** (`backend/`): owns the target. Every ptrace call happens here, because
  ptrace requests must come from the thread that attached. It blocks in `waitpid` while the
  target runs, so a queued command waits until the next stop.
- **Pty reader thread**: forwards everything the target writes to its terminal as
  `Event::PtyOut`.

The UI writes keystrokes for the target straight to the pty master (it holds a copy of the
file descriptor), because the backend may be blocked waiting for the very program that is
waiting for that input.

## 2. Protocol

Defined in `backend/mod.rs`.

**`Cmd`** (UI to backend): `Step`, `Next`, `Continue`, `Break(addr)`, `Delete(addr)`,
`Stack(Option<addr>)`, `Hex(Option<addr>)`, `Find{pat, filter, desc}`, `Checksec`,
`SetReg{name, value}`, `WriteMem{addr, bytes}`, `Cfg(addr)`, `Watch{addr, len, kind}`,
`Unwatch(n)`, `Watches`.

**`Event`** (backend to UI): `Started(pid)`, `Stopped(Snapshot)`, `Views(Views)`,
`Cfg(Arc<Cfg>)`, `BrowseCfg(Arc<Cfg>)`, `Maps(Arc<Vec<MapEntry>>)`, `Found(Found)`,
`Symbols(Arc<Symbols>)`, `Breakpoints(Vec<addr>)`, `Ended(Stop)`, `Log(String)`,
`Pty(File)`, `PtyOut(Vec<u8>)`, `Gone`.

**`Stop`** says why the target stopped: `Start`, `Edited`, `Step`, `Breakpoint(addr)`, `Trap`,
`Watch(slot)`, `Signal(sig)`, `Exited(code)`, `Killed(sig)`.

A stop produces, in order: possibly `Maps` and then `Symbols` (if the memory map changed),
possibly `Cfg` (if RIP left the current graph), then `Stopped` and `Views`. The UI relies on
this order: symbols arrive before the graph that uses them, and the graph before the stop that
highlights it.

Shared data (`Symbols`, `Cfg`, `Maps`) travels as `Arc`, so large structures are not copied
between threads.

## 3. Module map

| File | Role |
|---|---|
| `main.rs` | Argument parsing, terminal setup, main loop (resize sync, draw, key polling) |
| `app.rs` | All UI state; `Pane` and `ViewMode`; key handling per pane; command dispatch; context commands (`goto`, `follow`, `clear`, `set`, `write`) |
| `ui.rs` | Layout and rendering: `render_pane` per pane, bottom bar, selection cursors, vt100 to ratatui conversion |
| `graph.rs` | `GraphView`: turns a `Cfg` plus a layout into a canvas of styled cells; call selection; focus position |
| `cmd.rs` | Command parser, expression evaluator, `find` and `write` argument parsers, escape handling, help text |
| `backend/mod.rs` | Backend thread loop, protocol types, module loader (`/proc/pid/maps`), memory search, `views()`, pointer-chain description |
| `backend/ptrace.rs` | `Tracee`: launch on a pty, step, continue, software breakpoints, hardware watchpoints, register and memory writes |
| `analysis/disasm.rs` | Decoding and formatting with iced-x86 (NASM syntax); `call_target`, `call_return_addr` |
| `analysis/cfg.rs` | Basic-block recovery by recursive descent |
| `analysis/layout.rs` | Layered graph layout and orthogonal edge routing |
| `analysis/symbols.rs` | Function, PLT and data symbols; `lookup`, `func_range`; line info access |
| `analysis/lines.rs` | DWARF line tables flattened into a sorted table |
| `analysis/checksec.rs` | Mitigation report (hand-parsed ELF headers plus symbols) |

Main dependencies: ratatui (terminal UI), nix (ptrace, pty, signals), iced-x86 (disassembly),
object and gimli (ELF and DWARF), vt100 (terminal emulation), clap, anyhow.

## 4. Key mechanisms

### Breakpoints and stepping

Software breakpoints (`int3`) are written into memory **only while the target runs** and
removed at every stop, so anything read while stopped is the original bytes. `Tracee::cont`
first single-steps off the current instruction so a breakpoint at RIP is not hit again, inserts
all breakpoints, resumes, then on `SIGTRAP` checks whether `rip - 1` is one of them and rewinds
RIP.

`next` (step over) decodes the instruction at RIP; for a call it runs to the instruction after
it, using a one-shot stop plus a stack-pointer check so deeper recursive frames hitting the same
address are ignored.

Signals such as SIGWINCH, SIGCHLD and SIGALRM are forwarded to the target without reporting a
stop (`is_silent`). Other signals stop the target and are delivered on the next resume. SIGSTOP
is the interrupt signal and is never forwarded.

### Hardware watchpoints

Debug registers are accessed with `PTRACE_PEEKUSER` / `POKEUSER` at offset 848
(`offsetof(struct user, u_debugreg)` on x86_64). DR7 is rebuilt from the four slots on every
change: address registers are written first with DR7 cleared, then DR7 is written. After a
`SIGTRAP`, DR6 says which slot fired; for write-watchpoints a trap where the value did not
change is silent and the target keeps running.

### Target on a pty

`launch` opens a pty, gives the slave to the child as stdin, stdout and stderr, and in
`pre_exec` calls `setsid`, makes it the controlling terminal (`TIOCSCTTY`), disables ASLR
(`personality`) and requests tracing. The master fd is close-on-exec. `PTRACE_O_EXITKILL` makes
the target die with dbgt. The UI feeds output into a `vt100::Parser`, and resizes both the
parser and the pty (`TIOCSWINSZ`) to match the target pane.

### Symbols and modules

`refresh_modules` re-reads `/proc/pid/maps` at every stop and compares it with the previous text.
For each new ELF path it loads symbols at the mapping's base. PLT stubs are named by decoding
`jmp [rip+X]` in `.plt`, `.plt.sec` and `.plt.got` and matching X to a dynamic relocation's GOT
slot. DWARF line tables from the same modules are flattened into `Lines` (sorted rows with
sequence-end markers, so addresses outside any sequence resolve to nothing).

### Control-flow graph

1. **Recovery** (`cfg::build`): descend from the function start (and from RIP, so the current
   instruction is always included). Conditional branches add both targets, unconditional jumps
   add the target, returns, indirect jumps and `ud2` end a block, calls fall through. Blocks are
   cut at leaders; edges are tagged False / True / Jump.
2. **Layout** (`layout::layout`): a depth-first search finds loop edges, which are set aside.
   Longest-path layering assigns rows; edges spanning several layers get dummy nodes so they
   route between blocks. Blocks are ordered by barycenter sweeps, x-positions are found by
   repeatedly centring on neighbours, and each channel between layers gets one horizontal lane
   per overlapping edge segment. Loop edges go down the right margin.
3. **Rendering** (`graph::GraphView::refresh`): edges are drawn first, then block boxes on top,
   into a grid of styled cells. The UI draws a window of that grid.

`GraphView::refresh` is cheap enough to run on every stop; the layout is computed once per
`Cfg` (and again when symbols change, because labels affect block widths).

### Panes and focus

`Pane` (regs, main, stack, hex, log, target) is the focus model. `App::on_key` handles global
keys first, then dispatches to `key_main`, `key_regs`, `key_stack`, `key_hex`, `key_log` or
`key_target`. `pane_command` runs before the normal command parser and implements the commands
whose meaning depends on the focused pane. `pane_hint` returns the key hints for the bottom bar.
Maximise (`zoom`) simply renders only the focused pane into the whole body area.

## 5. Extending dbgt

**Add a command.**
1. Add a variant to `Command` in `cmd.rs` and parse it in `parse`.
2. Handle it in `App::run_command` (`app.rs`). If it only needs UI state, finish there.
3. If it needs the target, add a `Cmd` variant in `backend/mod.rs`, an arm in `run`, and, if the
   answer is data, an `Event` variant handled in `App::on_backend`.
4. Add a line to `cmd::HELP` and to the User Guide.

**Add a pane-specific command.** Add a match arm in `App::pane_command`.

**Add a main-pane view.** Add a `ViewMode` variant, a renderer returning `(lines, title)` in
`ui.rs`, a match arm in `render_pane`, and an entry in `key_main` / `set_mode`.

**Add a pane.** Add it to `Pane` (`ALL`, `name`), `pane_hint`, a `key_*` function, the layout in
`ui::draw` and a branch in `ui::render_pane`.

**Add a stop reason.** Add a `Stop` variant and its `Display`; return it from `Tracee`.

## 6. Known limitations

See the User Guide's limitations section. Structural ones worth knowing before changing things:

- The backend handles one command at a time and blocks while the target runs; there is no
  command queue priority.
- `Tracee` assumes a single traced thread (`waitpid(pid)`), so forks and threads are not
  followed.
- The graph canvas is rebuilt in full on each stop; very large functions would benefit from
  incremental drawing.
- There is no automated test suite. The pure parts (`cmd.rs` parsers, `analysis/cfg.rs`,
  `analysis/layout.rs`, `analysis/lines.rs`, `analysis/checksec.rs`) are the best places to
  start adding unit tests.
