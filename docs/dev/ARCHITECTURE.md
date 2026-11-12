# dbgt Architecture

How dbgt is put together, for contributors. For usage see the [User Guide](../user/USER_GUIDE.md).

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

A second rule, added as the pwn toolset grew: **static analysis never needs the target
running.** Anything that only reads the executable's own bytes — `analysis/gadgets.rs`,
`analysis/statics.rs`, `analysis/onegadget.rs`, `structs.rs`'s decode step — is a pure function
over `&[u8]`, callable with no `Tracee` at all. The backend commands that expose them
(`Cmd::Rop`, `Cmd::Statics`) still go through the backend thread only because that's where
`exe_path()` lives, not because the analysis itself needs a live process; `libc <path> ...` and
`struct load <path>` skip the backend entirely and run client-side in `app.rs`, reading an
arbitrary file off disk.

## 2. Protocol

Defined in `backend/mod.rs`.

**`Cmd`** (UI to backend): `Step`, `Next`, `Continue`, `Finish`, `Backtrace`, `Break(addr)`,
`Delete(addr)`, `Stack(Option<addr>)`, `Hex(Option<addr>)`, `Find{pat, filter, desc}`,
`Checksec`, `Rop(Option<filter>)`, `Statics`, `SetReg{name, value}`, `WriteMem{addr, bytes}`,
`Cfg(addr)`, `Watch{addr, len, kind}`, `Unwatch(n)`, `Watches`.

**`Event`** (backend to UI): `Started(pid)`, `Stopped(Snapshot)`, `Views(Views)`,
`Cfg(Arc<Cfg>)`, `BrowseCfg(Arc<Cfg>)`, `Maps(Arc<Vec<MapEntry>>)`, `Found(Found)`,
`Gadgets(Arc<GadgetList>)`, `Statics(Arc<StaticInfo>)`, `Symbols(Arc<Symbols>)`,
`Breakpoints(Vec<addr>)`, `Ended(Stop)`, `Log(String)`, `Pty(File)`, `PtyOut(Vec<u8>)`, `Gone`.

**`Stop`** says why the target stopped: `Start`, `Edited`, `Step`, `Breakpoint(addr)`, `Trap`,
`Watch(slot)`, `Signal(sig)`, `Exited(code)`, `Killed(sig)`.

A stop produces, in order: possibly `Maps` and then `Symbols` (if the memory map changed),
possibly `Cfg` (if RIP left the current graph), then `Stopped` and `Views`. The UI relies on
this order: symbols arrive before the graph that uses them, and the graph before the stop that
highlights it. `Event::Statics` is the one exception to "the UI reacts to what it asked for": it
only fills in cached data (`App.statics`), never changes the current view, because the user
already switched to the tab they want before the data arrives (see §4, "Static analysis cache").

Shared data (`Symbols`, `Cfg`, `Maps`, `GadgetList`, `StaticInfo`) travels as `Arc`, so large
structures are not copied between threads.

## 3. Module map

| File | Role |
|---|---|
| `main.rs` | Argument parsing, `dbgt init` dispatch (before clap parses the normal form), terminal setup, main loop |
| `app.rs` | All UI state; `Pane`, `ViewMode`, `StaticsTab`; key handling per pane; command dispatch; context commands (`goto`, `follow`, `clear`, `set`, `write`); the `libc`/`cyclic`/`bookmark`/`note`/`struct` client-side handlers |
| `ui.rs` | Layout and rendering: `render_pane` per pane, bottom bar, selection cursors, vt100 to ratatui conversion, the data inspector and struct overlay |
| `graph.rs` | `GraphView`: turns a `Cfg` plus a layout into a canvas of styled cells; call selection; focus position |
| `cmd.rs` | Command parser, expression evaluator, argument parsers (`find`, `write`, `cyclic`, `bookmark`, `note`, `struct`), escape handling, help text |
| `session.rs` | Bookmarks and notes: a hand-rolled text format, loaded/saved next to the executable |
| `structs.rs` | The struct-overlay DSL: parser and byte decoder, independent of any pane |
| `dbgt_init.rs` | `dbgt init` subcommand: shells out to `patchelf` for libc/ld patching |
| `backend/mod.rs` | Backend thread loop, protocol types, module loader (`/proc/pid/maps`), memory search, `views()`, pointer-chain description, the `frame_hop` helper shared by `bt`/`finish` |
| `backend/ptrace.rs` | `Tracee`: launch on a pty, step, continue, software breakpoints, hardware watchpoints, register and memory writes |
| `analysis/disasm.rs` | Decoding and formatting with iced-x86 (NASM syntax); `call_target`, `call_return_addr` |
| `analysis/cfg.rs` | Basic-block recovery by recursive descent |
| `analysis/layout.rs` | Layered graph layout and orthogonal edge routing |
| `analysis/symbols.rs` | Function, PLT and data symbols (runtime, ASLR-biased); `lookup`, `func_range`; line info access |
| `analysis/lines.rs` | DWARF line tables flattened into a sorted table |
| `analysis/checksec.rs` | Mitigation report (hand-parsed ELF headers plus symbols) |
| `analysis/gadgets.rs` | ROP gadget search: backward-decode from `ret`/indirect `jmp`/`call` tails |
| `analysis/statics.rs` | Static (unbiased, link-time) ELF analysis: sections, segments, symtab, imports/GOT, strings |
| `analysis/cyclic.rs` | De Bruijn pattern generation (Duval's algorithm) and crash-offset lookup |
| `analysis/onegadget.rs` | Scoped one_gadget-style candidate finder: real forward constant-propagation, single path only |

Main dependencies: ratatui (terminal UI), nix (ptrace, pty, signals), iced-x86 (disassembly),
object and gimli (ELF and DWARF), vt100 (terminal emulation), clap, anyhow. `dbgt init` adds a
runtime dependency on `patchelf` being on `$PATH` — not a Rust crate, a separate binary it
shells out to.

## 4. Key mechanisms

### Breakpoints and stepping

Software breakpoints (`int3`) are written into memory **only while the target runs** and
removed at every stop, so anything read while stopped is the original bytes. `Tracee::cont`
first single-steps off the current instruction so a breakpoint at RIP is not hit again, inserts
all breakpoints, resumes, then on `SIGTRAP` checks whether `rip - 1` is one of them and rewinds
RIP.

`next` (step over) decodes the instruction at RIP; for a call it runs to the instruction after
it, using `Tracee::cont`'s `temp: Option<(addr, min_rsp)>` parameter — a one-shot stop that only
fires once `rsp` has climbed back past `min_rsp`, so a deeper recursive call hitting the same
return address is ignored. `finish` and `bt` reuse this same primitive and the same frame-walk
building block (`frame_hop`, below) rather than inventing a second mechanism.

Signals such as SIGWINCH, SIGCHLD and SIGALRM are forwarded to the target without reporting a
stop (`is_silent`). Other signals stop the target and are delivered on the next resume. SIGSTOP
is the interrupt signal and is never forwarded.

### Backtrace and finish

`frame_hop(t, rbp)` in `backend/mod.rs` is the one building block both commands use: it reads 16
bytes at `rbp` and returns `(saved_rbp, return_addr)` from the standard
`push rbp; mov rbp, rsp` prologue layout, or `None` if `rbp` is null or unreadable.

- `Cmd::Backtrace` calls it in a loop, symbolizing each return address via `syms.lookup`, capped
  at 64 frames with a guard that stops if `saved_rbp <= rbp` (a corrupted or cyclic chain rather
  than genuine upward progress on the stack).
- `Cmd::Finish` calls it once on the current `rbp` to get the return address, then
  `t.cont(Some((ret, r.rsp)))` — exactly `next`'s mechanism, just with the return address found
  by a frame hop instead of decoding a `call` instruction.

Both are frame-pointer walks, not DWARF/CFI unwinding — see the User Guide's Limitations. There
is no fallback to `.eh_frame` parsing; on `-fomit-frame-pointer` builds `rbp` is just another
GPR and the walk silently produces garbage or stops early (`frame_hop` returning `None` is the
only signal `finish` has that something's wrong, and a corrupted-but-readable chain won't
trigger it).

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

`analysis/symbols.rs`'s addresses are **runtime** (ASLR-biased) — they combine a module's load
base with its static offset. `analysis/statics.rs`'s addresses are deliberately the opposite:
**unbiased, link-time** addresses straight off the ELF file, the same numbers `readelf`/`objdump`
show, because the static browser and `rop` both work before (or without) a process existing.
Don't mix the two without adding the bias back in.

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

### ROP gadget search (`analysis/gadgets.rs`)

For every byte position in an executable section that looks like a gadget "tail" — `ret`
(`0xc3`), `ret imm16` (`0xc2 xx xx`), or a single-byte-ModRM `jmp`/`call` through a register
(`0xff` with reg field 2 or 4 and mod==11) — the search tries decoding forward from every start
offset up to 12 bytes earlier, keeping sequences that land exactly on the tail with no invalid
instructions and no earlier control-flow transfer (only the final tail instruction may divert
control flow). This is the same backward-decode approach ROPgadget/ropper use. Capped at 4000
gadgets total across all executable sections.

### Static ELF analysis (`analysis/statics.rs`)

Five independent pure functions over `&[u8]`, combined into one `StaticInfo`:

- `sections`/`segments` use `object` for sections and a hand-parsed 64-bit LE ELF program
  header table for segments (same byte offsets `checksec.rs` already used).
- `symbols` walks both the static and dynamic symbol tables.
- `imports` cross-references undefined dynamic symbols against `.plt`/`.plt.sec`/`.plt.got`
  stub scanning — the same GOT-slot-matching technique `symbols.rs::add_plt` uses for the live
  process, adapted to work unbiased from raw bytes.
- `strings` scans every section with file bytes (skipping `.bss`) for printable-ASCII runs of
  4+ characters, capped at 8000 with a truncation flag.

Computed once per `Cmd::Statics` call and cached in `App.statics`; the five static-browser tabs
(`StaticsTab` in `app.rs`) just re-slice and filter the same cached struct, so switching tabs
with `[`/`]` is instant.

### cyclic (`analysis/cyclic.rs`)

`de_bruijn` is Duval's algorithm for a De Bruijn sequence B(26, 4) — the same construction and
defaults (`string.ascii_lowercase`, subsequence length 4) pwntools uses, so patterns and offsets
are interchangeable with pwntools output. `generate(len)` slices or cycles that sequence;
`find(needle)` is a substring search over it. The automatic crash-offset hint
(`App::suggest_cyclic_offset`) checks every general-purpose register's low 4 bytes against the
pattern on SIGSEGV/SIGBUS/SIGILL and only logs anything when it finds an actual match, so it
can't produce false positives on unrelated crashes.

### onegadget-lite (`analysis/onegadget.rs`)

Deliberately far smaller than real `one_gadget`. It finds call sites into `execve`/`system`
(direct calls by resolved symbol address, plus the raw `execve` syscall inside libc's own
wrapper, detected by finding `mov eax, 0x3b` within 12 instructions before a `syscall` in the
same basic block). For each site, it finds the enclosing function (nearest preceding sized
`Text`-kind symbol) and does a **single straight-line forward scan** — no branches followed —
tracking `rdi`/`rsi`/`rdx` as known constants via simple constant propagation (`mov reg, imm`,
`xor reg, reg`; any other write to the register marks it unknown from that point on).

This is real analysis, not a lookup table — but it only follows one path. Real `one_gadget`
follows every path through the function's control-flow graph and proves constraints precisely
per path; reusing `analysis/cfg.rs` to do the same here (enumerate paths from function entry to
each call site, one candidate per path) is the natural next step if this needs to get more
precise, and was deliberately deferred rather than attempted half-correctly.

### Session persistence (`session.rs`)

Bookmarks and notes are stored in a hand-rolled line-based text format (not JSON — there's no
serde dependency, and keeping the file human-editable matches how the rest of dbgt hand-parses
ELF/DWARF instead of adding dependencies for it), saved to `<exe-path>.dbgt-session` and
reloaded automatically by matching that path on `App::new`.

### Struct overlay (`structs.rs`)

A small hand-rolled parser for `struct Name { type name[; ...] }` blocks (no parser-combinator
crate — consistent with the rest of the codebase). `parse` returns `Vec<StructDef>`; `decode`
takes one `StructDef`, a base address, and a byte slice starting at that address, and returns
`Vec<FieldView>` with each field's address, type label, and formatted value. The hexdump
renderer (`ui.rs::struct_overlay_lines`) calls `decode` fresh on every draw using whatever
`Views.hex` currently holds — there is no separate memory-read path for the overlay, which is
why it can only show fields that are already in the visible hexdump window.

### dbgt init (`dbgt_init.rs`, dispatched from `main.rs`)

Not part of the TUI. `main.rs` checks `argv[1] == "init"` by hand before clap parses the normal
`dbgt <program> [args...]` form (the two don't mix cleanly as one clap command), then parses the
rest with a second, independent `clap::Parser` struct. All the actual ELF patching is done by
shelling out to `patchelf` (`--print-needed` to find the real libc `NEEDED` string,
`--replace-needed` and `--set-interpreter` to rewrite it) rather than reimplementing interpreter
segment growth and dynamic-section rewriting — that's exactly what pwninit itself does, and it's
a correctness-critical job better left to a tool everyone already trusts for it.

### Panes and focus

`Pane` (regs, main, stack, hex, log, target) is the focus model. `App::on_key` handles global
keys first, then dispatches to `key_main`, `key_regs`, `key_stack`, `key_hex`, `key_log` or
`key_target`. `pane_command` runs before the normal command parser and implements the commands
whose meaning depends on the focused pane. `pane_hint` returns the key hints for the bottom bar.
Maximise (`zoom`) simply renders only the focused pane into the whole body area.

`ViewMode` (the main pane's sub-view) now has seven variants: `Graph`, `Disasm`, `Source`,
`Maps`, `Results`, `Gadgets`, `Statics`. The last carries its own sub-selector, `StaticsTab`
(`Sections`/`Segments`/`Symtab`/`Imports`/`Strings`), switched with `[`/`]` rather than adding
five more `ViewMode` variants — keeps the exhaustive `ViewMode` matches in `app.rs`/`ui.rs`
from growing without bound as the static browser's tab count changes.

## 5. Extending dbgt

**Add a command.**
1. Add a variant to `Command` in `cmd.rs` and parse it in `parse`.
2. Handle it in `App::run_command` (`app.rs`). If it only needs UI state (or reads an arbitrary
   file off disk, like `libc`/`struct load`), finish there — it does not need a `Cmd`.
3. If it needs the target, add a `Cmd` variant **in both places**: the `pub enum Cmd { ... }`
   declaration *and* an arm in `run`. (This exact split — usage added, declaration forgotten —
   is a real mistake that shipped and broke the build once; `grep -oE "Cmd::[A-Za-z]+"` across
   `app.rs` and `backend/mod.rs`, sorted and deduped, should always match the enum's variant
   list exactly. Same check applies to `Command` against `cmd.rs`.)
4. If the answer is data, add an `Event` variant and handle it in `App::on_backend`.
5. Add a line to `cmd::HELP` and to the User Guide.

**Add a pane-specific command.** Add a match arm in `App::pane_command`.

**Add a main-pane view.** Prefer extending an existing `ViewMode` with a sub-selector (as
`StaticsTab` does) over adding a new top-level variant if the feature is naturally tabbed —
it keeps the exhaustive matches bounded. For a genuinely new view: add a `ViewMode` variant, a
renderer returning `(lines, title)` in `ui.rs`, a match arm in `render_pane`, and an entry in
`key_main` / `set_mode`.

**Add a pane.** Add it to `Pane` (`ALL`, `name`), `pane_hint`, a `key_*` function, the layout in
`ui::draw` and a branch in `ui::render_pane`.

**Add a stop reason.** Add a `Stop` variant and its `Display`; return it from `Tracee`.

**Add a static-analysis feature (no process needed).** Write it as a pure function over `&[u8]`
in `analysis/`, following `gadgets.rs`/`statics.rs`/`onegadget.rs`'s pattern. Only wire it
through a `Cmd`/`Event` round trip if it needs something only the backend thread has (like
`exe_path()`); if it can take a path directly from the command line, it can run entirely in
`app.rs` the way `libc`/`struct load` do, with no backend involvement at all.

## 6. Known limitations

See the User Guide's limitations section for the user-facing list. Structural ones worth
knowing before changing things:

- The backend handles one command at a time and blocks while the target runs; there is no
  command queue priority.
- `Tracee` assumes a single traced thread (`waitpid(pid)`), so forks and threads are not
  followed. This is the single biggest planned change and hasn't been started — it would touch
  `backend/mod.rs`'s core loop, `ptrace.rs`'s `Tracee`, and the implicit single-target assumption
  baked into the `Cmd`/`Event` protocol itself (there's no thread/process ID anywhere in either
  enum right now).
- No DWARF variable or type walk (`.debug_info` DIEs, location expressions) — only line tables
  (`lines.rs`) are read. This is the other half of the big planned item above.
- `bt`/`finish` have no `.eh_frame` fallback for `-fomit-frame-pointer` builds.
- `onegadget-lite` follows one path per call site; it doesn't use `cfg.rs` to enumerate branches
  even though that infrastructure already exists and would be the natural way to extend it.
- The struct overlay DSL has no arrays of scalar types, no nested structs, no bitfields, and
  decodes only from bytes already in the hexdump's current window (no independent memory read).
- The graph canvas is rebuilt in full on each stop; very large functions would benefit from
  incremental drawing.
- `dbgt init` has a hand-dispatched subcommand boundary (`argv[1] == "init"`) rather than a
  proper clap subcommand, which means a target program literally named `init` needs to be
  invoked as `dbgt ./init` rather than bare `dbgt init`.
- **There is no automated test suite.** This has been true since v0.1.0 and is more overdue now
  than ever: `cmd.rs`'s parsers, `analysis/cfg.rs`, `analysis/layout.rs`, `analysis/lines.rs`,
  `analysis/checksec.rs`, `analysis/gadgets.rs`, `analysis/statics.rs`, `analysis/cyclic.rs`,
  `analysis/onegadget.rs`, `session.rs`'s load/save, and `structs.rs`'s parse/decode are all
  pure functions with zero tests between them. `cyclic::find` and `structs::parse` are
  particularly easy first targets — small, deterministic, no process or ptrace involved.
