mod analysis;
mod app;
mod backend;
mod cmd;
mod dbgt_init;
mod graph;
mod session;
mod structs;
mod ui;

use anyhow::Result;
use clap::Parser;
use ratatui::crossterm::event::{self, Event as TermEvent, KeyEventKind};
use std::{
    path::PathBuf,
    sync::mpsc::{self, Receiver},
    time::Duration,
};

#[derive(Parser)]
#[command(name = "dbgt", about = "TUI debugger: GEF-style dashboard + r2-style CFG")]
struct Cli {
    /// Program to debug (give a path like ./a.out, or a name found in $PATH)
    program: PathBuf,
    /// Arguments passed to the program
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    args: Vec<String>,
}

fn main() -> Result<()> {
    // `dbgt init ...` is a separate, non-TUI subcommand (pwninit-style libc/ld
    // patching), dispatched by hand before clap parses the normal `dbgt
    // <program> [args...]` form, since the two don't mix cleanly as one
    // clap command. This does mean a target program literally named `init`
    // needs `dbgt ./init` (with a path) rather than bare `dbgt init`.
    let argv: Vec<String> = std::env::args().collect();
    if argv.get(1).map(String::as_str) == Some("init") {
        let init_args = dbgt_init::InitArgs::parse_from(std::iter::once("dbgt init".to_string()).chain(argv[2..].iter().cloned()));
        return dbgt_init::run(init_args);
    }

    let cli = Cli::parse();

    let (ev_tx, ev_rx) = mpsc::channel();
    let program_str = cli.program.to_string_lossy().into_owned();
    let cmd_tx = backend::start(cli.program, cli.args, ev_tx);
    let mut app = app::App::new(cmd_tx, &program_str);

    let mut terminal = ratatui::init(); // also installs a panic hook that restores the tty
    let res = run(&mut terminal, &mut app, &ev_rx);
    ratatui::restore();
    res
}

fn run(
    terminal: &mut ratatui::DefaultTerminal,
    app: &mut app::App,
    rx: &Receiver<backend::Event>,
) -> Result<()> {
    while !app.quit {
        while let Ok(ev) = rx.try_recv() {
            app.on_backend(ev);
        }
        app.sync_term_size();
        terminal.draw(|f| ui::draw(f, app))?;
        if event::poll(Duration::from_millis(30))? {
            if let TermEvent::Key(k) = event::read()? {
                if k.kind == KeyEventKind::Press {
                    app.on_key(k);
                }
            }
        }
    }
    Ok(())
}
