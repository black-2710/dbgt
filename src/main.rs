mod analysis;
mod app;
mod backend;
mod cmd;
mod graph;
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
    let cli = Cli::parse();

    let (ev_tx, ev_rx) = mpsc::channel();
    let cmd_tx = backend::start(cli.program, cli.args, ev_tx);
    let mut app = app::App::new(cmd_tx);

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
