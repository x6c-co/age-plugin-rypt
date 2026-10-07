//! `age-plugin-rypt`: an age plugin that wraps file keys with rypt.dev keys.

mod api;
mod identity_file;
mod key;
mod plugin;
mod stanza;

use std::fs::File;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{CommandFactory, Parser, Subcommand};
use uuid::Uuid;
use zeroize::Zeroizing;

/// The largest identity file `recipient` reads.
const MAX_IDENTITY_FILE: usize = 1 << 20;

#[derive(Parser)]
#[command(version, about = "age plugin that wraps file keys with rypt.dev keys")]
struct Cli {
    /// Run the given age plugin state machine. age sets this; it is not for
    /// interactive use.
    #[arg(long, value_name = "STATE_MACHINE", hide = true)]
    age_plugin: Option<String>,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Print an identity file for a rypt key. Does not call the rypt API.
    New {
        /// The rypt key id.
        #[arg(long, value_name = "UUID")]
        key: Uuid,
    },
    /// Print the recipient for each rypt identity in an identity file.
    Recipient {
        /// The identity file. Reads standard input when omitted or `-`.
        path: Option<PathBuf>,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    if let Some(state_machine) = cli.age_plugin {
        return match age_plugin::run_state_machine(&state_machine, plugin::Handler) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => fail(e),
        };
    }

    match cli.command {
        Some(Command::New { key }) => {
            let created = chrono::Local::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
            print(&identity_file::render(key, &created))
        }
        Some(Command::Recipient { path }) => {
            let recipients = read_identity_file(path.as_deref())
                .and_then(|text| identity_file::recipients(&text));
            match recipients {
                Ok(recipients) => print(&(recipients.join("\n") + "\n")),
                Err(e) => fail(e),
            }
        }
        None => {
            eprint!("{}", Cli::command().render_help());
            ExitCode::from(2)
        }
    }
}

/// Reads an identity file from `path`, or standard input for none or `-`.
///
/// The file may hold other identities, secret keys among them, so it is read
/// into one buffer that is wiped when dropped and never reallocated.
fn read_identity_file(path: Option<&Path>) -> Result<Zeroizing<String>, String> {
    let (name, file) = match path {
        Some(path) if path.as_os_str() != "-" => (path.display().to_string(), Some(path)),
        _ => ("standard input".to_owned(), None),
    };
    let limit = MAX_IDENTITY_FILE as u64 + 1;
    let mut buffer = Zeroizing::new(Vec::with_capacity(MAX_IDENTITY_FILE + 1));
    let read = match file {
        Some(path) => File::open(path).and_then(|f| f.take(limit).read_to_end(&mut buffer)),
        None => io::stdin().lock().take(limit).read_to_end(&mut buffer),
    };
    read.map_err(|e| format!("{name}: {e}"))?;
    if buffer.len() > MAX_IDENTITY_FILE {
        return Err(format!("{name}: larger than 1 MiB"));
    }
    // Moves the bytes into the String without copying them.
    String::from_utf8(std::mem::take(&mut *buffer))
        .map(Zeroizing::new)
        .map_err(|e| {
            drop(Zeroizing::new(e.into_bytes()));
            format!("{name}: not valid UTF-8")
        })
}

fn print(text: &str) -> ExitCode {
    let mut stdout = io::stdout().lock();
    match stdout
        .write_all(text.as_bytes())
        .and_then(|()| stdout.flush())
    {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => fail(e),
    }
}

fn fail(error: impl std::fmt::Display) -> ExitCode {
    eprintln!("age-plugin-rypt: {error}");
    ExitCode::FAILURE
}
