//! `safestore4n6` binary — a thin shell over the `chromium_safestorage_forensic`
//! library (Humble Object): parse args, run, print (text or JSON), set the exit
//! code. All decisions live in the library.

use std::process::ExitCode;

use chromium_safestorage_forensic::{render_text, Cli};
use clap::Parser;

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.run() {
        Ok(report) => {
            if cli.json {
                match serde_json::to_string_pretty(&report) {
                    Ok(s) => println!("{s}"),
                    Err(e) => {
                        eprintln!("error serializing report: {e}");
                        return ExitCode::FAILURE;
                    }
                }
            } else {
                print!("{}", render_text(&report));
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("safestore4n6: {e}");
            ExitCode::FAILURE
        }
    }
}
