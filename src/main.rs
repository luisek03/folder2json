mod cli;
mod constants;
mod glob;
mod pack;
mod security;
mod stream;
mod unpack;

use clap::Parser;
use cli::{Cli, Commands};
use constants::fmt_size;
use std::process;

fn main() {
    let cli = Cli::parse();

    match cli.cmd {
        Commands::Pack {
            src,
            out,
            all,
            exclude,
            no_dedup,
            no_compress,
            verbose,
        } => {
            let mut excludes: Vec<String> = Vec::new();
            if !all {
                excludes.push(".*".to_string());
            }
            excludes.extend(exclude);
            let dedup = !no_dedup;

            match pack::pack(&src, &out, &excludes, verbose, dedup, no_compress) {
                Ok((file_len, excluded, stats)) => {
                    if out != "-" {
                        println!("Gepackt: {} Dateien → {}", file_len, out);
                        if dedup {
                            println!(
                                "  Unique: {}, verlinkt: {} ({} gespart)",
                                     stats.unique,
                                     stats.linked,
                                     fmt_size(stats.bytes_saved)
                            );
                        } else {
                            println!("  Dedup deaktiviert (16-Char-Hashes dennoch erzeugt)");
                        }
                        if !excluded.is_empty() {
                            println!("  {} Einträge ausgeschlossen", excluded.len());
                        }
                    }
                }
                Err(e) => {
                    eprintln!("{}", e);
                    process::exit(1);
                }
            }
        }
        Commands::Unpack {
            in_json,
            dst,
            force,
                no_verify,
                allow_external_symlinks,
                max_size_mib,
                max_archive_mib,
                verbose,
        } => match unpack::unpack(
            &in_json,
            &dst,
            force,
                verbose,
                no_verify,
                allow_external_symlinks,
                max_size_mib,
                max_archive_mib,
        ) {
            Ok((files, links, failures)) => {
                println!(
                    "\n✅ Entpackt: {} Dateien → {} (davon {} Links aufgelöst)",
                         files,
                         dst.display(),
                         links
                );

                if !failures.is_empty() {
                    eprintln!(
                        "\n⚠️  WARNUNG: {} Datei(en) konnten nicht entpackt werden (manipuliert/fehlerhaft):",
                              failures.len()
                    );
                    for f in &failures {
                        eprintln!("  - {}", f);
                    }
                    process::exit(1);
                }
            }
            Err(e) => {
                eprintln!("\n🚨 KRITISCHER FEHLER: {}", e);
                process::exit(1);
            }
        },
    }
}
