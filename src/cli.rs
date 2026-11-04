use crate::constants::{DEFAULT_MAX_ARCHIVE_MIB, DEFAULT_MAX_SIZE_MIB};
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
name = "folder2json",
author = "luisek03",
version,
about = "Lossless folder archiving into self-contained, AI-optimized JSON.",
long_about = "folder2json - High-performance CLI utility to pack and unpack directory trees.\n\n\
Designed for LLM context injection, shell pipelines (Stdin/Stdout), and bit-exact\n\
source code archiving with SHA-256 integrity checks, O(1) RAM streaming, and hardening\n\
against path traversal, chained symlink escapes, and decompression bombs."
)]
pub struct Cli {
    #[command(subcommand)]
    pub cmd: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Pack a folder into a JSON archive (use '-' for stdout)
    #[command(
    name = "pack",
    about = "Packs a directory structure losslessly into a JSON document",
    long_about = "Packs all files, POSIX permissions, and symlinks of a directory tree into a single JSON file.\n\
Plaintext files are embedded as raw UTF-8, binary files are streamed through Zstandard compression\n\
and Base64 encoding. Supports content deduplication and SHA-256 integrity checks.\n\n\
EXAMPLES:\n  \
folder2json pack ./my-project archive.json\n  \
folder2json pack ./my-project - | xz > archive.json.xz\n  \
folder2json pack ./src output.json -a -e target -e '*.log'\n  \
folder2json pack ./data archive.json --no-compress --no-dedup"
    )]
    Pack {
        /// Source directory to pack
        #[arg(value_name = "SRC")]
        src: PathBuf,

        /// Destination path for the JSON archive, or '-' for stdout
        #[arg(value_name = "OUT")]
        out: String,

        /// Include hidden files and hidden directories (.*) (ignored by default)
        #[arg(short = 'a', long = "all")]
        all: bool,

        /// Exclude patterns (can be repeated, e.g. -e "*.log" -e ".git" -e "target")
        #[arg(short = 'e', long = "exclude", value_name = "PATTERN")]
        exclude: Vec<String>,

        /// Disable file deduplication (files are still hashed for integrity)
        #[arg(long = "no-dedup")]
        no_dedup: bool,

        /// Disable Zstandard compression for binary files (forces plain base64)
        #[arg(long = "no-compress")]
        no_compress: bool,

        /// Verbose output showing each processed entry and deduplication links
        #[arg(short = 'v', long = "verbose")]
        verbose: bool,
    },

    /// Unpack a JSON archive back into a folder (use '-' for stdin)
    #[command(
    name = "unpack",
    about = "Restores directory trees from a JSON archive",
    long_about = "Reads an archive created by folder2json and reconstructs directory hierarchy,\n\
file contents, POSIX permissions, and symlinks bit-exactly.\n\
Validates 16-character SHA-256 hashes prior to moving files into place and enforces\n\
strict scope validation against path traversal (../, ~/, /) and chained symlink escapes.\n\n\
EXAMPLES:\n  \
folder2json unpack archive.json ./restored\n  \
folder2json unpack archive.json ./restored --force\n  \
xz -dc archive.json.xz | folder2json unpack - ./restored\n  \
folder2json unpack archive.json ./restored --no-verify --max-size-mib 1024"
    )]
    Unpack {
        /// Path to the JSON archive, or '-' to read from stdin
        #[arg(value_name = "IN_JSON")]
        in_json: String,

        /// Target directory where files should be extracted
        #[arg(value_name = "DST")]
        dst: PathBuf,

        /// Overwrite existing files in destination directory (protected by default)
        #[arg(short = 'f', long = "force")]
        force: bool,

            /// Skip SHA-256 cryptographic integrity verification (use with trusted archives only)
            #[arg(long = "no-verify")]
            no_verify: bool,

            /// Allow symlinks pointing outside the destination folder (blocked by default)
            #[arg(long = "allow-external-symlinks")]
            allow_external_symlinks: bool,

            /// Maximum decompressed size per file in MiB (decompression bomb protection)
            #[arg(long = "max-size-mib", default_value_t = DEFAULT_MAX_SIZE_MIB, value_name = "MIB")]
            max_size_mib: u64,

            /// Maximum allowed size for the input JSON archive in MiB
            #[arg(long = "max-archive-mib", default_value_t = DEFAULT_MAX_ARCHIVE_MIB, value_name = "MIB")]
            max_archive_mib: u64,

            /// Verbose output showing each extracted or linked file
            #[arg(short = 'v', long = "verbose")]
            verbose: bool,
    },
}
