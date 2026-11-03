use crate::constants::{DEFAULT_MAX_ARCHIVE_MIB, DEFAULT_MAX_SIZE_MIB};
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
name = "folder2json",
author = "luisek03",
version,
about = "Lossless folder archiving into self-contained, AI-optimized JSON.",
long_about = "A high-performance CLI utility to pack and unpack directory trees into JSON format.\n\
Designed for LLM context injection, shell pipelines (Stdin/Stdout), and source code\n\
archiving with SHA-256 integrity checks, O(1) RAM payload streaming, and\n\
strict path-traversal / symlink-escape / per-file decompression-bomb protection."
)]
pub struct Cli {
    #[command(subcommand)]
    pub cmd: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Pack a folder into a JSON archive (use '-' for stdout)
    #[command(
    long_about = "Packs all files, permissions, and symlinks of a directory tree into a single JSON file.\n\
Outputs raw UTF-8 for plaintext files, and streamed zstd+base64 for binary files.\n\
Supports deduplication, automatic integrity hashing, and UNIX permission retention.\n\n\
EXAMPLES:\n  \
folder2json pack ./my-project archive.json\n  \
folder2json pack ./my-project - | xz > archive.json.xz\n  \
folder2json pack ./src output.json -a -e target -e '*.log'"
    )]
    Pack {
        /// Source directory to pack
        src: PathBuf,

        /// Destination JSON archive path, or '-' to stream directly to stdout
        out: String,

        /// Include hidden files and hidden directories (.*) (ignored by default)
        #[arg(short = 'a', long = "all")]
        all: bool,

        /// Exclude patterns (can be repeated, e.g. -e "*.log" -e ".git" -e "target")
        #[arg(short = 'e', long = "exclude")]
        exclude: Vec<String>,

        /// Disable file deduplication (content is still hashed with SHA-256 for integrity)
        #[arg(long = "no-dedup")]
        no_dedup: bool,

        /// Disable binary payload compression in the encoding pipeline (forces plain base64)
        #[arg(long = "no-compress")]
        no_compress: bool,

        /// Verbose output showing each processed entry and deduplication links
        #[arg(short = 'v', long = "verbose")]
        verbose: bool,
    },

    /// Unpack a JSON archive back into a folder (use '-' for stdin)
    #[command(
    long_about = "Restores a directory tree from a JSON archive created by this tool.\n\
Reconstructs file hierarchy, streams payloads to disk, recreates symlinks,\n\
restores POSIX permissions, and validates 16-character SHA-256 checksums.\n\
Enforces strict scope validation against path traversal (../, ~/, /) and chained symlink escapes.\n\n\
EXAMPLES:\n  \
folder2json unpack archive.json ./restored\n  \
xz -dc archive.json.xz | folder2json unpack - ./restored\n  \
folder2json unpack archive.json ./restored --force --no-verify"
    )]
    Unpack {
        /// Input JSON archive path, or '-' to read directly from stdin
        in_json: String,

        /// Target folder where files should be extracted
        dst: PathBuf,

        /// Overwrite existing files in the target directory (blocked by default)
        #[arg(short = 'f', long = "force")]
        force: bool,

            /// Skip 16-char SHA-256 integrity checks
            #[arg(long = "no-verify")]
            no_verify: bool,

            /// Allow symlinks whose target points outside the destination directory (blocked by default)
            #[arg(long = "allow-external-symlinks")]
            allow_external_symlinks: bool,

            /// Maximum allowed decompressed size per file in MiB (protects against zstd bombs)
            #[arg(long = "max-size-mib", default_value_t = DEFAULT_MAX_SIZE_MIB)]
            max_size_mib: u64,

            /// Maximum allowed input JSON archive size in MiB (protects against unbounded stdin OOM)
            #[arg(long = "max-archive-mib", default_value_t = DEFAULT_MAX_ARCHIVE_MIB)]
            max_archive_mib: u64,

            /// Verbose output showing each extracted or linked file
            #[arg(short = 'v', long = "verbose")]
            verbose: bool,
    },
}
