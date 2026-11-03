use crate::constants::{DEFAULT_MAX_ARCHIVE_MIB, DEFAULT_MAX_SIZE_MIB};
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
name = "folder2json",
author = "luisek03",
version,
about = "Verlustfreies Ordner-Archivieren in selbstentpackendes, KI-optimiertes JSON.",
long_about = "folder2json - Hochperformantes CLI-Werkzeug zum Packen und Entpacken von Ordnerstrukturen.\n\n\
Entwickelt für LLM-Kontextinjektion, Shell-Pipelines (Stdin/Stdout) und bitgenaue\n\
Quellcode-Archivierung mit SHA-256-Prüfsummen, O(1)-RAM-Streaming sowie Härtung\n\
gegen Path-Traversal, Symlink-Escapes und Zstd-Dekompressionsbomben."
)]
pub struct Cli {
    #[command(subcommand)]
    pub cmd: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Packt einen Ordner in ein JSON-Archiv (nutze '-' für Stdout)
    #[command(
    name = "pack",
    about = "Packt Verzeichnisse verlustfrei in ein JSON-Dokument",
    long_about = "Packt alle Dateien, POSIX-Berechtigungen und Symlinks eines Verzeichnisbaums in ein JSON-Dokument.\n\
Klartextdateien werden als UTF-8 eingebettet, Binärdateien gestreamt über Zstandard komprimiert\n\
und Base64-kodiert. Unterstützt Inhalts-Deduplizierung und SHA-256-Integritäts-Hashes.\n\n\
BEISPIELE:\n  \
folder2json pack ./mein-projekt archiv.json\n  \
folder2json pack ./mein-projekt - | xz > archiv.json.xz\n  \
folder2json pack ./src output.json -a -e target -e '*.log'\n  \
folder2json pack ./daten archiv.json --no-compress --no-dedup"
    )]
    Pack {
        /// Quellordner, der gepackt werden soll
        #[arg(value_name = "SRC")]
        src: PathBuf,

        /// Zielpfad für das JSON-Archiv oder '-' für direkte Stdout-Ausgabe
        #[arg(value_name = "OUT")]
        out: String,

        /// Versteckte Dateien und Ordner (.*) mit einbeziehen (standardmäßig ignoriert)
        #[arg(short = 'a', long = "all")]
        all: bool,

        /// Ausschluss-Muster (wiederholbar, z. B. -e "*.log" -e ".git" -e "target")
        #[arg(short = 'e', long = "exclude", value_name = "PATTERN")]
        exclude: Vec<String>,

        /// Inhalts-Deduplizierung deaktivieren (Dateien werden dennoch gehasht)
        #[arg(long = "no-dedup")]
        no_dedup: bool,

        /// Zstandard-Kompression für Binärdateien deaktivieren (erzwingt reines Base64)
        #[arg(long = "no-compress")]
        no_compress: bool,

        /// Ausführliche Ausgabe aller verarbeiteten Dateien und Deduplizierungs-Links
        #[arg(short = 'v', long = "verbose")]
        verbose: bool,
    },

    /// Entpackt ein JSON-Archiv zurück in einen Ordner (nutze '-' für Stdin)
    #[command(
    name = "unpack",
    about = "Stellt Verzeichnisbäume aus einem JSON-Archiv wieder her",
    long_about = "Liest ein von folder2json erstelltes Archiv und stellt die Verzeichnisstruktur,\n\
Dateiinhalte, POSIX-Rechte und Symlinks bitgenau wieder her.\n\
Prüft 16-stellige SHA-256-Hashes vor dem Schreiben und erzwingt strenge Scope-Prüfungen\n\
gegen Path-Traversal (../, ~/, /) und mehrstufige Symlink-Ketten-Escapes.\n\n\
BEISPIELE:\n  \
folder2json unpack archiv.json ./zielordner\n  \
folder2json unpack archiv.json ./zielordner --force\n  \
xz -dc archiv.json.xz | folder2json unpack - ./zielordner\n  \
folder2json unpack archiv.json ./zielordner --no-verify --max-size-mib 1024"
    )]
    Unpack {
        /// Pfad zum JSON-Archiv oder '-' zum Einlesen über Stdin
        #[arg(value_name = "IN_JSON")]
        in_json: String,

        /// Zielverzeichnis, in das entpackt werden soll
        #[arg(value_name = "DST")]
        dst: PathBuf,

        /// Bereits existierende Dateien im Zielordner überschreiben (standardmäßig geschützt)
        #[arg(short = 'f', long = "force")]
        force: bool,

            /// SHA-256-Integritätsprüfungen überspringen (nur bei vertrauenswürdigen Quellen)
            #[arg(long = "no-verify")]
            no_verify: bool,

            /// Erlaubt Symlinks, deren Ziel außerhalb des Zielordners liegt (standardmäßig blockiert)
            #[arg(long = "allow-external-symlinks")]
            allow_external_symlinks: bool,

            /// Maximal erlaubte entpackte Größe pro Datei in MiB (Schutz vor Dekompressionsbomben)
            #[arg(long = "max-size-mib", default_value_t = DEFAULT_MAX_SIZE_MIB, value_name = "MIB")]
            max_size_mib: u64,

            /// Maximal erlaubte Gesamtgröße des Eingabe-JSON-Archivs in MiB
            #[arg(long = "max-archive-mib", default_value_t = DEFAULT_MAX_ARCHIVE_MIB, value_name = "MIB")]
            max_archive_mib: u64,

            /// Ausführliche Ausgabe aller entpackten und wiederhergestellten Dateien
            #[arg(short = 'v', long = "verbose")]
            verbose: bool,
    },
}
