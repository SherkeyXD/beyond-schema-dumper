use anyhow::{bail, Context, Result};
use beyond_schema_dumper::reg::LocateOptions;
use beyond_schema_dumper::{
    export_bundle, locate_metadata_registration, write_bundle, ExportFormat, Metadata, PeImage,
};
use clap::{Parser, Subcommand};
use std::path::{Path, PathBuf};

#[derive(Parser, Debug)]
#[command(
    name = "beyond-schema-dumper",
    version,
    about = "Dumps MemoryPack schema of beyond game from global-metadata.dat and GameAssembly.dll",
    disable_help_subcommand = true
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
#[command(disable_help_subcommand = true)]
enum Cmd {
    /// Write schemas, type_index, union-map, unmanaged, enums, type.cs, README.md
    Export {
        /// global-metadata.dat path
        #[arg(long)]
        metadata: Option<PathBuf>,
        /// Windows GameAssembly.dll path
        #[arg(long)]
        gameassembly: Option<PathBuf>,
        /// Game root or handoff folder
        #[arg(long)]
        game_root: Option<PathBuf>,
        /// Output directory
        #[arg(long, default_value = "out/memorypack")]
        out: PathBuf,
        /// Export format: json (default) or messagepack (msgpack, with lz4 compression)
        #[arg(long, value_enum, default_value_t = ExportFormat::Json)]
        format: ExportFormat,
        /// Scan .rdata instead of using known MetadataRegistration RVA
        #[arg(long, default_value_t = false)]
        scan: bool,
        /// Verbose diagnostic output
        #[arg(short, long, default_value_t = false)]
        verbose: bool,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Export {
            metadata,
            gameassembly,
            game_root,
            out,
            format,
            scan,
            verbose,
        } => cmd_export(
            metadata,
            gameassembly,
            game_root,
            out,
            format,
            scan,
            verbose,
        ),
    }
}

fn cmd_export(
    metadata: Option<PathBuf>,
    gameassembly: Option<PathBuf>,
    game_root: Option<PathBuf>,
    out: PathBuf,
    format: ExportFormat,
    scan: bool,
    verbose: bool,
) -> Result<()> {
    let start_time = std::time::Instant::now();
    let (metadata, gameassembly) = resolve_inputs(metadata, gameassembly, game_root)?;
    if verbose {
        eprintln!("input metadata     : {}", metadata.display());
        eprintln!("input gameassembly : {}", gameassembly.display());
        eprintln!("output directory   : {}", out.display());
        eprintln!("output format      : {:?}", format);
    } else {
        eprintln!("metadata     {}", metadata.display());
        eprintln!("gameassembly {}", gameassembly.display());
    }

    let meta = Metadata::from_path(&metadata)
        .with_context(|| format!("load metadata {}", metadata.display()))?;
    if verbose {
        eprintln!("loaded metadata: {} type definitions", meta.type_defs.len());
    }

    let pe = PeImage::from_path(&gameassembly)
        .with_context(|| format!("load GameAssembly {}", gameassembly.display()))?;
    if verbose {
        eprintln!(
            "loaded PE image: {} sections, image base {:#x}",
            pe.sections.len(),
            pe.image_base
        );
    }

    let located = locate_metadata_registration(
        &pe,
        meta.type_defs.len() as u64,
        &LocateOptions {
            force_scan: scan,
            ..Default::default()
        },
    )?;
    eprintln!(
        "located MetadataRegistration at VA {:#x} (source: {})",
        located.reg.va, located.source
    );

    let bundle = export_bundle(&meta, &pe, &located.reg, located.source)
        .context("export schemas and type index")?;
    let files = write_bundle(&bundle, &out, format).context("write output files")?;

    println!(
        "wrote {} wrappers ({} files) to {} in {:.2?}",
        bundle.schemas.wrappers.len(),
        files.len(),
        out.display(),
        start_time.elapsed()
    );
    Ok(())
}

fn resolve_inputs(
    metadata: Option<PathBuf>,
    gameassembly: Option<PathBuf>,
    game_root: Option<PathBuf>,
) -> Result<(PathBuf, PathBuf)> {
    let mut metadata = metadata;
    let mut gameassembly = gameassembly;
    if let Some(root) = &game_root {
        if metadata.is_none() {
            metadata = Some(find_metadata(root)?);
        }
        if gameassembly.is_none() {
            gameassembly = Some(find_gameassembly(root)?);
        }
    }
    match (metadata, gameassembly) {
        (Some(m), Some(g)) => Ok((m, g)),
        _ => bail!("need --metadata and --gameassembly, or --game-root pointing at a game install"),
    }
}

fn find_gameassembly(root: &Path) -> Result<PathBuf> {
    for rel in ["GameAssembly.dll", "game/GameAssembly.dll"] {
        let dll = root.join(rel);
        if dll.is_file() {
            return Ok(dll);
        }
    }
    let so = root.join("GameAssembly.so");
    if so.is_file() {
        bail!(
            "found {} but this tool reads the Windows PE64 GameAssembly.dll",
            so.display()
        );
    }
    bail!(
        "GameAssembly.dll not found in {} (looked in . and game/)",
        root.display()
    );
}

fn find_metadata(root: &Path) -> Result<PathBuf> {
    let mut hits = Vec::new();
    for rel in [
        "Metadata/global-metadata.dat",
        "global-metadata.dat",
        "game/Metadata/global-metadata.dat",
    ] {
        let candidate = root.join(rel);
        if candidate.is_file() {
            hits.push(candidate);
        }
    }
    if let Ok(data_root) = root.read_dir() {
        for ent in data_root.flatten() {
            let name = ent.file_name();
            let name = name.to_string_lossy();
            if !name.ends_with("_Data") {
                continue;
            }
            let candidate = ent.path().join("il2cpp_data/Metadata/global-metadata.dat");
            if candidate.is_file() {
                hits.push(candidate);
            }
        }
    }
    hits.sort();
    hits.dedup();
    if hits.len() == 1 {
        return Ok(hits.remove(0));
    }
    if hits.len() > 1 {
        bail!(
            "several global-metadata.dat files under {}; pass --metadata",
            root.display()
        );
    }
    bail!(
        "global-metadata.dat not found under {} (expected *_Data/il2cpp_data/Metadata/, Metadata/, or game/Metadata/)",
        root.display()
    );
}
