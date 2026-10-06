//! Command line entry point for fictionet-codegen.
use fictionet_codegen::{
    Error, ErrorKind, FORMATS, Input, Limits, MAX_INPUT, MAX_TYPES, emit_fuzz, generate,
};
use std::{
    io::{Read, Write},
    path::{Component, Path, PathBuf},
};

const HELP: &str = "fictionet-codegen <format> <input...> -o <file.rs> [options]
fictionet-codegen --format <format> <input...> -o <file.rs>
fictionet-codegen --list

Generate once, then copy and edit the file. Regenerate only by choice.

Options:
  --max-message <bytes>     Maximum encoded value (default 1048576)
  --max-collection <count>  Default collection or data length (default 4096)
  --max-depth <count>       Maximum value nesting (default 32, maximum 64)
  --max-allocation <bytes>  Decoded heap budget (default 8388608)
  --max-nodes <count>       Structural work budget (default 65536)
  --fuzz <target.rs>        Also write a cargo-fuzz target
  --list                   List registered formats
  --help                   Show this help
";
fn error(kind: ErrorKind, location: &str, message: impl Into<String>) -> Error {
    Error {
        kind,
        location: location.into(),
        message: message.into(),
    }
}
fn io_error(path: &Path, e: std::io::Error) -> Error {
    error(ErrorKind::Io, &path.display().to_string(), e.to_string())
}
fn argument(args: &mut impl Iterator<Item = String>, flag: &str) -> Result<String, Error> {
    args.next()
        .ok_or_else(|| error(ErrorKind::Cli, flag, "missing argument"))
}
fn absolute(path: &Path) -> Result<PathBuf, Error> {
    let path = if path.is_absolute() {
        path.to_owned()
    } else {
        std::env::current_dir()
            .map_err(|e| io_error(path, e))?
            .join(path)
    };
    let mut clean = PathBuf::new();
    for c in path.components() {
        match c {
            Component::CurDir => {}
            Component::ParentDir => {
                clean.pop();
            }
            _ => clean.push(c),
        }
    }
    Ok(clean)
}
fn relative_module(module: &Path, target: &Path) -> Result<String, Error> {
    let module = absolute(module)?;
    let target = absolute(target)?;
    let parent = target
        .parent()
        .ok_or_else(|| error(ErrorKind::Cli, "--fuzz", "target has no parent"))?;
    let a: Vec<_> = module.components().collect();
    let b: Vec<_> = parent.components().collect();
    let common = a.iter().zip(&b).take_while(|(a, b)| a == b).count();
    let mut result = PathBuf::new();
    for _ in common..b.len() {
        result.push("..");
    }
    for c in a.iter().skip(common) {
        result.push(c.as_os_str());
    }
    result
        .to_str()
        .map(str::to_owned)
        .ok_or_else(|| error(ErrorKind::Cli, "--fuzz", "paths must be UTF-8"))
}

struct FileIdentity {
    absolute: PathBuf,
    resolved: PathBuf,
    metadata: Option<std::fs::Metadata>,
}
impl FileIdentity {
    fn new(path: &Path) -> Result<Self, Error> {
        fn resolve(path: &Path) -> Result<PathBuf, Error> {
            match std::fs::canonicalize(path) {
                Ok(path) => Ok(path),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    let parent = path
                        .parent()
                        .filter(|p| !p.as_os_str().is_empty())
                        .unwrap_or(Path::new("."));
                    match path.file_name() {
                        Some(name) => Ok(resolve(parent)?.join(name)),
                        None => Err(io_error(path, e)),
                    }
                }
                Err(e) => Err(io_error(path, e)),
            }
        }
        let metadata = match std::fs::metadata(path) {
            Ok(m) => Some(m),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => return Err(io_error(path, e)),
        };
        Ok(Self {
            absolute: absolute(path)?,
            resolved: resolve(path)?,
            metadata,
        })
    }
    fn same(&self, other: &Self) -> bool {
        if self.absolute == other.absolute || self.resolved == other.resolved {
            return true;
        }
        #[cfg(unix)]
        if let (Some(a), Some(b)) = (&self.metadata, &other.metadata) {
            use std::os::unix::fs::MetadataExt;
            return a.dev() == b.dev() && a.ino() == b.ino();
        }
        false
    }
}
fn check_paths(output: &Path, fuzz: Option<&Path>, inputs: &[PathBuf]) -> Result<(), Error> {
    let mut outputs = vec![FileIdentity::new(output)?];
    if let Some(fuzz) = fuzz {
        let target = FileIdentity::new(fuzz)?;
        if outputs[0].same(&target) {
            return Err(error(
                ErrorKind::Cli,
                "--fuzz",
                "target must differ from module",
            ));
        }
        outputs.push(target);
    }
    for input in inputs {
        let input = FileIdentity::new(input)?;
        if outputs.iter().any(|o| o.same(&input)) {
            return Err(error(
                ErrorKind::Cli,
                "output",
                "output must differ from inputs",
            ));
        }
    }
    for out in outputs {
        if out.metadata.as_ref().is_some_and(|m| !m.is_file()) {
            return Err(error(ErrorKind::Io, "output", "destination must be a file"));
        }
    }
    Ok(())
}

struct StagedFile {
    temporary: PathBuf,
    destination: PathBuf,
}
impl StagedFile {
    fn new(destination: &Path, source: &str) -> Result<Self, Error> {
        let parent = destination.parent().unwrap_or(Path::new("."));
        for id in 0..128 {
            let temporary = parent.join(format!(
                ".fictionet-codegen-{}-{id}.tmp",
                std::process::id()
            ));
            match std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&temporary)
            {
                Ok(mut file) => {
                    let staged = Self {
                        temporary,
                        destination: destination.into(),
                    };
                    file.write_all(source.as_bytes())
                        .map_err(|e| io_error(destination, e))?;
                    file.sync_all().map_err(|e| io_error(destination, e))?;
                    return Ok(staged);
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(io_error(destination, e)),
            }
        }
        Err(error(
            ErrorKind::Io,
            "output",
            "temporary file names are occupied",
        ))
    }
    fn finish(self) -> Result<(), Error> {
        std::fs::rename(&self.temporary, &self.destination)
            .map_err(|e| io_error(&self.destination, e))
    }
}
impl Drop for StagedFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.temporary);
    }
}
fn run() -> Result<(), Error> {
    let mut raw = Vec::new();
    let mut arg_bytes = 0usize;
    for arg in std::env::args_os().skip(1) {
        let arg = arg
            .into_string()
            .map_err(|_| error(ErrorKind::Cli, "arguments", "arguments must be UTF-8"))?;
        arg_bytes = arg_bytes
            .checked_add(arg.len())
            .ok_or_else(|| error(ErrorKind::InputLimit, "arguments", "too many bytes"))?;
        if arg_bytes > MAX_INPUT || raw.len() > MAX_TYPES + 32 {
            return Err(error(
                ErrorKind::InputLimit,
                "arguments",
                "too many arguments",
            ));
        }
        raw.push(arg);
    }
    let mut args = raw.into_iter();
    let mut format = None;
    let mut paths = Vec::new();
    let mut output = None;
    let mut fuzz = None;
    let mut limits = Limits::default();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--help" | "-h" => {
                std::io::stdout()
                    .lock()
                    .write_all(HELP.as_bytes())
                    .map_err(|e| error(ErrorKind::Io, "stdout", e.to_string()))?;
                return Ok(());
            }
            "--list" => {
                let mut stdout = std::io::stdout().lock();
                for f in FORMATS {
                    writeln!(stdout, "{}", f.name())
                        .map_err(|e| error(ErrorKind::Io, "stdout", e.to_string()))?;
                }
                return Ok(());
            }
            "--format" => {
                if format.is_some() {
                    return Err(error(ErrorKind::Cli, "--format", "format given twice"));
                }
                format = Some(argument(&mut args, &arg)?);
            }
            "-o" | "--output" => {
                if output.is_some() {
                    return Err(error(ErrorKind::Cli, "-o", "output given twice"));
                }
                output = Some(PathBuf::from(argument(&mut args, &arg)?));
            }
            "--fuzz" => {
                if fuzz.is_some() {
                    return Err(error(ErrorKind::Cli, "--fuzz", "target given twice"));
                }
                fuzz = Some(PathBuf::from(argument(&mut args, &arg)?));
            }
            "--max-message" | "--max-collection" | "--max-depth" | "--max-allocation"
            | "--max-nodes" => {
                let n = argument(&mut args, &arg)?
                    .parse()
                    .map_err(|_| error(ErrorKind::Cli, &arg, "expected nonnegative usize"))?;
                match arg.as_str() {
                    "--max-message" => limits.max_message = n,
                    "--max-collection" => limits.max_collection = n,
                    "--max-depth" => limits.max_depth = n,
                    "--max-allocation" => limits.max_allocation = n,
                    _ => limits.max_nodes = n,
                }
            }
            _ if arg.starts_with('-') => return Err(error(ErrorKind::Cli, &arg, "unknown option")),
            _ if format.is_none() => format = Some(arg),
            _ => paths.push(PathBuf::from(arg)),
        }
    }
    let format =
        format.ok_or_else(|| error(ErrorKind::Cli, "format", "missing format; use --list"))?;
    if !FORMATS.iter().any(|f| f.name() == format) {
        return Err(error(ErrorKind::UnknownFormat, "format", format));
    }
    let output = output.ok_or_else(|| error(ErrorKind::Cli, "-o", "output is required"))?;
    if paths.is_empty() {
        return Err(error(
            ErrorKind::Cli,
            "input",
            "at least one input is required",
        ));
    }
    if paths.len() > MAX_TYPES {
        return Err(error(ErrorKind::InputLimit, "input", "too many files"));
    }
    check_paths(&output, fuzz.as_deref(), &paths)?;
    let mut inputs = Vec::new();
    let mut total = 0usize;
    for path in paths {
        let mut bytes = Vec::new();
        std::fs::File::open(&path)
            .map_err(|e| io_error(&path, e))?
            .take((MAX_INPUT + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|e| io_error(&path, e))?;
        total = total
            .checked_add(bytes.len())
            .ok_or_else(|| error(ErrorKind::InputLimit, "input", "MAX_INPUT exceeded"))?;
        if total > MAX_INPUT {
            return Err(error(ErrorKind::InputLimit, "input", "MAX_INPUT exceeded"));
        }
        inputs.push(Input {
            name: path.display().to_string(),
            bytes,
        });
    }
    let generated = generate(&format, &inputs, limits)?;
    let names = inputs.iter().map(|i| i.name.clone()).collect::<Vec<_>>();
    let fuzz_source = fuzz
        .as_ref()
        .map(|p| emit_fuzz(&generated.schema, &relative_module(&output, p)?, &names))
        .transpose()?;
    let module = StagedFile::new(&output, &generated.source)?;
    let target = fuzz
        .as_ref()
        .zip(fuzz_source.as_ref())
        .map(|(path, source)| StagedFile::new(path, source))
        .transpose()?;
    module.finish()?;
    if let Some(target) = target {
        target.finish()?;
    }
    Ok(())
}
fn main() -> std::process::ExitCode {
    match run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            let _ = writeln!(std::io::stderr().lock(), "{e}");
            std::process::ExitCode::FAILURE
        }
    }
}
