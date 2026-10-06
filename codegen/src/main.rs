//! Command line entry point for fictionet-codegen.
use fictionet_codegen::{
    Error, ErrorKind, FORMATS, Input, Limits, MAX_INPUT, MAX_TYPES, emit, emit_fuzz, validate,
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
    let front = FORMATS
        .iter()
        .find(|f| f.name() == format)
        .ok_or_else(|| error(ErrorKind::UnknownFormat, "format", format))?;
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
    let mut inputs = Vec::new();
    let mut total = 0usize;
    for path in paths {
        if absolute(&path)? == absolute(&output)? || fuzz.as_ref().is_some_and(|f| f == &path) {
            return Err(error(
                ErrorKind::Cli,
                "output",
                "output must differ from inputs",
            ));
        }
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
    let checked = validate(front.parse(&inputs, limits)?, limits)?;
    let names = inputs.iter().map(|i| i.name.clone()).collect::<Vec<_>>();
    let source = emit(&checked, &names)?;
    let fuzz_source = fuzz
        .as_ref()
        .map(|p| {
            if absolute(p)? == absolute(&output)? {
                return Err(error(
                    ErrorKind::Cli,
                    "--fuzz",
                    "target must differ from module",
                ));
            }
            emit_fuzz(&checked, &relative_module(&output, p)?, &names)
        })
        .transpose()?;
    std::fs::write(&output, source).map_err(|e| io_error(&output, e))?;
    if let (Some(path), Some(source)) = (fuzz, fuzz_source) {
        std::fs::write(&path, source).map_err(|e| io_error(&path, e))?;
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
