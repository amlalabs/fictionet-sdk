//! Offline inference and enrollment; never opens network sockets.

use std::fs::File;
use std::io::{self, BufReader, BufWriter, Write};

use honeypot_world::inference::{Enrollment, Trace, infer};

fn trace(path: &str) -> io::Result<Trace> {
    Trace::read(BufReader::new(File::open(path)?))
}

fn artifact(path: &str) -> Result<Enrollment, Box<dyn std::error::Error + Send + Sync>> {
    let enrollment: Enrollment = serde_json::from_reader(BufReader::new(File::open(path)?))?;
    enrollment.validate()?;
    Ok(enrollment)
}

fn save(
    path: &str,
    enrollment: &Enrollment,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut output = BufWriter::new(File::create(path)?);
    serde_json::to_writer_pretty(&mut output, enrollment)?;
    output.flush()?;
    Ok(())
}

fn labeled(
    args: &[String],
) -> Result<Vec<(String, Trace)>, Box<dyn std::error::Error + Send + Sync>> {
    args.iter()
        .map(|arg| {
            let (label, path) = arg
                .split_once('=')
                .ok_or("training input must be LABEL=PATH")?;
            Ok((label.to_owned(), trace(path)?))
        })
        .collect()
}

pub fn run(args: &[String]) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    match args {
        [command, input, directory] if command == "split" => {
            let groups = Trace::read_grouped(BufReader::new(File::open(input)?))?;
            std::fs::create_dir_all(directory)?;
            for (index, (key, trace)) in groups.into_iter().enumerate() {
                let path = std::path::Path::new(directory).join(format!("trace-{:04}.jsonl",index+1));
                let mut output = BufWriter::new(std::fs::OpenOptions::new().write(true).create_new(true).open(&path)?);
                for (gate, provenance) in trace.gates.iter().zip(&trace.provenance) {
                    serde_json::to_writer(&mut output, &serde_json::json!({
                        "run_id":provenance.run_id,
                        "event":{"event":"trap","session":provenance.session,"src":provenance.src,
                            "dst":provenance.dst,"at_us":provenance.at_us,"trap":gate}
                    }))?;
                    output.write_all(b"\n")?;
                }
                output.flush()?;
                println!("{}",serde_json::json!({"path":path,"trace":key}));
            }
        }
        [command, output, inputs @ ..] if command == "fit" && !inputs.is_empty() => {
            let enrollment = Enrollment::fit(&labeled(inputs)?)?;
            save(output, &enrollment)?;
        }
        [command, input, output, inputs @ ..] if command == "enroll" && !inputs.is_empty() => {
            let mut enrollment = artifact(input)?;
            for (label, trace) in labeled(inputs)? { enrollment.enroll(&label, &trace)?; }
            save(output, &enrollment)?;
        }
        [command, enrollment, input] if command == "classify" => {
            let enrollment = if enrollment == "-" { None } else { Some(artifact(enrollment)?) };
            serde_json::to_writer_pretty(io::stdout().lock(), &infer(&trace(input)?, enrollment.as_ref())?)?;
        }
        [command, enrollment, input] if command == "fingerprint" => {
            let enrollment = artifact(enrollment)?;
            serde_json::to_writer_pretty(io::stdout().lock(), &serde_json::json!({
                "format": enrollment.format,
                "dimensions": enrollment.vocabulary.len(),
                    "vocabulary": enrollment.vocabulary,
                    "idf": enrollment.idf,
                    "fitted_inputs": enrollment.fitted_inputs,
                "vector": enrollment.fingerprint(&trace(input)?)?
            }))?;
        }
        _ => return Err("usage: cargo run -p xtask --features shibboleth -- shibboleth-infer split EVIDENCE DIRECTORY | fit OUTPUT LABEL=TRACE... | enroll INPUT OUTPUT LABEL=TRACE... | classify ARTIFACT_OR_DASH TRACE | fingerprint ARTIFACT TRACE".into()),
    }
    Ok(())
}
