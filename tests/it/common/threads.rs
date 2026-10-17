use std::fs::File;
use std::os::unix::fs::FileExt;

/// The `stat` files of the threads whose name starts with one of `prefixes`,
/// opened now, so they can be read when no descriptors are left.
pub fn stats(prefixes: &[&str]) -> Vec<(String, File)> {
    let mut files = Vec::new();
    for entry in std::fs::read_dir("/proc/self/task").unwrap() {
        let dir = entry.unwrap().path();
        let comm = std::fs::read_to_string(dir.join("comm")).unwrap_or_default();
        let comm = comm.trim_end().to_owned();
        if prefixes.iter().any(|p| comm.starts_with(p)) {
            files.push((comm, File::open(dir.join("stat")).unwrap()));
        }
    }
    files
}

/// CPU time each thread has used so far, in clock ticks.
pub fn ticks(stats: &[(String, File)]) -> Vec<(String, u64)> {
    stats
        .iter()
        .map(|(name, file)| {
            let mut buf = [0u8; 1024];
            let n = file.read_at(&mut buf, 0).unwrap();
            let stat = std::str::from_utf8(&buf[..n]).unwrap();
            // Fields after the ")" that ends the name: state is field 3,
            // utime and stime are fields 14 and 15.
            let rest = &stat[stat.rfind(')').unwrap() + 2..];
            let fields: Vec<&str> = rest.split(' ').collect();
            (
                name.clone(),
                fields[11].parse::<u64>().unwrap() + fields[12].parse::<u64>().unwrap(),
            )
        })
        .collect()
}
