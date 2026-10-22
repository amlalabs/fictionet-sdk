//! Cloud-init filesystem bytes preserve the guest's installed files.

use fictionet_demo::kit::{Guest, seed};
use std::io::Read;

#[test]
fn cloud_init_image_carries_guest_files() {
    let content = "First line.\nSecond line: <>&'\"\n";
    let guest = Guest::ubuntu("station", "analyst").file("/home/analyst/note.txt", 0o600, content);
    let image = seed::build(&seed::Provision {
        guest: &guest,
        authorized_key: "key",
        ca: None,
    })
    .unwrap();
    let fs = fatfs::FileSystem::new(std::io::Cursor::new(image), fatfs::FsOptions::new()).unwrap();
    assert!(fs.volume_label().trim().eq_ignore_ascii_case("cidata"));
    let root = fs.root_dir();
    root.open_file("meta-data").unwrap();
    let mut data = String::new();
    root.open_file("user-data")
        .unwrap()
        .read_to_string(&mut data)
        .unwrap();
    assert_eq!(
        seed::files(&data).unwrap()["/home/analyst/note.txt"],
        content
    );
}
