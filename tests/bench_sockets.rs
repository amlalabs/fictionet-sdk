#[path = "../benches/support/socket_path.rs"]
mod socket_path;

#[test]
fn benchmark_sockets_use_the_temporary_directory() {
    let first = socket_path::socket_path("test");
    let second = socket_path::socket_path("test");
    assert_eq!(
        first.parent().unwrap(),
        std::env::temp_dir().join("fictionet-bench-sockets")
    );
    assert_ne!(first, second);
    assert!(first.parent().unwrap().is_dir());
}
