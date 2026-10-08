//! The README shows the code in `docs/readme/sites.rs`, which a doctest
//! in the crate root compiles. This checks that the two stay the same.

#[test]
fn the_readme_shows_the_compiled_example() {
    let readme = include_str!("../README.md");
    let code = include_str!("../docs/readme/sites.rs");
    let block = format!("```rust\n{code}```\n");
    assert!(
        readme.contains(&block),
        "README.md must show docs/readme/sites.rs, as written, in a ```rust block"
    );
}
