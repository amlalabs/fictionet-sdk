//! Build the ngtcp2 peer against the system's ngtcp2, nghttp3 and OpenSSL.

const LIBRARIES: [&str; 5] = [
    "libngtcp2",
    "libngtcp2_crypto_ossl",
    "libnghttp3",
    "libssl",
    "libcrypto",
];

fn probe(library: &str, link: bool) -> pkg_config::Library {
    pkg_config::Config::new()
        .cargo_metadata(link)
        .probe(library)
        .unwrap_or_else(|error| panic!("{library} is required for the ngtcp2 peer: {error}"))
}

fn main() {
    println!("cargo:rerun-if-changed=peer.c");
    if std::env::var("CARGO_CFG_TARGET_ARCH").as_deref() == Ok("wasm32") {
        return;
    }
    let mut build = cc::Build::new();
    for library in LIBRARIES {
        build.includes(probe(library, false).include_paths);
    }
    build
        .file("peer.c")
        .std("c11")
        .define("_DEFAULT_SOURCE", None)
        .warnings_into_errors(true)
        .compile("fictionet_ngtcp2_peer");
    // The libraries follow the peer on the link line, which needs them.
    for library in LIBRARIES {
        probe(library, true);
    }
}
