use cbindgen::Config;
use std::env;

fn main() {
    let crate_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let crate_dir = std::path::Path::new(&crate_dir);

    let header_file = env::var("HEADER_FILE").unwrap();
    let cbindgen_config = env::var("CBINDGEN_CONFIG").unwrap();

    cbindgen::Builder::new()
        .with_crate(crate_dir)
        .with_config(Config::from_file(cbindgen_config).expect("Parsing config failed"))
        .generate()
        .expect("Unable to generate bindings")
        .write_to_file(header_file);
}
