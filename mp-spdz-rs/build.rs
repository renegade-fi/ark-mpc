use itertools::Itertools;

// Build entrypoint
fn main() {
    // Resolve the libsodium and gmp include paths
    let libsodium_include = find_include_path("libsodium");
    let gmp_include = find_include_path("gmp");
    let ntl_include = find_include_path("ntl");

    // Build the c++ bridge
    cxx_build::bridge("src/lib.rs")
        .file("src/include/MP-SPDZ/FHE/Ring.cpp")
        .file("src/include/MP-SPDZ/FHE/NTL-Subs.cpp")
        .file("src/include/MP-SPDZ/Math/bigint.cpp")
        .include("src/include/MP-SPDZ")
        .include("src/include/MP-SPDZ/deps")
        .include(libsodium_include)
        .include(gmp_include)
        .include(ntl_include)
        .define("USE_NTL", None)
        .std("c++17")
        .compile("mp-spdz-cxx");

    // Linker args
    println!("cargo:rustc-link-arg=-L{}", find_lib_path("ntl"));
    println!("cargo:rustc-link-arg=-lntl");
    println!("cargo:rustc-link-arg=-L{}", find_lib_path("gmp"));
    println!("cargo:rustc-link-arg=-lgmp");

    // Build cache flags
    println!("cargo:rerun-if-changed=src/lib.rs");
    println!("cargo:rerun-if-changed=../MP-SPDZ");
}

/// Get the vendor of the current host
fn get_host_vendor() -> String {
    let host_triple = get_host_triple();
    host_triple[1].to_string()
}

/// Get the host triple
fn get_host_triple() -> Vec<String> {
    let host_triple = std::env::var("HOST").unwrap();
    host_triple.split('-').map(|s| s.to_string()).collect_vec()
}

/// Find the include location for a package
fn find_include_path(name: &str) -> String {
    let base_path = find_package(name);
    format!("{base_path}/include")
}

/// Find the lib location for a package
fn find_lib_path(name: &str) -> String {
    let base_path = find_package(name);
    format!("{base_path}/lib")
}

/// Resolve a package's include location
///
/// Windows is not supported
fn find_package(name: &str) -> String {
    let vendor = get_host_vendor();
    if vendor == "apple" {
        find_package_macos(name)
    } else {
        find_package_linux(name)
    }
}

/// Find a package on macOS
///
/// For now we assume that the package is installed via `brew`
fn find_package_macos(name: &str) -> String {
    let output = std::process::Command::new("brew")
        .arg("--prefix")
        .arg(name)
        .output()
        .expect("error running `brew --prefix`");

    // Check for a `brew` error
    if !output.stderr.is_empty() {
        panic!(
            "\nPackage not found: {}\nTry running:\n\t `brew install {}`\n",
            parse_utf8(&output.stderr),
            name
        );
    }

    // Parse the output from stdout
    let path = parse_utf8(&output.stdout).trim().to_string();
    path
}

/// Find a package on Linux
fn find_package_linux(name: &str) -> String {
    let conf = pkg_config::Config::new().probe(name);
    match conf {
        Ok(lib) => lib.include_paths[0].to_str().unwrap().to_string(),
        Err(e) => {
            panic!(
                "Package not found: {}\nTry running:\n\t `{{apt-get, yum}} install {}`\n",
                e, name
            )
        },
    }
}

/// Parse a utf8 string from a byte array
fn parse_utf8(bytes: &[u8]) -> String {
    String::from_utf8(bytes.to_vec()).unwrap()
}