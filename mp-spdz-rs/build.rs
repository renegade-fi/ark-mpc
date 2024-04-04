use itertools::Itertools;

// Build entrypoint
fn main() {
    // Resolve the include paths referenced in the MP-SPDZ library
    let includes = [
        find_include_path("libsodium"),
        find_include_path("gmp"),
        find_include_path("ntl"),
        find_include_path("boost"),
        find_include_path("openssl"),
    ];

    // Build the c++ bridge
    cxx_build::bridge("src/ffi.rs")
        .files(get_source_files("src/include/MP-SPDZ/FHE"))
        .files(get_source_files("src/include/MP-SPDZ/FHEOffline"))
        .files(get_source_files("src/include/MP-SPDZ/Math"))
        .files(get_source_files("src/include/MP-SPDZ/Tools"))
        .files(&[
            "src/include/MP-SPDZ/Processor/BaseMachine.cpp",
            "src/include/MP-SPDZ/Processor/OnlineOptions.cpp",
            "src/include/MP-SPDZ/Processor/DataPositions.cpp",
            "src/include/MP-SPDZ/Processor/ThreadQueues.cpp",
            "src/include/MP-SPDZ/Processor/ThreadQueue.cpp",
        ])
        .file("src/include/MP-SPDZ/Protocols/CowGearOptions.cpp")
        .include("src/include/MP-SPDZ")
        .include("src/include/MP-SPDZ/deps")
        .includes(&includes)
        .define("USE_NTL", None)
        .std("c++17")
        .compile("mp-spdz-cxx");

    // Link in shared libraries installed through package manager
    add_link_path("openssl");
    link_lib("ssl");
    link_lib("crypto");

    add_link_path("ntl");
    link_lib("ntl");

    add_link_path("libsodium");
    link_lib("sodium");

    add_link_path("gmp");
    link_lib("gmp");
    link_lib("gmpxx");

    add_link_path("boost");
    link_lib("boost_system");
    link_lib("boost_filesystem");
    link_lib("boost_iostreams");
    if get_host_vendor() == "apple" {
        println!("cargo:rustc-link-arg=-lboost_thread-mt");
    } else {
        println!("cargo:rustc-link-arg=-lboost_thread");
    }

    // Link in realtime extensions if running on linux
    if get_host_vendor() != "apple" {
        link_lib("rt");
    }

    // Build cache flags
    println!("cargo:rerun-if-changed=src/include/MP-SPDZ");
    println!("cargo:rerun-if-changed=src/ffi.rs");
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

/// Add a link path to the linker
fn add_link_path(lib: &str) {
    let lib_path = find_lib_path(lib);
    println!("cargo:rustc-link-arg=-L{}", lib_path);
}

/// Link a library into the object
fn link_lib(lib: &str) {
    println!("cargo:rustc-link-arg=-l{}", lib);
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

/// Get the list of cpp files in a directory
fn get_source_files(dir: &str) -> Vec<String> {
    let paths = std::fs::read_dir(dir).unwrap();
    paths
        .map(|p| p.unwrap().path())
        .map(|p| p.to_str().unwrap().to_string())
        .filter(|p| p.ends_with(".cpp"))
        .collect()
}

/// Parse a utf8 string from a byte array
fn parse_utf8(bytes: &[u8]) -> String {
    String::from_utf8(bytes.to_vec()).unwrap()
}
