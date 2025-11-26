use std::path::PathBuf;

fn main() {
    if std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default() == "macos" {
        let mut build = cc::Build::new();
        build.cpp(true)
             .file("src/mlx_bridge.cpp")
             .flag("-std=c++17");

        if let Some(mlx_path) = find_mlx_path() {
            let lib_path = mlx_path.join("lib");
            let include_path = mlx_path.join("include");
            if lib_path.exists() {
                println!("cargo:rustc-link-search=native={}", lib_path.display());
                println!("cargo:rustc-link-lib=dylib=mlx");
                println!("cargo:rustc-link-arg=-Wl,-rpath,{}", lib_path.display());
            }
            if include_path.exists() {
                build.include(include_path);
            }
        } else {
            println!("cargo:warning=MLX not found. NPU mining will run in CPU mock mode.");
        }
        
        build.compile("mlx_bridge");
    }
}

fn find_mlx_path() -> Option<PathBuf> {
    let mut candidates = Vec::new();

    // 1. Respect explicit override
    if let Ok(env) = std::env::var("MLX_HOME") {
        candidates.push(PathBuf::from(env));
    }

    // 2. Workspace-local libs/mlx directory
    if let Ok(workspace_dir) = std::env::var("CARGO_MANIFEST_DIR") {
        candidates.push(PathBuf::from(workspace_dir).join("../../libs/mlx"));
    }

    // 3. Common Anaconda path (user mentioned using MLX via local environment)
    if let Ok(home) = std::env::var("HOME") {
        for py_ver in ["3.12", "3.11", "3.10", "3.9"] {
            candidates.push(PathBuf::from(format!("{home}/anaconda3/lib/python{py_ver}/site-packages/mlx")));
        }
    }

    candidates.into_iter().find(|path| path.exists())
}
