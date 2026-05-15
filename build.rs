use std::{
    env,
    fs::{self, File},
    io::{self, Write},
    path::{Path, PathBuf},
};

fn main() -> io::Result<()> {
    let dist = PathBuf::from("frontend/dist");
    println!("cargo:rerun-if-changed={}", dist.display());

    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR is set by cargo"));
    let mut generated = File::create(out_dir.join("embedded_frontend.rs"))?;

    let mut assets = Vec::new();
    if dist.is_dir() {
        collect_assets(&dist, &dist, &mut assets)?;
    }
    assets.sort_by(|a, b| a.0.cmp(&b.0));

    writeln!(
        generated,
        "pub fn get(path: &str) -> Option<(&'static [u8], &'static str)> {{"
    )?;
    writeln!(generated, "    match path {{")?;
    for (relative, absolute, mime) in assets {
        println!("cargo:rerun-if-changed={}", absolute.display());
        writeln!(
            generated,
            "        {:?} => Some((include_bytes!({:?}).as_slice(), {:?})),",
            relative,
            absolute.display().to_string(),
            mime
        )?;
    }
    writeln!(generated, "        _ => None,")?;
    writeln!(generated, "    }}")?;
    writeln!(generated, "}}")?;

    Ok(())
}

fn collect_assets(
    root: &Path,
    dir: &Path,
    assets: &mut Vec<(String, PathBuf, &'static str)>,
) -> io::Result<()> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let file_type = entry.file_type()?;
        if file_type.is_dir() {
            collect_assets(root, &path, assets)?;
        } else if file_type.is_file() {
            let relative = path
                .strip_prefix(root)
                .expect("asset path is under frontend dist")
                .to_string_lossy()
                .replace('\\', "/");
            let absolute = fs::canonicalize(&path)?;
            let mime = mime_for_path(&path);
            assets.push((relative, absolute, mime));
        }
    }
    Ok(())
}

fn mime_for_path(path: &Path) -> &'static str {
    match path
        .extension()
        .and_then(|ext| ext.to_str())
        .unwrap_or_default()
    {
        "css" => "text/css; charset=utf-8",
        "gif" => "image/gif",
        "html" => "text/html; charset=utf-8",
        "ico" => "image/x-icon",
        "jpeg" | "jpg" => "image/jpeg",
        "js" | "mjs" => "text/javascript; charset=utf-8",
        "json" | "webmanifest" => "application/json; charset=utf-8",
        "map" => "application/json; charset=utf-8",
        "png" => "image/png",
        "svg" => "image/svg+xml",
        "txt" => "text/plain; charset=utf-8",
        "wasm" => "application/wasm",
        "webp" => "image/webp",
        "woff" => "font/woff",
        "woff2" => "font/woff2",
        _ => "application/octet-stream",
    }
}
