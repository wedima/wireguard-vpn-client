fn sha256_file(path: &std::path::Path) -> String {
    use sha2::{Digest, Sha256};
    let bytes = std::fs::read(path).unwrap_or_default();
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn main() {
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();

    if target_os == "windows" {
        let arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
        let dll_subdir = match arch.as_str() {
            "x86_64" => "amd64",
            "aarch64" => "arm64",
            "x86" => "x86",
            "arm" => "arm",
            _ => "",
        };

        if !dll_subdir.is_empty() {
            let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
            let src = std::path::Path::new(&manifest_dir)
                .join("wintun")
                .join("bin")
                .join(dll_subdir)
                .join("wintun.dll");

            if src.exists() {
                let expected = match dll_subdir {
                    // Official wintun 0.14.1 from https://www.wintun.net/builds/wintun-0.14.1.zip
                    // (zip SHA-256 07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51).
                    "amd64" => "e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce",
                    "arm64" => "f7ba89005544be9d85231a9e0d5f23b2d15b3311667e2dad0debd344918a3f80",
                    "x86" => "d694fa46ab4cfebcb2632d094c7aa97278eef2f8052438621766d863ae98a931",
                    "arm" => "daad267411ecdc70a0535e274d2c3e9da3d0084bdac7662cb8424dd4a031b4d9",
                    _ => "",
                };
                if !expected.is_empty() && sha256_file(&src) != expected {
                    panic!("wintun.dll for {dll_subdir} does not match the pinned official 0.14.1 hash");
                }
                let out_dir = std::env::var("OUT_DIR").unwrap();
                if let Some(bin_dir) = std::path::Path::new(&out_dir).ancestors().nth(3) {
                    let _ = std::fs::copy(&src, bin_dir.join("wintun.dll"));
                }
                let _ = std::fs::copy(&src, std::path::Path::new(&manifest_dir).join("wintun.dll"));
                println!("cargo:rerun-if-changed=wintun/bin/{}/wintun.dll", dll_subdir);
            }
        }
    }

    let windows_attrs = tauri_build::WindowsAttributes::new().app_manifest(
        r#"<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
    <security>
      <requestedPrivileges>
        <requestedExecutionLevel level="asInvoker" uiAccess="false"/>
      </requestedPrivileges>
    </security>
  </trustInfo>
  <dependency>
    <dependentAssembly>
      <assemblyIdentity
        type="win32"
        name="Microsoft.Windows.Common-Controls"
        version="6.0.0.0"
        processorArchitecture="*"
        publicKeyToken="6595b64144ccf1df"
        language="*"
      />
    </dependentAssembly>
  </dependency>
</assembly>"#,
    );

    tauri_build::try_build(tauri_build::Attributes::new().windows_attributes(windows_attrs))
        .expect("failed to run tauri-build");
}
