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
