fn main() {
    #[cfg(target_os = "windows")]
    embed_resource::compile("assets/icon.rc", embed_resource::NONE)
        .manifest_optional()
        .unwrap();
}
