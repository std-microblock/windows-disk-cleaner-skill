fn main() {
    #[cfg(feature = "gui")]
    slint_build::compile_with_config(
        "ui/review.slint",
        slint_build::CompilerConfiguration::new().with_style("fluent".into()),
    ).expect("compile review UI");
}
