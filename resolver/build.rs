extern crate lalrpop;

fn main() {
    lalrpop::Configuration::new()
        .log_verbose()
        .use_cargo_dir_conventions()
        .use_colors_if_tty()
        .process()
        .expect("lalrpop processing failed");
}