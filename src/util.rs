use std::{env, path::Path};

pub fn my_cli() -> String {
    env::args()
        .next()
        .as_ref()
        .map(Path::new)
        .and_then(Path::to_str)
        .map(String::from)
        .unwrap_or("ipass".to_owned())
}
