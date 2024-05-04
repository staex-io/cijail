use std::io::ErrorKind;

pub fn env_to_bool(name: &str) -> Result<bool, std::io::Error> {
    match std::env::var(name) {
        Ok(value) => str_to_bool(value.as_str()),
        Err(_) => Ok(false),
    }
}

pub fn str_to_bool(s: &str) -> Result<bool, std::io::Error> {
    let s = s.trim();
    match s {
        "0" => Ok(false),
        "1" => Ok(true),
        _ => Err(std::io::Error::new(
            ErrorKind::Other,
            format!("invalid boolean: `{}`", s),
        )),
    }
}

pub fn bool_to_str(value: bool) -> &'static str {
    if value {
        "1"
    } else {
        "0"
    }
}
