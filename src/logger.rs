use std::io::stderr;
use std::sync::OnceLock;

use chrono::Local;
use log::set_logger;
use log::set_max_level;
use log::LevelFilter;
use log::Log;
use log::Metadata;
use log::Record;
use log::SetLoggerError;

pub struct Logger {
    program: &'static str,
}

impl Logger {
    pub fn init(program: &'static str) -> Result<(), SetLoggerError> {
        set_logger(LOGGER.get_or_init(move || Logger { program }))
            .map(|()| set_max_level(LevelFilter::Info))
    }
}

impl Log for Logger {
    fn enabled(&self, _metadata: &Metadata) -> bool {
        true
    }

    fn log(&self, record: &Record) {
        use std::fmt::Write;
        let time = Local::now();
        let mut buffer = String::with_capacity(4096);
        if write!(
            &mut buffer,
            "[{}] {}: {}",
            time.format("%a %b %d %H:%M:%S %Y"),
            self.program,
            record.args()
        )
        .is_ok()
        {
            eprintln!("{}", buffer);
        }
    }

    fn flush(&self) {
        use std::io::Write;
        let _ = stderr().flush();
    }
}

static LOGGER: OnceLock<Logger> = OnceLock::new();
