use std::fmt::Write;

use chrono::Local;
use log::LevelFilter;
use log::Log;
use log::Metadata;
use log::Record;
use log::SetLoggerError;

pub(crate) struct Logger;

impl Logger {
    pub(crate) fn init() -> Result<(), SetLoggerError> {
        log::set_logger(&LOGGER).map(|()| log::set_max_level(LevelFilter::Info))
    }
}

impl Log for Logger {
    fn enabled(&self, _metadata: &Metadata) -> bool {
        true
    }

    fn log(&self, record: &Record) {
        let time = Local::now();
        let mut buffer = String::with_capacity(4096);
        let _ = write!(
            &mut buffer,
            "[{}] cijail: {}",
            time.format("%a %b %m %H:%M:%S %Y"),
            record.args()
        );
        eprintln!("{}", buffer);
    }

    fn flush(&self) {}
}

static LOGGER: Logger = Logger;
