use crate::APP_NAME;
use rolling_file::*;
use tracing_appender;
use tracing_subscriber::{fmt, prelude::__tracing_subscriber_SubscriberExt, util::SubscriberInitExt};

pub fn start(directory: &String, max_files: &usize) {
    std::fs::create_dir_all(directory).expect(&*format!("Unable to create log dir: {}", directory));

    let file_appender = BasicRollingFileAppender::new(
        std::path::Path::new(directory).join(format!("{}.{}", APP_NAME, "log")),
        RollingConditionBasic::new().daily(),
        *max_files,
    )
    .unwrap();

    let (non_blocking, _guard) = tracing_appender::non_blocking(file_appender);

    fmt::Subscriber::builder()
        .finish()
        .with(fmt::Layer::default().with_writer(non_blocking).with_ansi(false))
        .init();
}
