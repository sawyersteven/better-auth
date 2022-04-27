#[macro_export]
/// Logs an error! and returns an Err() with the formatted str
macro_rules! return_err_string {
    ($($arg:tt)*) => {{
        let msg = format!($($arg)*);
        tracing::error!("{}", msg);
        return Err(msg);
    }};
}
