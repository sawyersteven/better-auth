use std::{
    fs::{self},
    path::Path,
};

use argh::FromArgs;
//use clap::{Parser, Subcommand};
use merge::Merge;
use serde_lite::{Deserialize, Serialize};
use serde_lite_derive::{Deserialize, Serialize};

mod default_path {
    use crate::APP_NAME;
    // Builds a path as ~/auth/child_path
    #[cfg(target_os = "windows")]
    fn make_path_from_home(child_path: &str) -> String {
        return std::path::Path::new(&dirs::home_dir().unwrap())
            .join(APP_NAME)
            .join(child_path)
            .to_str()
            .unwrap()
            .to_string();
    }

    pub fn config_file() -> Option<String> {
        #[cfg(target_os = "windows")]
        let cf = make_path_from_home("auth.conf");
        #[cfg(not(target_os = "windows"))]
        let cf = String::from("/etc/adequate_auth/adequate_auth.conf");
        return Some(cf);
    }

    pub fn users_file() -> Option<String> {
        #[cfg(target_os = "windows")]
        let uf = make_path_from_home("auth.users");
        #[cfg(not(target_os = "windows"))]
        let uf = String::from("/etc/adequate_auth/adequate_auth.users");
        return Some(uf);
    }

    pub fn log_dir() -> Option<String> {
        #[cfg(target_os = "windows")]
        let ld = make_path_from_home("logs");
        #[cfg(not(target_os = "windows"))]
        let ld = String::from("/var/log/adequate_auth/");
        return Some(ld);
    }
}

mod merge_strategy {
    // Overwrites existing Option<T> with donor Option<T> if donor's option
    // contains a value, regardless of the existing option
    pub fn overwrite_option<T>(existing: &mut Option<T>, donor: Option<T>) {
        if !donor.is_none() {
            *existing = donor;
        }
    }
}

#[derive(Debug, Merge, Serialize, Deserialize, FromArgs)]
/// A description
// #[clap(author, version, about, long_about = None)]
pub struct UserConfig {
    /// address at which to start server
    #[merge(strategy = merge_strategy::overwrite_option)]
    // #[clap(short, long)]
    #[argh(option)]
    pub address: Option<String>,

    /// port on which to listen
    #[merge(strategy = merge_strategy::overwrite_option)]
    //// #[clap(short, long)]
    #[argh(option)]
    pub port: Option<usize>,

    /// time in seconds for inactive sessions to expire
    #[merge(strategy = merge_strategy::overwrite_option)]
    // #[clap(short = 't', long)]
    #[argh(option)]
    pub session_timeout: Option<u64>,

    /// location of user/password file for this session
    #[merge(strategy = merge_strategy::overwrite_option)]
    // #[clap(short = 'u', long)]
    #[argh(option)]
    pub users_file: Option<String>,

    /// directory in which to write logs
    #[merge(strategy = merge_strategy::overwrite_option)]
    // #[clap(short, long)]
    #[argh(option)]
    pub log_dir: Option<String>,

    /// number of days to keep old log files
    #[merge(strategy = merge_strategy::overwrite_option)]
    // #[clap(short = 'r', long)]
    #[argh(option)]
    pub log_rotation: Option<usize>,

    /// custom config file location
    #[serde(skip)]
    #[merge(strategy = merge_strategy::overwrite_option)]
    // #[clap(short, long)]
    #[argh(option)]
    pub config: Option<String>,

    #[serde(skip)]
    // #[clap(subcommand)]
    #[argh(subcommand)]
    pub command: Option<Command>,
}

impl Default for UserConfig {
    fn default() -> Self {
        return UserConfig {
            address: Some(String::from("localhost")),
            port: Some(8675),
            session_timeout: Some(3600),
            users_file: default_path::users_file(),
            log_dir: default_path::log_dir(),
            log_rotation: Some(5),
            config: default_path::config_file(), // only used for passing --config via cmdline args
            command: None,
        };
    }
}

impl UserConfig {
    // Compiles a UserConfig by layering args over json over default values
    pub fn build() -> Self {
        let mut default_conf = UserConfig::default();
        // cmd line args parsed via clap
        let args: UserConfig = argh::from_env(); // = UserConfig::parse();
        let filepath: &str = args.config.as_deref().unwrap_or(default_conf.config.as_deref().unwrap());

        let deserialized = UserConfig::read_or_create(filepath);

        default_conf.merge(deserialized);
        default_conf.merge(args);

        return default_conf;
    }

    fn read_or_create(filepath: &str) -> Self {
        if std::path::Path::new(filepath).exists() {
            return UserConfig::deserialize_file(filepath);
        } else {
            let default_conf = UserConfig::default();
            UserConfig::serialize(&default_conf, filepath);
            return default_conf;
        }
    }

    pub fn serialize(config: &UserConfig, filepath: &str) {
        println!("Writing config file {filepath}");
        let intermediate = config.serialize().unwrap();
        let json = serde_json::to_string_pretty(&intermediate).unwrap();

        match Path::new(filepath).parent() {
            Some(dir) => match fs::create_dir_all(dir) {
                Ok(_) => match fs::write(filepath, json) {
                    Ok(_) => {}
                    Err(e) => {
                        println!("Error writing config file: {e}");
                        std::process::exit(1);
                    }
                },
                Err(e) => {
                    println!("Error creating log directory: {e}");
                    std::process::exit(1);
                }
            },
            None => {
                println!("Cannot get parent directory of {filepath}");
                std::process::exit(1);
            }
        }
    }

    pub fn deserialize_file(filepath: &str) -> Self {
        println!("Reading config from {filepath}");
        let json_string = fs::read_to_string(filepath).expect(&*format!("Unable to read file: {}", filepath));
        let intermediate = serde_json::from_str(json_string.as_str()).expect(&*format!("Malformed config file: {}", filepath));
        return UserConfig::deserialize(&intermediate).expect(&*format!("Error parsing file: {}", filepath));
    }
}

#[derive(Debug, FromArgs)]
#[argh(subcommand)]
pub enum Command {
    AddUser(AddUser),
}

#[derive(FromArgs, PartialEq, Debug)]
/// Add new user and password
#[argh(subcommand, name = "adduser")]
pub struct AddUser {
    /// username to add
    #[argh(option)]
    pub username: String,

    /// password for user
    #[argh(option)]
    pub password: Option<String>,
}

#[cfg(test)]
pub mod tests {
    use crate::test_utils::{make_tmp_dir, make_tmp_file};

    use super::UserConfig;

    static mut TEST_PORT: usize = 9000;

    pub fn make_test_config() -> UserConfig {
        let p: usize;
        unsafe {
            p = TEST_PORT;
            TEST_PORT += 1;
        }

        return UserConfig {
            address: Some(String::from("localhost")),
            port: Some(p),
            session_timeout: Some(3600),
            users_file: Some(make_tmp_file().unwrap()),
            log_dir: Some(make_tmp_dir().unwrap()),
            log_rotation: Some(1),
            config: None,
            command: None,
        };
    }
}
