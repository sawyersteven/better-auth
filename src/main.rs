extern crate clap;
extern crate dirs;

mod config;
mod logging;
mod macros;
mod routes;
mod server;
mod token_manager;
mod user_manager;

use config::UserConfig;
use user_manager::UserManager;

const APP_NAME: &str = "RustAuth";

#[async_std::main]
async fn main() {
    let user_config = UserConfig::build();
    logging::start(
        user_config.log_dir.as_ref().unwrap(),
        user_config.log_rotation.as_ref().unwrap(),
    );

    match user_config.command {
        Some(config::Command::AddUser { username, password }) => {
            let pw = password.unwrap_or(rpassword::prompt_password("Enter password for user: ").unwrap());
            _ = UserManager::new(&user_config.users_file.as_ref().unwrap())
                .unwrap()
                .add_user(&username, &pw);
            return;
        }
        None => {
            let s = server::start(&user_config);
            s.await.expect("Unable to start server");
        }
    }
}

#[cfg(test)]
mod test_utils {
    use rand::{distributions::Alphanumeric, Rng};
    use std::io;

    fn tmp_path() -> Result<String, std::ffi::OsString> {
        let mut rndm = rand::thread_rng();
        let tmp_dir = std::env::temp_dir();

        let id: String = (0..16).map(|_| rndm.sample(Alphanumeric) as char).collect();
        let mut tmp_file = tmp_dir.join(format!("test_file_{id}"));

        loop {
            if !tmp_file.exists() {
                break;
            }
            let id: String = (0..16).map(|_| rndm.sample(Alphanumeric) as char).collect();
            tmp_file = tmp_dir.join(format!("test_file_{id}"));
        }
        return tmp_file.into_os_string().into_string();
    }

    pub fn make_tmp_file() -> Result<String, io::Error> {
        let path = tmp_path().unwrap();
        match std::fs::File::create(&path) {
            Ok(_) => return Ok(path),
            Err(err) => Err(err),
        }
    }

    pub fn make_tmp_dir() -> Result<String, io::Error> {
        let path = tmp_path().unwrap();
        return match std::fs::create_dir_all(&path) {
            Ok(_) => Ok(path),
            Err(e) => Err(e),
        };
    }
}
