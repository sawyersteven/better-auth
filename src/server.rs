use crate::{
    config::UserConfig,
    routes::{AuthReqest, Login},
    token_manager::TokenManager,
    user_manager::UserManager,
};
use async_std::task::JoinHandle;
use std::{fs, io::Error, sync::Arc};
use tracing::error;

const CSRF_TOKEN: &str = "csrf_token";
pub const SESSION_ID: &str = "session_token";

#[derive(Clone)]
pub struct State {
    pub user_manager: Arc<UserManager>,
    pub csrf_manager: Arc<TokenManager>,
    pub session_manager: Arc<TokenManager>,
    pub login_form_html: String, // is this proper or ideal? No. But I'm doing it anyway because its easier this way.
}

impl State {
    pub fn new(user_config: &UserConfig) -> Self {
        let um = match UserManager::new(&user_config.users_file.as_ref().unwrap()) {
            Ok(um) => um,
            Err(e) => {
                error!("{}", e);
                std::process::exit(1);
            }
        };

        let lfh = match fs::read_to_string("./static/login.html") {
            Ok(h) => h,
            Err(e) => {
                error!("{}", e);
                std::process::exit(1);
            }
        };

        return State {
            user_manager: Arc::new(um),
            csrf_manager: Arc::new(TokenManager::new(CSRF_TOKEN, 15 * 60)),
            session_manager: Arc::new(TokenManager::new(SESSION_ID, user_config.session_timeout.unwrap())),
            login_form_html: lfh,
        };
    }
}

// TODO handle http
pub fn start(user_config: &UserConfig) -> JoinHandle<Result<(), Error>> {
    let state = State::new(user_config);

    let addr = format!("{}:{}", user_config.address.as_ref().unwrap(), user_config.port.unwrap());
    let mut srv = tide::with_state(state);

    srv.at("/login").get(Login::get);
    srv.at("/login").post(Login::post);
    srv.at("/auth_request").get(AuthReqest::get);

    return async_std::task::spawn(srv.listen(addr));
}

#[cfg(test)]
mod tests {
    use crate::{config::UserConfig, test_utils::*};

    use super::start;

    static mut TEST_PORT: usize = 9000;

    fn make_test_confg() -> UserConfig {
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
            https: Some(false),
            config: None,
            command: None,
        };
    }

    #[test]
    fn test_start() {
        let uc = make_test_confg();
        let _srv_task = start(&uc);
        assert!(true);
    }
}
