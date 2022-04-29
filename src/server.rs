use crate::{
    config::UserConfig,
    return_err_string,
    routes::{AuthReqest, Login},
    token_manager::TokenManager,
    user_manager::UserManager,
};
use async_std::task::JoinHandle;
use std::{fs, io::Error, sync::Arc};

pub const CSRF_ID: &str = "csrf_token";
pub const SESSION_ID: &str = "session_token";

#[derive(Clone)]
pub struct State {
    pub user_manager: Arc<UserManager>,
    pub csrf_manager: Arc<TokenManager>,
    pub session_manager: Arc<TokenManager>,
    pub login_form_html: String, // is this proper or ideal? No. But I'm doing it anyway because its easier this way.
}

impl State {
    pub fn new(user_config: &UserConfig) -> Result<Self, String> {
        let um = match UserManager::new(&user_config.users_file.as_ref().unwrap()) {
            Ok(um) => um,
            Err(e) => {
                return_err_string!("{}", e);
            }
        };

        let lfh = match fs::read_to_string("./static/login.html") {
            Ok(h) => h,
            Err(e) => {
                return_err_string!("{}", e);
            }
        };

        return Ok(State {
            user_manager: Arc::new(um),
            csrf_manager: Arc::new(TokenManager::new(CSRF_ID, 15 * 60)),
            session_manager: Arc::new(TokenManager::new(SESSION_ID, user_config.session_timeout.unwrap())),
            login_form_html: lfh,
        });
    }
}

pub fn start(user_config: &UserConfig) -> Result<JoinHandle<Result<(), Error>>, String> {
    let state = match State::new(user_config) {
        Ok(s) => s,
        Err(e) => return Err(e),
    };

    let addr = format!("{}:{}", user_config.address.as_ref().unwrap(), user_config.port.unwrap());
    let mut srv = tide::with_state(state);

    srv.at("/login").get(Login::get);
    srv.at("/login").post(Login::post);
    srv.at("/auth_request").get(AuthReqest::get);

    return Ok(async_std::task::spawn(srv.listen(addr)));
}

#[cfg(test)]
mod tests {
    use crate::config;

    use super::start;

    #[test]
    fn test_missing_html() {
        _ = std::fs::rename("./static/login.html", "./static/login_backup.html");
        let uc = config::tests::make_test_config();
        let _srv_task = start(&uc);
        _ = std::fs::rename("./static/login_backup.html", "./static/login.html");
    }
}
