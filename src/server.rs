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

pub fn start(user_config: &UserConfig) -> JoinHandle<Result<(), Error>> {
    let state = State::new(user_config).unwrap_or_else(|_| std::process::exit(1));

    let addr = format!("{}:{}", user_config.address.as_ref().unwrap(), user_config.port.unwrap());
    let mut srv = tide::with_state(state);

    srv.at("/login").get(Login::get);
    srv.at("/login").post(Login::post);
    srv.at("/auth_request").get(AuthReqest::get);

    return async_std::task::spawn(srv.listen(addr));
}

#[cfg(test)]
mod tests {
    use surf::StatusCode;

    use crate::{config::UserConfig, server::CSRF_ID, test_utils::*};

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

    #[async_std::test]
    async fn test_get_login() {
        let uc = make_test_confg();
        let _srv_task = start(&uc);
        let url = format!("http://localhost:{}/login", uc.port.unwrap());
        let resp = surf::get(&url).await;
        assert!(resp.is_ok());
        let resp = resp.unwrap();
        assert!(resp.status() == StatusCode::Ok);
        let csrf_cookie = resp.header("Set-Cookie");
        assert!(csrf_cookie.is_some());

        let csrf_cookie = csrf_cookie.unwrap();
        let resp = surf::get(&url)
            .header("Cookie", format!("{}={}", CSRF_ID, csrf_cookie))
            .send()
            .await;
        assert!(resp.is_ok());
        let resp = resp.unwrap();
        assert!(resp.status() == StatusCode::Ok);
        let csrf_cookie = resp.header("Set-Cookie");
        assert!(csrf_cookie.is_none());
    }
}
