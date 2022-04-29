use tide::{Response, ResponseBuilder, StatusCode};
use tracing::info;

use crate::{
    server::CSRF_ID,
    server::{State, SESSION_ID},
};

pub struct Login;

impl Login {
    pub async fn get(req: tide::Request<State>) -> tide::Result {
        let state = req.state();
        let mut resp = Response::builder(StatusCode::Ok)
            .body(state.login_form_html.to_owned())
            .content_type("text/html");

        let c = req
            .cookie(CSRF_ID)
            .and_then(|c| state.csrf_manager.renew(&String::from(c.value())));
        if c.is_none() {
            resp = Login::set_csrf(state, resp);
        }

        return Ok(resp.build());
    }

    fn set_csrf(state: &State, resp: ResponseBuilder) -> ResponseBuilder {
        let cookie = state.csrf_manager.create().to_string();
        return resp.header("Set-Cookie", cookie);
    }

    pub async fn post(mut req: tide::Request<State>) -> tide::Result {
        let payload = req.body_string().await?;
        let state = req.state();

        let csrf = req.cookie(CSRF_ID);

        if csrf.is_none() {
            return Ok(Response::new(StatusCode::NetworkAuthenticationRequired));
        }

        let csrf = csrf.unwrap();
        let csrf = csrf.value();
        if !state.csrf_manager.is_valid(csrf) {
            return Ok(Response::new(StatusCode::NetworkAuthenticationRequired));
        };

        /* Using serde to deserialize this is like using a howitzer to hunt quail
         The post payload is just the user and password, so it can be submitted
         in something as simple as `user:pass` to be split apart here. Use the
         char ':' to separate because it is the only char not allowed in a
         username.
        */
        let (user, pass) = payload.split_once(':').unwrap();
        if !state.user_manager.verify(&String::from(user), &String::from(pass)) {
            // This is not 100% proper, but rather than returning a 200 with
            // a bool in the resp body I might as well save a few bytes and
            // just send this status code for a failed login
            info!("Failed login attempt for {} from {}", user, req.remote().unwrap_or("#ERR#"));
            return Ok(Response::new(StatusCode::UnprocessableEntity));
        }

        state.csrf_manager.remove(&String::from(csrf));
        let sess_cookie = state.session_manager.create().to_string();
        let resp = Response::builder(StatusCode::Ok).header("Set-Cookie", sess_cookie).build();

        info!("Succesful login for {} from {}", user, req.remote().unwrap_or("#ERR#"));

        return Ok(resp);
    }
}

pub struct AuthReqest {}

impl AuthReqest {
    pub async fn get(req: tide::Request<State>) -> tide::Result {
        let status = match req.cookie(SESSION_ID) {
            Some(c) => match req.state().session_manager.is_valid(c.value()) {
                true => StatusCode::Ok,
                false => StatusCode::Unauthorized,
            },
            None => StatusCode::Unauthorized,
        };
        return Ok(Response::new(status));
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use surf::{Response, StatusCode};

    use crate::{
        config,
        server::{self, start, CSRF_ID},
        user_manager::UserManager,
    };

    #[async_std::test]
    async fn test_get_login() {
        let uc = config::tests::make_test_config();
        let srv_task = start(&uc).unwrap();
        let url = format!("http://localhost:{}/login", uc.port.unwrap());

        let resp = surf::get(&url).await;

        assert!(resp.is_ok());
        let resp = resp.unwrap();
        assert!(resp.status() == StatusCode::Ok);

        let csrf_token = get_csrf_token(&resp);
        assert!(csrf_token.is_some());
        let csrf_token = csrf_token.unwrap();

        // test that sending the csrf doesn't generate a new set-cookie header
        let resp = surf::get(&url)
            .header("Cookie", format!("{}={}", CSRF_ID, csrf_token))
            .send()
            .await;
        assert!(resp.is_ok());
        let resp = resp.unwrap();
        assert!(resp.status() == StatusCode::Ok);
        assert!(get_csrf_token(&resp).is_none());

        srv_task.cancel().await;
    }

    #[async_std::test]
    async fn test_post_login() {
        let uc = config::tests::make_test_config();
        _ = UserManager::new(&uc.users_file.as_ref().unwrap())
            .unwrap()
            .add_user(&String::from("test_user"), &String::from("test_password"))
            .unwrap();

        let srv_task = start(&uc).unwrap();

        let url = format!("http://localhost:{}/login", uc.port.unwrap());
        let resp = surf::get(&url).await.unwrap();
        let csrf_cookie = get_csrf_token(&resp).unwrap();

        let resp = surf::post(&url)
            .body_string(String::from("bad_user:bad_password"))
            .header("Cookie", format!("{}={}", CSRF_ID, csrf_cookie))
            .send()
            .await;

        assert!(resp.is_ok());
        let resp = resp.unwrap();
        assert!(resp.status() == StatusCode::UnprocessableEntity);
        srv_task.cancel().await;
    }

    fn get_csrf_token(resp: &Response) -> Option<String> {
        let h = resp.header("Set-Cookie")?.to_string();
        // surely there is a better way?
        let t = h[2..].split(";").nth(0)?.split('=').nth(1)?;
        return Some(t.to_string());
    }
}
