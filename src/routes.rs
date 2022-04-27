use serde::Deserialize;
use tide::{Response, StatusCode};
use tracing::info;

use crate::{
    server::CSRF_ID,
    server::{State, SESSION_ID},
};

#[derive(Deserialize)]
struct LoginFormData {
    username: String,
    password: String,
    csrf_id: String,
}

pub struct Login;

impl Login {
    pub async fn get(req: tide::Request<State>) -> tide::Result {
        let mut resp = Response::builder(StatusCode::Ok);
        let state = req.state();
        match req.cookie(CSRF_ID) {
            Some(sess) => {
                state.csrf_manager.renew(&String::from(sess.value()));
            }
            None => {
                let cookie = state.csrf_manager.create().to_string();
                resp = resp.header("Set-Cookie", cookie);
            }
        }

        return Ok(resp.build());
    }

    pub async fn post(mut req: tide::Request<State>) -> tide::Result {
        let login_form_data: LoginFormData = req.body_json().await?;
        let state = req.state();

        if !state.csrf_manager.is_valid(&login_form_data.csrf_id) {
            return Ok(Response::new(StatusCode::NetworkAuthenticationRequired));
        }

        if !state
            .user_manager
            .verify(&login_form_data.username, &login_form_data.password)
        {
            // This is not 100% proper, but rather than returning a 200 with
            // a bool in the resp body I might as well save a few bytes and
            // just send this status code for a failed login
            info!(
                "Failed login attempt for {} from {}",
                login_form_data.username,
                req.remote().unwrap_or("#ERR#")
            );
            return Ok(Response::new(StatusCode::UnprocessableEntity));
        }

        state.csrf_manager.remove(&login_form_data.csrf_id);
        let cookie = state.session_manager.create().to_string();
        let resp = Response::builder(StatusCode::Ok)
            .body("2")
            .header("Set-Cookie", cookie)
            .build();

        info!(
            "Succesful login for {} from {}",
            login_form_data.username,
            req.remote().unwrap_or("#ERR#")
        );

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

mod tests {
    // All tests in server.rs
}
