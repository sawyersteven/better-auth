use std::{
    sync::Arc,
    thread::{self, JoinHandle},
};

const THREAD_COUNT: usize = 4;

use crate::{
    config::UserConfig,
    routes::{AuthReqest, Login},
    token_manager::TokenManager,
    user_manager::UserManager,
    SESSION_ID,
};
use tiny_http::{Method, Request, Response, StatusCode};
use tracing::info;

pub struct Server {
    address: String,
    port: usize,
    auth: AuthReqest,
    login: Login,
    threads: Vec<JoinHandle<()>>,
}

impl Server {
    pub fn new(user_config: &UserConfig) -> Self {
        let user_manager = UserManager::new(user_config.users_file.as_ref().unwrap()).unwrap();
        let shared_session_manager = Arc::new(TokenManager::new(SESSION_ID, user_config.session_timeout.unwrap()));

        return Server {
            address: String::from(user_config.address.as_ref().unwrap()),
            port: user_config.port.unwrap(),
            login: Login::new(user_manager, shared_session_manager.clone()),
            auth: AuthReqest::new(shared_session_manager.clone()),
            threads: Vec::with_capacity(THREAD_COUNT),
        };
    }

    pub fn start(&self) {
        let addr = format!("{}:{}", self.address, self.port);
        info!("Starting server at {}", addr);

        //let arc_self = Arc::new(self);

        let http_server = Arc::new(tiny_http::Server::http(addr).unwrap());

        //let mut threads = Vec::with_capacity(THREAD_COUNT);
        // for _ in 0..THREAD_COUNT {
        //     let http_server = http_server.clone();
        //     let s = arc_self.clone();

        //     self.threads.push(thread::spawn(move || {
        for rq in http_server.incoming_requests() {
            self.handle_request(rq);
        }
        //     }));
        // }

        // for t in threads {
        //     t.join().unwrap();
        // }
    }

    fn handle_request(&self, rq: Request) {
        match (rq.url(), rq.method()) {
            ("/login", Method::Get) => self.login.get(rq),
            ("/login", Method::Post) => self.login.post(rq),
            ("/auth_request", Method::Get) => self.auth.get(rq),
            _ => _ = rq.respond(Response::new_empty(StatusCode(404))),
        }
    }
}

struct Router {
    login: Login,
    auth: AuthReqest,
}

impl Router {}
