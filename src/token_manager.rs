use std::{
    collections::HashMap,
    sync::{Mutex, MutexGuard},
    time::Duration,
};

use rand::{self, distributions::Alphanumeric, Rng};
use tide::http::Cookie;
use time::OffsetDateTime;

const TOKEN_LEN: usize = 16;

pub struct TokenManager {
    tokens_mut: Mutex<HashMap<String, OffsetDateTime>>,
    timeout: Duration,
    name: String,
}

impl TokenManager {
    pub fn new(name: &str, timeout: u64) -> Self {
        return TokenManager {
            tokens_mut: Mutex::new(HashMap::new()),
            timeout: Duration::from_secs(timeout),
            name: String::from(name),
        };
    }

    fn lock_tokens(&self) -> MutexGuard<HashMap<String, OffsetDateTime>> {
        return self.tokens_mut.lock().unwrap();
    }

    fn with_tokens_lock<P, T>(&self, predicate: P)
    where
        P: Fn(MutexGuard<HashMap<String, OffsetDateTime>>) -> T,
    {
        predicate(self.tokens_mut.lock().unwrap());
    }

    pub fn create(&self) -> Cookie {
        self.clean_expired();
        let id: String = self.random_id();
        let exp = self.make_exp_timestamp();
        self.with_tokens_lock(|mut x| x.insert(id.to_owned(), exp));
        return Cookie::build(&self.name, id)
            .secure(true)
            .http_only(true)
            .expires(exp)
            .finish();
    }

    fn random_id(&self) -> String {
        let mut rndm = rand::thread_rng();
        let tokens = self.lock_tokens();
        let mut id: String;
        loop {
            id = (0..TOKEN_LEN).map(|_| rndm.sample(Alphanumeric) as char).collect();
            if !tokens.contains_key(&id) {
                break;
            }
        }
        return id;
    }

    fn clean_expired(&self) {
        let now = OffsetDateTime::now_utc();
        self.with_tokens_lock(|mut x| x.retain(|_, v| *v > now));
    }

    fn make_exp_timestamp(&self) -> OffsetDateTime {
        return OffsetDateTime::now_utc() + self.timeout;
    }

    pub fn remove(&self, id: &String) {
        self.with_tokens_lock(|mut x| x.remove(id));
    }

    // gives token a new expiry of now + timeout
    pub fn renew(&self, id: &String) -> Option<OffsetDateTime> {
        self.clean_expired();
        let mut tokens = self.lock_tokens();

        return match tokens.get(id) {
            Some(_) => tokens.insert(id.to_owned(), self.make_exp_timestamp()),
            None => None,
        };
    }

    // Checks if token id exists and is not expired. Extends expiry if id is valid.
    pub fn is_valid(&self, id: &str) -> bool {
        let mut tokens = self.lock_tokens();
        if !tokens.contains_key(id) || tokens[id] < OffsetDateTime::now_utc() {
            _ = tokens.remove(id);
            return false;
        }

        tokens.insert(String::from(id), self.make_exp_timestamp());
        return true;
    }
}

#[cfg(test)]
mod tests {
    use super::TokenManager;
    use std::{collections::HashSet, time::Duration};

    #[test]
    fn test_unique_id() {
        let tokenman = TokenManager::new("Test", 1);

        let mut ids: HashSet<String> = HashSet::new();
        for _ in 0..1024 {
            let id = String::from(tokenman.create().value());
            assert!(!ids.contains(&id));
            ids.insert(id);
        }
    }

    #[test]
    fn test_expiration() {
        let tokenman = TokenManager::new("Test", 1);
        let id1 = String::from(tokenman.create().value());
        std::thread::sleep(Duration::from_millis(500));
        let id2 = String::from(tokenman.create().value());
        std::thread::sleep(Duration::from_millis(500));

        assert!(!tokenman.is_valid(&id1));
        assert!(tokenman.is_valid(&id2));
    }

    #[test]
    fn test_remove() {
        let tokenman = TokenManager::new("Test", 1);
        let id = String::from(tokenman.create().value());
        tokenman.remove(&id);
        assert!(!tokenman.is_valid(&id));
    }

    #[test]
    fn test_renew() {
        let tokenman = TokenManager::new("Test", 1);
        let id = String::from(tokenman.create().value());
        std::thread::sleep(Duration::from_millis(500));
        tokenman.renew(&id);
        std::thread::sleep(Duration::from_millis(750));
        assert!(tokenman.is_valid(&id));
        assert!(tokenman.renew(&String::from("not_a_token")).is_none());
    }

    #[test]
    fn test_clean_expired() {
        let tokenman = TokenManager::new("Test", 1);
        let id = String::from(tokenman.create().value());
        tokenman.clean_expired();
        assert!(tokenman.is_valid(&id));
        std::thread::sleep(Duration::from_millis(1010));
        tokenman.clean_expired();
        assert!(!tokenman.is_valid(&id));
    }
}
