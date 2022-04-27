use std::{
    collections::HashMap,
    fs::{self, File},
    io::Write,
    path::Path,
};

use std::result::Result;

use bcrypt::BcryptResult;
use tracing::{info, warn};

use crate::return_err_string;

pub struct UserManager {
    users: HashMap<String, String>,
    filepath: String,
}

const HASH_COST: u32 = 11;

impl UserManager {
    pub fn new(filepath: &String) -> Result<Self, String> {
        let users: HashMap<String, String>;
        if Path::new(filepath).exists() {
            users = match UserManager::read_from_file(filepath) {
                Ok(u) => u,
                Err(e) => return Err(e),
            }
        } else {
            users = HashMap::new();
            match File::create(filepath) {
                Err(e) => return_err_string!("{}", e),
                Ok(_) => {
                    info!("A new users file has been created at {filepath}");
                }
            }
        }
        return Ok(UserManager {
            users: users,
            filepath: filepath.to_owned(),
        });
    }

    fn read_from_file(filepath: &String) -> Result<HashMap<String, String>, String> {
        info!("Reading user file at {}", filepath);
        let mut map: HashMap<String, String> = HashMap::new();

        let file_contents = match fs::read_to_string(filepath) {
            Err(e) => {
                return_err_string!("{}", e);
            }
            Ok(content) => content,
        };

        if file_contents == "" {
            warn!("Empty user file found");
            return Ok(map);
        }

        for (i, line) in file_contents.split('\n').enumerate() {
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() != 2 {
                return_err_string!("Invalid user on line {i} of {filepath}");
            }
            map.insert(String::from(parts[0]), String::from(parts[1]));
        }

        return Ok(map);
    }

    pub fn add_user(&mut self, username: &String, password: &String) -> Result<(), String> {
        let ok = self
            .validate_username(username)
            .and_then(|_| self.validate_password(password));

        if ok.is_err() {
            return ok;
        }

        let hashed_pass = match self.hash_password(password) {
            Ok(pw) => pw,
            Err(e) => {
                return_err_string!("Error hashing password: {e}");
            }
        };

        let result = self.write_user_to_file(username, &hashed_pass);
        if result.is_ok() {
            self.users.insert(username.to_owned(), hashed_pass);
        }

        return result;
    }

    fn write_user_to_file(&self, username: &String, hashed_pass: &String) -> Result<(), String> {
        let line = format!("{username}:{hashed_pass}");
        let mut file = match fs::OpenOptions::new().write(true).append(true).open(&self.filepath) {
            Ok(file) => file,
            Err(e) => {
                return_err_string!("Unable to write to file {}: {}", self.filepath, e);
            }
        };
        match file.write_all(line.as_str().as_bytes()) {
            Ok(_) => {
                return Ok(());
            }
            Err(e) => return_err_string!("{}", e),
        };
    }

    fn validate_username(&self, username: &String) -> Result<(), String> {
        if self.users.contains_key(username) {
            return_err_string!("User {username} already exists");
        }
        if username.len() == 0 {
            return_err_string!("Username may not be empty");
        }
        if username.contains(':') {
            return_err_string!("Username may not contain character ':'");
        }
        return Ok(());
    }

    fn validate_password(&self, password: &String) -> Result<(), String> {
        if password.len() < 8 {
            return_err_string!("Password too short (minimum 8 characters)");
        }
        return Ok(());
    }

    pub fn verify(&self, username: &String, password: &String) -> bool {
        return match self.users.get(username) {
            None => false,
            Some(stored) => bcrypt::verify(password, stored).unwrap_or(false),
        };
    }

    fn hash_password(&self, password: &String) -> BcryptResult<String> {
        return bcrypt::hash(password, HASH_COST);
    }
}

#[cfg(test)]
mod tests {
    use crate::test_utils::*;

    use super::*;
    const NAME: &str = "TestUser";
    const PASS: &str = "TestPass";

    #[test]
    fn test_add_user() {
        let tmp = make_tmp_file().unwrap();
        let mut userman = UserManager::new(&tmp).unwrap();
        let added = userman.add_user(&NAME.to_string(), &PASS.to_string());
        assert!(added.is_ok());
        assert!(fs::read_to_string(&tmp).unwrap().starts_with(NAME));

        _ = fs::remove_file(&tmp);
        let added = userman.add_user(&"a_new_name".to_string(), &"a_new_pass".to_string());
        assert!(added.is_err());
    }

    #[test]
    fn test_check() {
        let tmp = make_tmp_file().unwrap();
        let mut userman = UserManager::new(&tmp).unwrap();
        _ = userman.add_user(&NAME.to_string(), &PASS.to_string());

        assert!(userman.verify(&NAME.to_string(), &PASS.to_string()));
        assert!(!userman.verify(&NAME.to_string(), &"not_a_pass".to_string()));
        assert!(!userman.verify(&"not_a_user".to_string(), &PASS.to_string()));
    }

    #[test]
    fn test_invalid_name_pass() {
        let tmp = make_tmp_file().unwrap();
        let mut userman = UserManager::new(&tmp).unwrap();
        _ = userman.add_user(&NAME.to_string(), &PASS.to_string());
        assert!(userman.add_user(&NAME.to_string(), &PASS.to_string()).is_err());
        assert!(userman.add_user(&"".to_string(), &PASS.to_string()).is_err());
        assert!(userman.add_user(&"test:user".to_string(), &PASS.to_string()).is_err());
        assert!(userman.add_user(&"bad_pass".to_string(), &"1234567".to_string()).is_err());
    }

    #[test]
    fn test_read_from_file() {
        let tmp = make_tmp_file().unwrap();
        let mut userman = UserManager::new(&tmp).unwrap();
        _ = userman.add_user(&NAME.to_string(), &PASS.to_string());

        let userman = UserManager::new(&tmp).unwrap();

        let content = fs::read_to_string(tmp).unwrap();
        let lines: Vec<&str> = content.split('\n').collect();
        assert!(lines.len() == 1);
        assert!(userman.verify(&NAME.to_string(), &PASS.to_string()));
    }

    #[test]
    fn test_new_file() {
        let tmp_name = make_tmp_file().unwrap();
        _ = fs::remove_file(&tmp_name);
        let mut userman = UserManager::new(&tmp_name).unwrap();
        _ = userman.add_user(&NAME.to_string(), &PASS.to_string());

        userman = UserManager::new(&tmp_name).unwrap();

        let content = fs::read_to_string(tmp_name).unwrap();
        let lines: Vec<&str> = content.split('\n').collect();
        assert!(lines.len() == 1);
        assert!(userman.verify(&NAME.to_string(), &PASS.to_string()));

        let tmp_name = String::from("invalid_file_path!)@(#*$&%^|}{[]';:?/.<>,");
        let err_userman = UserManager::new(&tmp_name);
        assert!(err_userman.is_err());

        let readonly_tmp_name = make_tmp_file().unwrap();
        let mut perms = fs::metadata(&readonly_tmp_name).unwrap().permissions();
        perms.set_readonly(true);
        fs::set_permissions(&readonly_tmp_name, perms).unwrap();
        let err_fs = UserManager::new(&tmp_name);
        assert!(err_fs.is_err());
    }

    #[test]
    fn test_read_bad_file_content() {
        let tmp = make_tmp_file().unwrap();

        _ = fs::write(&tmp, "\nusername:password".to_string());
        let userman = UserManager::new(&tmp);
        assert!(userman.is_err());

        _ = fs::write(&tmp, "username:pass:word".to_string());
        let userman = UserManager::new(&tmp);
        assert!(userman.is_err());
    }
}
