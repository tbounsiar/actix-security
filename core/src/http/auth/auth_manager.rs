use std::collections::HashMap;

use crate::http::auth::user::User;

pub trait UserAuth {
    fn get_user(self, user_name: &'static str, password: &'static str) -> Option<User>;
}

pub struct AuthManager {}

impl AuthManager {
    pub fn in_memory_auth() -> MemoryAuth {
        MemoryAuth {
            users: HashMap::new()
        }
    }
}

pub struct MemoryAuth {
    users: HashMap<&'static str, User>
}

impl MemoryAuth {
    pub fn with_user(&mut self, user: User) -> &mut MemoryAuth {
        match self.users.get(user.get_username()) {
            Some(us) => {
                println!("User {} exists", user.get_username());
            }
            None => self.users.insert(user.get_username(), user)
        }
        self
    }
}

impl UserAuth for MemoryAuth {
    fn get_user(self, user_name: &'static str, password: &'static str) -> Option<&User> {
        let mut user: Option<&User> = None;
        match self.users.get(user_name) {
            Some(u) => {
                if u.get_password() == password {
                    user = Some(u);
                }
            }
            None => {}
        }
        user
    }
}