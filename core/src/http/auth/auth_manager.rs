use crate::http::auth::user::User;

pub struct AuthManager {}

impl AuthManager {
    pub fn in_memory_auth() -> MemoryAuth {
        MemoryAuth {
            users: Vec::new()
        }
    }
}

pub struct MemoryAuth {
    users: Vec<User>
}

impl MemoryAuth {
    pub fn with_user(&mut self, user: User) -> &mut MemoryAuth {
        match self.users.iter().find(|u| u.get_username() == user.get_username()) {
            Some(us) => {}
            None => self.users.push(user)
        }
        self
    }
}