#[derive(Clone)]
pub struct User {
    username: String,
    password: String,
    roles: Vec<String>,
    authorities: Vec<String>,
}

impl User {
    pub fn new(username: String, password: String) -> User {
        User {
            username,
            password,
            roles: Vec::new(),
            authorities: Vec::new(),
        }
    }

    pub fn get_username(&self) -> &String {
        &self.username
    }

    pub fn get_password(&self) -> &String {
        &self.password
    }

    pub fn roles(mut self, roles: &[String]) -> User {
        for role in roles {
            if self.roles.contains(role) {
                continue;
            }
            self.roles.push(String::from(role));
        }
        self
    }

    pub fn authorities(mut self, authorities: &[String]) -> User {
        for authority in authorities {
            if self.authorities.contains(authority) {
                continue;
            }
            self.authorities.push(String::from(authority));
        }
        self
    }

    pub fn has_roles(self, roles: Vec<String>) -> bool {
        for role in roles {
            if self.roles.contains(&role) {
                return true;
            }
        }
        false
    }

    pub fn has_authority(self, authorities: Vec<String>) -> bool {
        for authority in authorities {
            if self.authorities.contains(&authority) {
                return true;
            }
        }
        false
    }
}