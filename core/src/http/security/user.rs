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

    pub fn roles(&mut self, roles: Vec<String>) -> &mut User {
        for role in roles {
            if self.roles.contains(&role) {
                continue;
            }
            self.roles.push(role);
        }
        self
    }

    pub fn authorities(&mut self, authorities: Vec<String>) -> &mut User {
        for authority in authorities {
            if self.authorities.contains(&authority) {
                continue;
            }
            self.authorities.push(authority);
        }
        self
    }
}