pub trait User {

}

pub struct UserD {
    username: &'static str,
    password: &'static str,
    roles: Vec<&'static str>,
    authorities: Vec<&'static str>,
}

impl UserD {
    pub fn new(username: &'static str, password: &'static str) -> User {
        User {
            username,
            password,
            roles: Vec::new(),
            authorities: Vec::new(),
        }
    }

    pub fn get_username(self) -> &'static str {
        self.username
    }

    pub fn get_password(self) -> &'static str {
        self.password
    }

    pub fn roles(&mut self, roles: Vec<&'static str>) -> User {
        for role in roles {
            if self.roles.contains(&role) {
                continue;
            }
            self.roles.push(role);
        }
        self;
    }

    pub fn authorities(&mut self, authorities: Vec<&'static str>) -> User {
        for authority in authorities {
            if self.authorities.contains(&authority) {
                continue;
            }
            self.authorities.push(authority);
        }
        self;
    }
}