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

    pub fn roles(&mut self, roles: Vec<String>) -> User {
        for role in roles {
            if self.roles.contains(&role) {
                continue;
            }
            self.roles.push(role);
        }
        self;
    }
}