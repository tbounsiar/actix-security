pub struct Access {
    roles: Vec<String>,
    authorities: Vec<String>,
}

impl Access {
    pub fn new(roles: Vec<String>, authorities: Vec<String>) -> Self {
        Access {
            roles,
            authorities,
        }
    }

    fn has_role(self, role: String) -> bool {
        self.roles.contains(&role)
    }
    fn has_authority(self, authority: String) -> bool {
        self.authorities.contains(&authority)
    }
}

pub type AccessFn = fn(access: &Access) -> bool;