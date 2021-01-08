pub struct Access {
    roles: Vec<&'static str>,
    authorities: Vec<&'static str>,
}

impl Access {
    pub fn new(roles: Vec<&'static str>, authorities: Vec<&'static str>) -> Self {
        Access {
            roles,
            authorities,
        }
    }

    fn has_role(self, role: &'static str) -> bool {
        self.roles.contains(&role)
    }
    fn has_authority(self, authority: &'static str) -> bool {
        self.authorities.contains(&authority)
    }
}

pub type AccessFn = fn(access: &Access) -> bool;