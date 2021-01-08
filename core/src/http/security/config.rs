use crate::http::security::user::User;

pub trait Authenticator {
    fn get_user(username: &'static str, password: &'static str) -> Option<User>;
}

pub trait Authorizer {
    fn authorize(user: &User) -> bool;
}

pub trait SecurityConfigurator<A: Authenticator, S: Authorizer> {
    fn configure_authenticator() -> A;

    fn configure_authorizer() -> S;
}

