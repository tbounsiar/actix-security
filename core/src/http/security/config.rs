pub trait AuthenticationManager {}

pub trait SecurityManager {}

pub trait SecurityConfigurer<A: AuthenticationManager, S: SecurityManager> {
    fn configure_authentication_manager() -> A;

    fn configure_security() -> S;
}

struct SM;

impl SecurityManager for SM {}

struct AM;

impl AuthenticationManager for AM {}

struct SC;

impl SecurityConfigurer<AM, SM> for SC {
    fn configure_authentication_manager() -> AM {
        AM {}
    }

    fn configure_security() -> SM {
        SM {}
    }
}

