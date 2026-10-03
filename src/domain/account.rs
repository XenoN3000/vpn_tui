use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AccountId(pub String);

impl AccountId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }
}

impl std::fmt::Display for AccountId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Credentials {
    pub username: Option<String>,
    pub password: Option<String>,
    pub auth_group: Option<String>,
    pub cert_path: Option<String>,
    pub token: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Account {
    pub id: AccountId,
    pub name: String,
    pub description: Option<String>,
    pub credentials: Option<Credentials>,
}

impl Account {
    pub fn new(name: impl Into<String>) -> Self {
        let name_str = name.into();
        let slug = name_str
            .to_lowercase()
            .replace(' ', "-")
            .chars()
            .filter(|c| c.is_alphanumeric() || *c == '-')
            .collect::<String>();
        Self {
            id: AccountId(slug),
            name: name_str,
            description: None,
            credentials: None,
        }
    }

    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = Some(desc.into());
        self
    }

    pub fn with_credentials(mut self, creds: Credentials) -> Self {
        self.credentials = Some(creds);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_account_creation_and_slug_generation() {
        let acc = Account::new("Work Office VPN");
        assert_eq!(acc.name, "Work Office VPN");
        assert_eq!(acc.id.0, "work-office-vpn");
        assert_eq!(acc.description, None);
        assert_eq!(acc.credentials, None);
    }

    #[test]
    fn test_account_with_credentials_and_description() {
        let creds = Credentials {
            username: Some("alice".into()),
            password: Some("secret123".into()),
            auth_group: Some("Developers".into()),
            cert_path: None,
            token: None,
        };

        let acc = Account::new("Personal")
            .with_description("My personal VPN account")
            .with_credentials(creds.clone());

        assert_eq!(acc.description.as_deref(), Some("My personal VPN account"));
        assert_eq!(acc.credentials, Some(creds));
    }

    #[test]
    fn test_account_serialization_roundtrip_toml() {
        let acc = Account::new("Corporate AnyConnect").with_credentials(Credentials {
            username: Some("bob".into()),
            password: Some("p@ss".into()),
            auth_group: Some("IT".into()),
            cert_path: Some("/etc/ssl/cert.pem".into()),
            token: None,
        });

        let serialized = toml::to_string(&acc).expect("failed to serialize to TOML");
        assert!(serialized.contains("Corporate AnyConnect"));
        assert!(serialized.contains("bob"));

        let deserialized: Account = toml::from_str(&serialized).expect("failed to deserialize");
        assert_eq!(acc, deserialized);
    }
}
