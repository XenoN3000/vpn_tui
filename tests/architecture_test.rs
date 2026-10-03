use vpn_tui::domain::account::Account;

#[test]
fn test_clean_architecture_modules_compile() {
    let acc = Account::new("Smoke");
    assert_eq!(acc.name, "Smoke");
}
