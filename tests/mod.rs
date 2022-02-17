use anyhow::Result;
use hex::FromHex;
use web3_keystore::{decrypt_key, encrypt_key, new, KeyStore};

fn load_test_key(name: &str) -> Result<KeyStore> {
    let path = format!("./tests/test-keys/{}", name);
    let contents = std::fs::read_to_string(&path)?;
    let keystore: KeyStore = serde_json::from_str(&contents)?;
    Ok(keystore)
}

mod tests {
    use super::*;

    #[test]
    fn test_new() -> Result<()> {
        let mut rng = rand::thread_rng();
        let (keystore, secret) = new(&mut rng, "thebestrandompassword", None)?;

        assert_eq!(decrypt_key(&keystore, "thebestrandompassword")?, secret);
        assert!(decrypt_key(&keystore, "notthebestrandompassword").is_err());
        Ok(())
    }

    #[test]
    fn test_new_with_address() -> Result<()> {
        let mut rng = rand::thread_rng();
        let address = String::from("0xdeadbeef");
        let (keystore, secret) =
            new(&mut rng, "thebestrandompassword", Some(address))?;
        assert_eq!(decrypt_key(&keystore, "thebestrandompassword")?, secret);
        Ok(())
    }

    #[test]
    fn test_decrypt_pbkdf2() -> Result<()> {
        let secret = Vec::from_hex(
            "7a28b5ba57c53603b0b07b56bba752f7784bf506fa95edc395f5cf6c7514fe9d",
        )?;
        let keystore = load_test_key("key-pbkdf2.json")?;
        assert_eq!(decrypt_key(&keystore, "testpassword")?, secret);
        assert!(decrypt_key(&keystore, "wrongtestpassword").is_err());
        Ok(())
    }

    #[test]
    fn test_decrypt_scrypt() -> Result<()> {
        let secret = Vec::from_hex(
            "80d3a6ed7b24dcd652949bc2f3827d2f883b3722e3120b15a93a2e0790f03829",
        )
        .unwrap();
        let keystore = load_test_key("key-scrypt.json")?;
        assert_eq!(decrypt_key(&keystore, "grOQ8QDnGHvpYJf")?, secret);
        assert!(decrypt_key(&keystore, "thisisnotrandom").is_err());
        Ok(())
    }

    #[test]
    fn test_encrypt_decrypt_key() -> Result<()> {
        let secret = Vec::from_hex(
            "7a28b5ba57c53603b0b07b56bba752f7784bf506fa95edc395f5cf6c7514fe9d",
        )
        .unwrap();
        let mut rng = rand::thread_rng();
        let keystore = encrypt_key(&mut rng, &secret, "newpassword", None)?;

        assert_eq!(decrypt_key(&keystore, "newpassword")?, secret);
        assert!(decrypt_key(&keystore, "notanewpassword").is_err());
        Ok(())
    }
}
