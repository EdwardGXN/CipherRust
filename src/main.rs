use rsa::{PublicKey, RSAPrivateKey, PaddingScheme};
use rand::rngs::OsRng;
use std::env;
use std::fs;
use std::io::{self, Write};

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 4 {
        println!("Uso: {} <arquivo de entrada> <chave privada> <modo: 'encrypt' ou 'decrypt'>", args[0]);
        return;
    }

    let input_file = &args[1];
    let private_key_file = &args[2];
    let mode = &args[3];

    let content = match fs::read_to_string(input_file) {
        Ok(content) => content,
        Err(err) => {
            println!("Erro ao ler o arquivo {}: {}", input_file, err);
            return;
        }
    };

    let private_key = match fs::read_to_string(private_key_file) {
        Ok(key) => key,
        Err(err) => {
            println!("Erro ao ler a chave privada {}: {}", private_key_file, err);
            return;
        }
    };

    let result = match mode.as_str() {
        "encrypt" => encrypt(&content, &private_key),
        "decrypt" => decrypt(&content, &private_key),
        _ => {
            println!("Modo inválido. Use 'encrypt' ou 'decrypt'.");
            return;
        }
    };

    match result {
        Ok(output) => {
            println!("Resultado:");
            println!("{}", output);
        }
        Err(err) => {
            println!("Erro: {}", err);
        }
    }
}

fn encrypt(data: &str, private_key: &str) -> Result<String, &'static str> {
    let private_key = RSAPrivateKey::from_pkcs8(private_key.as_bytes())
        .map_err(|_| "Erro ao carregar a chave privada")?;

    let mut rng = OsRng;
    let encrypted_data = private_key
        .encrypt(&mut rng, PaddingScheme::PKCS1v15, data.as_bytes())
        .map_err(|_| "Erro ao criptografar os dados")?;

    Ok(base64::encode(&encrypted_data))
}

fn decrypt(data: &str, private_key: &str) -> Result<String, &'static str> {
    let private_key = RSAPrivateKey::from_pkcs8(private_key.as_bytes())
        .map_err(|_| "Erro ao carregar a chave privada")?;

    let mut rng = OsRng;
    let encrypted_data = base64::decode(data).map_err(|_| "Erro ao decodificar os dados")?;

    let decrypted_data = private_key
        .decrypt(&mut rng, PaddingScheme::PKCS1v15, &encrypted_data)
        .map_err(|_| "Erro ao descriptografar os dados")?;

    Ok(String::from_utf8_lossy(&decrypted_data).into_owned())
}
