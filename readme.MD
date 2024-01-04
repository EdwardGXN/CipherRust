# CipherRust

CipherRust é uma ferramenta simples para criptografar e descriptografar dados usando o algoritmo RSA em Rust.

## Requisitos

Certifique-se de ter o [Rust](https://www.rust-lang.org/tools/install) instalado em seu sistema.

## Uso

### Compilar o programa

```bash
cargo build
```
Executar com argumentos
```bash
cargo run -- <arquivo de entrada> <chave privada> <modo: 'encrypt' ou 'decrypt'>
```
Criptografar
```bash
cargo run -- texto.txt chave_privada.pem encrypt
```
Decriptografar
```bash
cargo run -- texto_criptografado.txt chave_privada.pem decrypt
```

# Autor
**EdwardGNX**