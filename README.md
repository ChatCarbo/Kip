<img width="512" height="512" alt="kip_512" src="https://github.com/user-attachments/assets/ef68e8c8-dcb0-4494-b03b-1068406c057a" />
# Kip

Gestionnaire de mots de passe local, rapide et sécurisé, développé en Rust pour Windows (x86_64).

## Fonctionnalités principales

- **Sécurité robuste :** Chiffrement XChaCha20-Poly1305 et dérivation Argon2id avec chiffrement par entrée.
- **Durcissement Windows :** Protection anti-capture d'écran, gestion stricte de la mémoire (`zeroize`, `secrecy`, `VirtualLock`) et verrouillage automatique.
- **Interopérabilité :** Import et export multi-formats (CSV, JSON Bitwarden, XML KeePass/KeePassXC).
- **Confidentialité totale :** Architecture 100 % locale, sans dépendance cloud.

## Architecture du projet

Le projet est structuré en un workspace Cargo :

- `vault-core` : Moteur cryptographique, format de fichier et modèle de données.
- `vault-import` : Parseurs d'import et d'export.
- `vault-app` : Interface graphique (`iced`) et intégration Windows.

## Compilation et lancement

Prérequis : Rust (avec la cible MSVC sous Windows).

```bash
rustup target add x86_64-pc-windows-msvc
cargo test --workspace
cargo run -p vault-app --release
