<img width="1280" height="512" alt="preview" src="https://github.com/user-attachments/assets/216c8a31-67c5-45c0-be04-1563ac4eec8a" />

# Kip

Gestionnaire de mots de passe **local**, rapide et sécurisé, écrit en Rust pour Windows (x86_64).
Pas de compte, pas de cloud, pas de télémétrie : votre coffre est un simple fichier chiffré sur votre disque.

## Fonctionnalités principales

- **Chiffrement robuste** : XChaCha20-Poly1305, clé dérivée par Argon2id (64 Mio et 3 passes minimum, calibrée automatiquement pour environ 700 ms sur votre machine). Chaque mot de passe est chiffré individuellement dans le coffre.
- **Format authentifié** : les paramètres Argon2id et l'identifiant du coffre sont protégés, toute modification de l'en-tête fait échouer le déchiffrement.
- **Durcissement Windows** : mémoire effacée après usage (`zeroize`, `secrecy`), pages sensibles verrouillées en RAM (`VirtualLock`), fenêtres exclues des captures d'écran, politique de gestion des plantages.
- **Verrouillage automatique** : après 5 minutes d'inactivité ou au verrouillage de la session Windows.
- **Presse-papiers prudent** : le mot de passe copié est effacé après 20 secondes.
- **Générateur** : mots de passe (longueur, minuscules, majuscules, chiffres, symboles, exclusion des caractères ambigus) et phrases de passe à partir de la liste EFF.
- **Recherche rapide** parmi vos entrées (titre, URL, identifiant).
- **Sauvegardes automatiques** : copies `.bak1`, `.bak2`… tournantes à côté du coffre, écriture atomique.
- **Import / export** :
  - import CSV (Chrome, Edge, Firefox, Bitwarden, KeePassXC, LastPass, 1Password, Dashlane, RoboForm, ou tout CSV à en-tête reconnaissable), JSON Bitwarden non chiffré, XML KeePass / KeePassXC ;
  - export CSV et JSON Bitwarden **en clair** : supprimez ces fichiers après usage.
  - Le format `.kdbx` chiffré n'est pas encore pris en charge : exportez depuis KeePass en XML ou CSV.
- **Interface FR / EN** (selon la langue de Windows) et icône dans la zone de notification.

## Premiers pas

1. Lancez `kip.exe` : au premier démarrage, créez votre coffre avec un **mot de passe maître d'au moins 12 caractères**. Il n'est pas récupérable : si vous le perdez, le coffre est définitivement illisible.
2. Le coffre est enregistré par défaut dans `%APPDATA%\gestionnaire-mdp\coffre.vault`.
3. Pour les phrases de passe, placez le fichier `eff_large_wordlist.txt` dans le même dossier que le coffre.
Options en ligne de commande :

| Option | Rôle |
|---|---|
| `--vault <chemin>` | ouvre un coffre à un autre emplacement |
| `--compat` | désactive certains durcissements (capture d'écran, méthodes de saisie) en cas d'incompatibilité |

## Architecture du projet

Le projet est structuré en un workspace Cargo :

| `vault-core` | moteur cryptographique, format de fichier, modèle de données, générateur, recherche (aucun code `unsafe`) |
| `vault-import` | lecteurs et écrivains d'import / export |
| `vault-app` | interface graphique `iced` (rendu logiciel, sans GPU) et intégration Windows (seul code `unsafe`) |

Le format du fichier `.vault` (version 2) est documenté en tête de `vault-core/src/header.rs`. Il réserve un emplacement pour une enveloppe Windows Hello, **pas encore active dans l'interface**.

## Compilation

Prérequis : Rust avec la cible MSVC.

```bash
rustup target add x86_64-pc-windows-msvc
cargo test --workspace
cargo run -p vault-app --release
```

L'exécutable se trouve ensuite dans `target/release/kip.exe`.

## Limites connues

- Windows uniquement.
- Pas de lecture `.kdbx`, pas de saisie automatique dans les navigateurs.
- Projet non audité par un tiers : à utiliser en connaissance de cause.

## Licence

GPL-3.0-or-later. Voir le fichier [LICENSE](LICENSE).



