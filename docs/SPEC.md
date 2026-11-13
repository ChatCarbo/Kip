# Gestionnaire de mots de passe — Spécification v1

Rust · Windows 10/11 x86_64 uniquement · local uniquement · protection maximale · faible empreinte mémoire

## 1. Objectifs

- Sécurité maximale : le vol du fichier du coffre ne doit pas permettre de récupérer les secrets.
- Rapidité : ouverture, recherche et génération instantanées ; seule la dérivation de clé est volontairement lente.
- Légèreté : cible < 40 Mo de RAM au repos, binaire unique sans dépendance externe.
- Saisie automatique dans les navigateurs dès la v1.

## 2. Hors périmètre v1

Synchronisation (réseau/cloud), multiplateforme, notes sécurisées, cartes, pièces jointes, TOTP.
Le coffre ne contient que des entrées de type identifiant / mot de passe.

## 3. Modèle de menace

| Menace | Réponse |
|---|---|
| Vol du fichier coffre | Chiffrement authentifié + Argon2id fort + liaison TPM/Windows Hello |
| Malware sans droits admin | Mitigations de processus, mémoire verrouillée et effacée, anti-capture |
| Keylogger / presse-papiers espionné | Saisie automatique sans presse-papiers, exclusion historique/cloud du presse-papiers |
| Page de phishing | Correspondance stricte du domaine avant remplissage |
| Extension malveillante / processus tiers sur le canal | Appairage authentifié, canal chiffré, validation de l'origine |
| Attaquant avec droits admin / noyau | Hors périmètre (limite assumée) |

## 4. Cryptographie

- Chiffrement du coffre : XChaCha20-Poly1305 (`chacha20poly1305`), nonce aléatoire 192 bits par écriture.
- Dérivation : Argon2id (`argon2`), paramètres calibrés au premier lancement (cible 500 ms–1 s), plancher 64 Mo / 3 passes, stockés dans l'en-tête.
- Hiérarchie de clés : clé maître (Argon2id du mot de passe) enveloppe une clé de coffre aléatoire 256 bits. Changer le mot de passe = ré-envelopper, pas re-chiffrer.
- Windows Hello : `KeyCredentialManager` (crate `windows`) signe un défi ; la signature dérive une seconde clé qui enveloppe aussi la clé de coffre (liée TPM). Le mot de passe maître reste exigé au premier lancement, après redémarrage et tous les N déverrouillages.
- Aléa : `OsRng` uniquement.
- Aucune primitive maison ; crates auditées (RustCrypto).

## 5. Format du fichier

Fichier unique `.vault`, versionné :

1. Magic + version de format
2. Paramètres Argon2id + sel
3. Clé de coffre enveloppée (mot de passe) + enveloppe Hello (optionnelle)
4. Nonce + données chiffrées (entrées sérialisées, `postcard` ou équivalent compact)
5. En-tête authentifié (AAD) pour empêcher toute modification des paramètres

Écriture atomique (temp + `MoveFileEx` remplacement), sauvegarde rotative locale (3 versions).

## 6. Hygiène mémoire et durcissement Windows

- `zeroize` + `secrecy` sur tous les secrets ; `VirtualLock` des pages sensibles.
- Entrées déchiffrées à la demande : seul l'index (titre, domaine, identifiant) est en mémoire ; les mots de passe sont déchiffrés au moment de l'usage puis effacés.
- Mitigations de processus : DEP, ASLR forcé, DLL signées uniquement, pas de processus enfant, désactivation des crash dumps (WER).
- Fenêtre de saisie exclue des captures (`SetWindowDisplayAffinity`).
- Presse-papiers : formats d'exclusion de l'historique et du cloud, effacement après 20 s.
- Verrouillage : inactivité, veille, verrouillage de session, fermeture.
- Aucun secret dans les logs, panics en mode `abort` sans message sensible.

## 7. Interface

- `iced` avec rendu logiciel `tiny-skia` (pas de GPU, faible RAM).
- Liste + recherche instantanée (filtre en mémoire), fiche entrée, générateur (OsRng, longueur/jeux configurables, mode phrase de passe diceware), indicateur de robustesse (`zxcvbn`).
- Application en zone de notification, démarrage rapide.

## 8. Saisie automatique (v1)

- Extension Chrome, Edge, Firefox (Manifest V3) + hôte natif Rust (Native Messaging).
- Appairage initial par code affiché dans l'application ; échange de clés (X25519), canal chiffré et authentifié (ChaCha20-Poly1305), clés par navigateur révocables.
- Règles de remplissage :
  - Correspondance stricte de l'hôte enregistré (liste Public Suffix, pas de sous-domaine implicite).
  - Refus dans les iframes d'origine différente et sur HTTP non sécurisé (avertissement).
  - Confirmation utilisateur (Hello) avant premier remplissage d'un site, puis option « se souvenir ».
  - Remplissage direct dans les champs, sans passer par le presse-papiers.
- Enregistrement de nouveaux identifiants et mise à jour détectés à la soumission du formulaire.
- Déverrouillage requis côté application ; l'extension ne stocke aucun secret.

## 9. Import / export

Priorité aux formats open source :

- Import v1 : KeePass `.kdbx` (3.1 et 4), KeePassXC CSV/XML, Bitwarden JSON et CSV, CSV générique (mappage de colonnes), exports Chrome/Edge/Firefox (CSV).
- Import v1.x : 1Password `.1pux`, LastPass, Dashlane.
- Export : CSV et JSON en clair (avertissement explicite, fichier supprimé en toute sécurité si possible), export `.vault` chiffré.
- Détection de doublons à l'import, rapport d'import.

## 10. Architecture (workspace Cargo)

- `vault-core` : crypto, format, modèle de données, zéro dépendance UI.
- `vault-import` : parseurs d'import/export.
- `vault-app` : interface `iced`, intégration Windows (Hello, presse-papiers, mitigations).
- `vault-host` : hôte natif Native Messaging.
- `extension/` : extension navigateur (JS/TS minimal, sans dépendance externe).

## 11. Qualité

- Tests unitaires et vecteurs de test connus (crypto, format) ; tests de propriété sur le format.
- `cargo-fuzz` sur les parseurs d'import et le canal natif.
- `cargo audit`, `cargo deny`, builds reproductibles, dépendances minimales.
- Benchmarks `criterion` : déverrouillage, recherche, import de 10 000 entrées.
- Licence open source à choisir (suggestion : GPL-3.0 ou MPL-2.0).

## 12. Jalons proposés

1. `vault-core` : crypto, format, tests, CLI de test.
2. Interface `iced` + générateur + presse-papiers + durcissement.
3. Import/export.
4. Windows Hello.
5. Hôte natif + extension + appairage.
6. Audit interne, fuzzing, durcissement final.
