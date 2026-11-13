//! Gestionnaire de mots de passe : interface iced (rendu logiciel) et intégration Windows.

#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]

mod i18n;
mod timers;
mod util;
mod winsec;

use std::fmt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime};

use iced::alignment::Horizontal;
use iced::widget::{
    button, checkbox, column, container, horizontal_rule, row, scrollable, slider, text,
    text_input, vertical_rule, Column,
};
use iced::{
    executor, theme, window, Alignment, Application, Color, Command, Element, Length, Settings,
    Size, Subscription, Theme,
};
use vault_core::generator::password_entropy_bits;
use vault_core::storage::{self, DEFAULT_BACKUPS, DEFAULT_BACKUP_INTERVAL};
use vault_core::{Entry, PasswordOptions, Vault};
use vault_import::{export_bitwarden_json, export_csv, ExportEntry, Fingerprint};
use zeroize::Zeroizing;

use i18n::Lang;
use timers::{AutoLock, ClipboardTimer, LockReason};
use util::Handoff;

/// Inactivité avant verrouillage automatique.
const IDLE_TIMEOUT: Duration = Duration::from_secs(300);
/// Durée de vie d'une copie dans le presse-papiers.
const CLIPBOARD_TTL: Duration = Duration::from_secs(20);
/// Longueur minimale du mot de passe maître.
const MIN_MASTER_LEN: usize = 12;
/// Temps visé pour la dérivation de clé, calibré à la création du coffre.
const KDF_TARGET: Duration = Duration::from_millis(700);
const ERROR_COLOR: Color = Color::from_rgb(0.90, 0.33, 0.33);

// ------------------------------------------------------------------ secrets

/// Texte secret : effacé de la mémoire à la libération, jamais affiché par `Debug`.
/// Limite connue : iced copie la saisie dans ses propres tampons, que l'on ne contrôle pas.
#[derive(Clone, Default)]
struct Secret(Zeroizing<String>);

impl Secret {
    fn new(value: String) -> Self {
        Self(Zeroizing::new(value))
    }

    fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(***)")
    }
}

// ----------------------------------------------------------------- travaux

/// Exécute un travail bloquant sur un fil dédié, sans geler l'interface.
async fn blocking<T, F>(job: F) -> T
where
    T: Send + 'static,
    F: FnOnce() -> T + Send + 'static,
{
    let (sender, receiver) = iced::futures::channel::oneshot::channel();
    std::thread::spawn(move || {
        let _ = sender.send(job());
    });
    receiver.await.expect("le fil de travail s'est arrêté")
}

fn create_vault(path: &Path, password: Secret, lang: Lang) -> Result<Vault, String> {
    let kdf = vault_core::calibrate_kdf(KDF_TARGET).map_err(|e| lang.core_error(&e))?;
    let vault =
        Vault::create(password.as_str().as_bytes(), kdf).map_err(|e| lang.core_error(&e))?;
    let bytes = vault.seal().map_err(|e| lang.core_error(&e))?;
    storage::save_atomic(path, &bytes, DEFAULT_BACKUPS, DEFAULT_BACKUP_INTERVAL)
        .map_err(|e| lang.detail("Écriture impossible", "Cannot write the file", e))?;
    // Relit le fichier pour être sûr que ce qui est sur le disque est ce qu'on a produit.
    match storage::load(path) {
        Ok(Some(on_disk)) if on_disk == bytes => Ok(vault),
        _ => Err(lang
            .t(
                "Le coffre écrit sur le disque ne correspond pas : création annulée.",
                "The vault written to disk does not match: creation cancelled.",
            )
            .into()),
    }
}

fn open_vault(path: &Path, password: Secret, lang: Lang) -> Result<Vault, String> {
    let bytes = match storage::load(path) {
        Ok(Some(bytes)) => bytes,
        Ok(None) => return Err(lang.t("Coffre introuvable.", "Vault not found.").into()),
        Err(e) => return Err(lang.detail("Lecture impossible", "Cannot read the file", e)),
    };
    Vault::open(&bytes, password.as_str().as_bytes()).map_err(|e| lang.core_error(&e))
}

/// Ce qui a été copié dans le presse-papiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Copied {
    Password,
    Username,
}

fn copied_notice(lang: Lang, what: Copied, seconds: u64) -> String {
    let label = match (what, lang) {
        (Copied::Password, Lang::Fr) => "Mot de passe copié",
        (Copied::Username, Lang::Fr) => "Identifiant copié",
        (Copied::Password, Lang::En) => "Password copied",
        (Copied::Username, Lang::En) => "Username copied",
    };
    match lang {
        Lang::Fr => format!("{label}. Effacement du presse-papiers dans {seconds} s."),
        Lang::En => format!("{label}. The clipboard will be cleared in {seconds} s."),
    }
}

/// Textes de l'icône de la zone de notification.
fn tray_text(lang: Lang) -> winsec::TrayText {
    winsec::TrayText {
        tooltip: winsec::WINDOW_TITLE.to_string(),
        open: lang.t("Ouvrir Kip", "Open Kip").to_string(),
        lock: lang.t("Verrouiller", "Lock").to_string(),
        quit: lang.t("Quitter", "Quit").to_string(),
    }
}

fn wordlist_path(vault_path: &Path) -> PathBuf {
    vault_path.with_file_name("eff_large_wordlist.txt")
}

// ------------------------------------------------------------------ éditeur

/// Formulaire d'ajout ou de modification d'une entrée.
struct Editor {
    id: Option<[u8; 16]>,
    title: String,
    url: String,
    username: String,
    password: Secret,
    show_password: bool,
    options: PasswordOptions,
    passphrase: bool,
    words: u8,
    entropy: Option<f64>,
}

impl Editor {
    fn new() -> Self {
        Self {
            id: None,
            title: String::new(),
            url: String::new(),
            username: String::new(),
            password: Secret::default(),
            show_password: false,
            options: PasswordOptions::default(),
            passphrase: false,
            words: 6,
            entropy: None,
        }
    }

    fn from_entry(entry: &Entry) -> Self {
        Self {
            id: Some(entry.id),
            title: entry.title.clone(),
            url: entry.url.clone(),
            username: entry.username.clone(),
            // Le mot de passe n'est pas déchiffré pour l'édition : champ vide = inchangé.
            password: Secret::default(),
            ..Self::new()
        }
    }
}

// ------------------------------------------------------------ import / export

/// Écran d'import ou d'export de fichier.
struct Transfer {
    import: bool,
    path: String,
    /// Export : JSON Bitwarden plutôt que CSV.
    json: bool,
    /// Export : l'utilisateur a confirmé avoir compris que le fichier est en clair.
    understood: bool,
}

impl Transfer {
    fn new(import: bool) -> Self {
        Self {
            import,
            path: String::new(),
            json: false,
            understood: false,
        }
    }
}

/// « Copier en tant que chemin » de l'explorateur Windows entoure le chemin de guillemets.
fn clean_path(raw: &str) -> PathBuf {
    PathBuf::from(raw.trim().trim_matches('"'))
}

// ----------------------------------------------------------------- messages

#[derive(Debug, Clone)]
enum Message {
    MasterChanged(Secret),
    ConfirmChanged(Secret),
    Submit,
    Opened(Handoff<Result<Vault, String>>),
    Tick,
    LockNow,
    SetLang(Lang),

    SearchChanged(String),
    Select([u8; 16]),
    NewEntry,
    EditSelected,
    AskDelete,
    ConfirmDelete,
    CancelDelete,
    ShowPassword(bool),
    CopyPassword,
    CopyUsername,

    TitleChanged(String),
    UrlChanged(String),
    UsernameChanged(String),
    PasswordChanged(Secret),
    ShowEditorPassword(bool),
    LengthChanged(u8),
    LowercaseToggled(bool),
    UppercaseToggled(bool),
    DigitsToggled(bool),
    SymbolsToggled(bool),
    AmbiguousToggled(bool),
    PassphraseToggled(bool),
    WordsChanged(u8),
    Generate,
    SaveEntry,
    CancelEdit,

    OpenImport,
    OpenExport,
    TransferPath(String),
    TransferJson(bool),
    TransferUnderstood(bool),
    RunTransfer,
    CloseTransfer,
}

// ---------------------------------------------------------------- application

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Screen {
    Setup,
    Unlock,
    Vault,
}

struct Flags {
    path: PathBuf,
    hardening: (usize, usize),
    lang: Lang,
}

struct App {
    path: PathBuf,
    lang: Lang,
    lang_path: PathBuf,
    screen: Screen,
    busy: bool,
    error: Option<String>,
    notice: Option<String>,
    hardening: (usize, usize),
    window_protected: bool,

    master: Secret,
    confirm: Secret,

    vault: Option<Vault>,
    search: String,
    selected: Option<[u8; 16]>,
    confirm_delete: bool,
    show_password: bool,
    editor: Option<Editor>,
    transfer: Option<Transfer>,

    autolock: AutoLock,
    /// Copie en cours : échéance d'effacement et ce qui a été copié.
    clipboard: Option<(ClipboardTimer, Copied)>,
}

impl App {
    fn lock(&mut self, reason: Option<LockReason>) {
        if let Some(vault) = self.vault.take() {
            // On relâche le verrouillage mémoire avant la destruction : la clé est
            // effacée à la libération (`Zeroizing`).
            let (ptr, len) = vault.key_region();
            winsec::unlock_memory(ptr, len);
            drop(vault);
        }
        winsec::clipboard_clear_pending();
        self.clipboard = None;
        self.editor = None;
        self.transfer = None;
        self.selected = None;
        self.confirm_delete = false;
        self.show_password = false;
        self.search.clear();
        self.master = Secret::default();
        self.confirm = Secret::default();
        self.busy = false;
        self.error = None;
        let lang = self.lang;
        self.notice = Some(
            match reason {
                Some(reason) => reason.message(lang == Lang::En),
                None => lang.t("Coffre verrouillé.", "Vault locked."),
            }
            .to_string(),
        );
        self.screen = Screen::Unlock;
    }

    fn enter_vault(&mut self, vault: Vault) {
        let (ptr, len) = vault.key_region();
        // Au mieux : si Windows refuse, le coffre fonctionne quand même.
        winsec::lock_memory(ptr, len);
        self.vault = Some(vault);
        self.autolock.reset(Instant::now(), SystemTime::now());
        self.screen = Screen::Vault;
        self.error = None;
        self.notice = None;
        self.selected = None;
        self.search.clear();
    }

    fn persist(&self) -> Result<(), String> {
        let lang = self.lang;
        let vault = self
            .vault
            .as_ref()
            .ok_or(lang.t("Coffre verrouillé.", "Vault locked."))?;
        let bytes = vault.seal().map_err(|e| lang.core_error(&e))?;
        storage::save_atomic(&self.path, &bytes, DEFAULT_BACKUPS, DEFAULT_BACKUP_INTERVAL)
            .map_err(|e| lang.detail("Écriture impossible", "Cannot write the file", e))
    }

    fn submit(&mut self) -> Command<Message> {
        if self.busy {
            return Command::none();
        }
        self.error = None;
        self.notice = None;
        let path = self.path.clone();
        let lang = self.lang;
        match self.screen {
            Screen::Setup => {
                if self.master.as_str().chars().count() < MIN_MASTER_LEN {
                    self.error = Some(match lang {
                        Lang::Fr => format!(
                            "Le mot de passe maître doit faire au moins {MIN_MASTER_LEN} caractères."
                        ),
                        Lang::En => format!(
                            "The master password must be at least {MIN_MASTER_LEN} characters long."
                        ),
                    });
                    return Command::none();
                }
                if self.master.as_str() != self.confirm.as_str() {
                    self.error = Some(
                        lang.t(
                            "Les deux saisies ne correspondent pas.",
                            "The two entries do not match.",
                        )
                        .into(),
                    );
                    return Command::none();
                }
                self.busy = true;
                let password = std::mem::take(&mut self.master);
                self.confirm = Secret::default();
                Command::perform(blocking(move || create_vault(&path, password, lang)), |result| {
                    Message::Opened(Handoff::new(result))
                })
            }
            Screen::Unlock => {
                if self.master.as_str().is_empty() {
                    return Command::none();
                }
                self.busy = true;
                let password = std::mem::take(&mut self.master);
                Command::perform(blocking(move || open_vault(&path, password, lang)), |result| {
                    Message::Opened(Handoff::new(result))
                })
            }
            Screen::Vault => Command::none(),
        }
    }

    fn copy(&mut self, password: bool) {
        let lang = self.lang;
        let Some(id) = self.selected else {
            return;
        };
        let Some(vault) = self.vault.as_ref() else {
            return;
        };
        let Some(entry) = vault.entry(&id) else {
            return;
        };
        // Le mot de passe n'est déchiffré que pour cette copie, puis effacé.
        let secret;
        let (value, what) = if password {
            secret = match vault.password(&id) {
                Ok(p) => p,
                Err(e) => {
                    self.error = Some(lang.core_error(&e));
                    return;
                }
            };
            (secret.as_str(), Copied::Password)
        } else {
            (entry.username.as_str(), Copied::Username)
        };
        match winsec::clipboard_set_sensitive(value) {
            Ok(()) => {
                self.clipboard = Some((ClipboardTimer::new(Instant::now(), CLIPBOARD_TTL), what));
                self.notice = Some(copied_notice(lang, what, CLIPBOARD_TTL.as_secs()));
                self.error = None;
            }
            Err(_) => {
                self.error = Some(
                    lang.t("Presse-papiers indisponible.", "Clipboard unavailable.")
                        .into(),
                )
            }
        }
    }

    fn generate(&mut self) {
        let Some(editor) = self.editor.as_mut() else {
            return;
        };
        if editor.passphrase {
            let path = wordlist_path(&self.path);
            let Ok(list) = std::fs::read_to_string(&path) else {
                let folder = path
                    .parent()
                    .map_or(String::new(), |p| p.display().to_string());
                self.error = Some(match self.lang {
                    Lang::Fr => format!(
                        "Liste de mots introuvable. Placez eff_large_wordlist.txt dans {folder}."
                    ),
                    Lang::En => format!(
                        "Word list not found. Place eff_large_wordlist.txt in {folder}."
                    ),
                });
                return;
            };
            let words = vault_core::generator::parse_wordlist(&list);
            match vault_core::generate_passphrase(&words, usize::from(editor.words), "-", true) {
                Ok(phrase) => {
                    editor.password = Secret(phrase);
                    editor.entropy = Some(f64::from(editor.words) * (words.len() as f64).log2());
                    self.error = None;
                }
                Err(e) => self.error = Some(self.lang.core_error(&e)),
            }
        } else {
            match vault_core::generate_password(&editor.options) {
                Ok(password) => {
                    editor.password = Secret(password);
                    editor.entropy = Some(password_entropy_bits(&editor.options));
                    self.error = None;
                }
                Err(e) => self.error = Some(self.lang.core_error(&e)),
            }
        }
    }

    /// Applique le formulaire au coffre et l'enregistre. Renvoie l'identifiant de l'entrée.
    fn apply_editor(&mut self, editor: &Editor) -> Result<[u8; 16], String> {
        let title = editor.title.trim().to_string();
        let url = editor.url.trim().to_string();
        let username = editor.username.trim().to_string();
        let lang = self.lang;
        let vault = self
            .vault
            .as_mut()
            .ok_or(lang.t("Coffre verrouillé.", "Vault locked."))?;

        let id = match editor.id {
            Some(id) => {
                // Champ vide : on garde le mot de passe actuel.
                let new_password =
                    Some(editor.password.as_str()).filter(|p| !p.is_empty());
                vault
                    .update(&id, &title, &url, &username, new_password)
                    .map_err(|e| lang.core_error(&e))?;
                id
            }
            None => vault
                .add(&title, &url, &username, editor.password.as_str())
                .map_err(|e| lang.core_error(&e))?,
        };
        self.persist()?;
        Ok(id)
    }

    fn open_transfer(&mut self, import: bool) {
        self.transfer = Some(Transfer::new(import));
        self.editor = None;
        self.error = None;
        self.notice = None;
    }

    fn run_transfer(&mut self) {
        let Some(transfer) = self.transfer.as_ref() else {
            return;
        };
        let path = clean_path(&transfer.path);
        let (import, understood, json) = (transfer.import, transfer.understood, transfer.json);
        if path.as_os_str().is_empty() {
            self.error = Some(
                self.lang
                    .t("Indiquez le chemin du fichier.", "Enter the file path.")
                    .into(),
            );
            return;
        }
        let outcome = if import {
            self.import_file(&path)
        } else if !understood {
            Err(self
                .lang
                .t(
                    "Cochez la case pour confirmer que vous avez compris le risque.",
                    "Tick the box to confirm that you understand the risk.",
                )
                .to_string())
        } else {
            let lang = self.lang;
            self.export_file(&path, json).map(|count| match lang {
                Lang::Fr => format!(
                    "{count} entrée(s) exportée(s) dans {}. Ce fichier contient tous vos mots de \
                     passe en clair : supprimez-le dès que vous n'en avez plus besoin.",
                    path.display()
                ),
                Lang::En => format!(
                    "{count} entry(ies) exported to {}. This file contains all your passwords in \
                     clear text: delete it as soon as you no longer need it.",
                    path.display()
                ),
            })
        };
        match outcome {
            Ok(summary) => {
                self.notice = Some(summary);
                self.error = None;
                self.transfer = None;
            }
            Err(message) => self.error = Some(message),
        }
    }

    /// Lit un fichier d'un autre gestionnaire et ajoute au coffre ce qui n'y est pas déjà.
    fn import_file(&mut self, path: &Path) -> Result<String, String> {
        let lang = self.lang;
        let size = std::fs::metadata(path)
            .map_err(|e| lang.detail("Fichier illisible", "Cannot read the file", e))?
            .len();
        if size > vault_import::MAX_FILE_SIZE as u64 {
            return Err(lang.import_error(&vault_import::ImportError::TooLarge));
        }
        // Le contenu brut du fichier est effacé de la mémoire dès l'analyse terminée.
        let bytes = Zeroizing::new(
            std::fs::read(path).map_err(|e| lang.detail("Lecture impossible", "Cannot read the file", e))?,
        );
        let mut parsed =
            vault_import::parse(&bytes, None).map_err(|e| lang.import_error(&e))?;
        drop(bytes);

        let vault = self
            .vault
            .as_mut()
            .ok_or(lang.t("Coffre verrouillé.", "Vault locked."))?;
        // Chaque mot de passe est déchiffré un instant, le temps d'en calculer l'empreinte.
        let mut existing: Vec<Fingerprint> = Vec::with_capacity(vault.entries().len());
        for e in vault.entries() {
            let password = vault.password(&e.id).map_err(|err| lang.core_error(&err))?;
            existing.push(Fingerprint::new(&e.url, &e.username, password.as_str()));
        }
        vault_import::dedup(&existing, &mut parsed);

        let report = parsed.report.clone();
        let mut added = 0;
        for imported in parsed.entries {
            vault
                .add(
                    &imported.title,
                    &imported.url,
                    &imported.username,
                    imported.password.as_str(),
                )
                .map_err(|e| lang.core_error(&e))?;
            added += 1;
        }
        if added > 0 {
            self.persist()?;
        }
        Ok(lang.import_summary(&report, added))
    }

    /// Écrit tout le coffre, en clair, dans un nouveau fichier. N'écrase jamais un fichier existant.
    fn export_file(&self, path: &Path, json: bool) -> Result<usize, String> {
        use std::io::{ErrorKind, Write};

        let lang = self.lang;
        let vault = self
            .vault
            .as_ref()
            .ok_or(lang.t("Coffre verrouillé.", "Vault locked."))?;
        // L'export est par nature en clair : on déchiffre tout, ici seulement.
        let mut passwords: Vec<Zeroizing<String>> = Vec::with_capacity(vault.entries().len());
        for e in vault.entries() {
            passwords.push(vault.password(&e.id).map_err(|err| lang.core_error(&err))?);
        }
        let items: Vec<ExportEntry<'_>> = vault
            .entries()
            .iter()
            .zip(&passwords)
            .map(|(e, password)| ExportEntry {
                title: &e.title,
                url: &e.url,
                username: &e.username,
                password: password.as_str(),
            })
            .collect();
        let content = Zeroizing::new(if json {
            export_bitwarden_json(&items)
        } else {
            export_csv(&items)
        });
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .map_err(|e| {
                if e.kind() == ErrorKind::AlreadyExists {
                    lang.t(
                        "Ce fichier existe déjà : choisissez un autre nom.",
                        "This file already exists: choose another name.",
                    )
                    .to_string()
                } else {
                    lang.detail("Création impossible", "Cannot create the file", e)
                }
            })?;
        file.write_all(content.as_bytes())
            .and_then(|()| file.sync_all())
            .map_err(|e| lang.detail("Écriture impossible", "Cannot write the file", e))?;
        Ok(items.len())
    }

    fn visible_entries(&self) -> Vec<&Entry> {
        let Some(vault) = &self.vault else {
            return Vec::new();
        };
        let mut scored: Vec<(u32, &Entry)> = vault
            .entries()
            .iter()
            .filter_map(|entry| {
                let fields = [
                    entry.title.as_str(),
                    entry.url.as_str(),
                    entry.username.as_str(),
                ];
                vault_core::search::score(&self.search, &fields).map(|s| (s, entry))
            })
            .collect();
        scored.sort_by(|a, b| {
            a.0.cmp(&b.0)
                .then_with(|| a.1.title.to_lowercase().cmp(&b.1.title.to_lowercase()))
        });
        scored.into_iter().map(|(_, entry)| entry).collect()
    }

    fn selected_entry(&self) -> Option<&Entry> {
        let id = self.selected?;
        self.vault.as_ref()?.entry(&id)
    }
}

impl Application for App {
    type Executor = executor::Default;
    type Message = Message;
    type Theme = Theme;
    type Flags = Flags;

    fn new(flags: Flags) -> (Self, Command<Message>) {
        let screen = if flags.path.exists() {
            Screen::Unlock
        } else {
            Screen::Setup
        };
        let lang_path = flags.path.with_file_name("kip.lang");
        let app = App {
            path: flags.path,
            lang: flags.lang,
            lang_path,
            screen,
            busy: false,
            error: None,
            notice: None,
            hardening: flags.hardening,
            window_protected: false,
            master: Secret::default(),
            confirm: Secret::default(),
            vault: None,
            search: String::new(),
            selected: None,
            confirm_delete: false,
            show_password: false,
            editor: None,
            transfer: None,
            autolock: AutoLock::new(IDLE_TIMEOUT, Instant::now(), SystemTime::now()),
            clipboard: None,
        };
        (app, Command::none())
    }

    fn title(&self) -> String {
        winsec::WINDOW_TITLE.into()
    }

    fn theme(&self) -> Theme {
        Theme::Nord
    }

    fn subscription(&self) -> Subscription<Message> {
        iced::time::every(Duration::from_secs(1)).map(|_| Message::Tick)
    }

    fn update(&mut self, message: Message) -> Command<Message> {
        match message {
            Message::MasterChanged(value) => self.master = value,
            Message::ConfirmChanged(value) => self.confirm = value,
            Message::Submit => return self.submit(),
            Message::Opened(handoff) => {
                self.busy = false;
                match handoff.take() {
                    Some(Ok(vault)) => self.enter_vault(vault),
                    Some(Err(message)) => self.error = Some(message),
                    None => {
                        self.error = Some(
                            self.lang
                                .t("Résultat indisponible.", "Result unavailable.")
                                .into(),
                        )
                    }
                }
            }
            Message::Tick => {
                let mono = Instant::now();
                let wall = SystemTime::now();
                if !self.window_protected && winsec::exclude_windows_from_capture() > 0 {
                    self.window_protected = true;
                }
                if let Some((timer, what)) = self.clipboard {
                    if timer.due(mono) {
                        winsec::clipboard_clear_pending();
                        self.clipboard = None;
                        self.notice = Some(
                            self.lang
                                .t("Presse-papiers effacé.", "Clipboard cleared.")
                                .into(),
                        );
                    } else {
                        // Arrondi vers le haut : jamais « 0 s » avant l'effacement.
                        let left = timer.remaining(mono).as_secs() + 1;
                        self.notice = Some(copied_notice(self.lang, what, left));
                    }
                }
                if self.vault.is_some() {
                    let idle = winsec::idle_time();
                    if let Some(reason) =
                        self.autolock
                            .tick(mono, wall, idle, winsec::session_locked())
                    {
                        self.lock(Some(reason));
                    }
                }
                // Demandes du menu de l'icône de la zone de notification.
                match winsec::take_tray_request() {
                    Some(winsec::TrayRequest::Lock) => {
                        if self.vault.is_some() {
                            self.lock(None);
                        }
                    }
                    Some(winsec::TrayRequest::Quit) => return window::close(window::Id::MAIN),
                    None => {}
                }
            }
            Message::LockNow => self.lock(None),
            Message::SetLang(lang) => {
                self.lang = lang;
                lang.save(&self.lang_path);
                winsec::set_tray_text(tray_text(lang));
                // Les messages déjà affichés sont dans l'ancienne langue : on les retire.
                self.error = None;
                self.notice = None;
            }

            Message::SearchChanged(value) => self.search = value,
            Message::Select(id) => {
                self.selected = Some(id);
                self.editor = None;
                self.transfer = None;
                self.confirm_delete = false;
                self.show_password = false;
                self.error = None;
                self.notice = None;
            }
            Message::NewEntry => {
                self.editor = Some(Editor::new());
                self.transfer = None;
                self.error = None;
                self.notice = None;
            }
            Message::EditSelected => {
                self.editor = self.selected_entry().map(Editor::from_entry);
                self.transfer = None;
                self.error = None;
                self.notice = None;
            }
            Message::AskDelete => self.confirm_delete = true,
            Message::CancelDelete => self.confirm_delete = false,
            Message::ConfirmDelete => {
                if let (Some(id), Some(vault)) = (self.selected, self.vault.as_mut()) {
                    // Le retrait détruit l'entrée : son mot de passe est effacé.
                    vault.remove(&id);
                }
                self.selected = None;
                self.confirm_delete = false;
                self.error = self.persist().err();
            }
            Message::ShowPassword(show) => self.show_password = show,
            Message::CopyPassword => self.copy(true),
            Message::CopyUsername => self.copy(false),

            Message::TitleChanged(v) => self.with_editor(|e| e.title = v),
            Message::UrlChanged(v) => self.with_editor(|e| e.url = v),
            Message::UsernameChanged(v) => self.with_editor(|e| e.username = v),
            Message::PasswordChanged(v) => self.with_editor(|e| {
                e.password = v;
                e.entropy = None;
            }),
            Message::ShowEditorPassword(v) => self.with_editor(|e| e.show_password = v),
            Message::LengthChanged(v) => self.with_editor(|e| e.options.length = usize::from(v)),
            Message::LowercaseToggled(v) => self.with_editor(|e| e.options.lowercase = v),
            Message::UppercaseToggled(v) => self.with_editor(|e| e.options.uppercase = v),
            Message::DigitsToggled(v) => self.with_editor(|e| e.options.digits = v),
            Message::SymbolsToggled(v) => self.with_editor(|e| e.options.symbols = v),
            Message::AmbiguousToggled(v) => self.with_editor(|e| e.options.avoid_ambiguous = v),
            Message::PassphraseToggled(v) => self.with_editor(|e| e.passphrase = v),
            Message::WordsChanged(v) => self.with_editor(|e| e.words = v),
            Message::Generate => self.generate(),
            Message::SaveEntry => {
                let Some(editor) = self.editor.take() else {
                    return Command::none();
                };
                if editor.title.trim().is_empty() {
                    self.error = Some(
                        self.lang
                            .t("Le titre est obligatoire.", "The title is required.")
                            .into(),
                    );
                    self.editor = Some(editor);
                } else if editor.id.is_none() && editor.password.as_str().is_empty() {
                    self.error = Some(
                        self.lang
                            .t(
                                "Le mot de passe est vide : saisissez-le ou générez-en un.",
                                "The password is empty: type one or generate one.",
                            )
                            .into(),
                    );
                    self.editor = Some(editor);
                } else {
                    match self.apply_editor(&editor) {
                        Ok(id) => {
                            self.selected = Some(id);
                            self.show_password = false;
                            self.error = None;
                            self.notice =
                                Some(self.lang.t("Entrée enregistrée.", "Entry saved.").into());
                        }
                        Err(message) => {
                            self.error = Some(message);
                            self.editor = Some(editor);
                        }
                    }
                }
            }
            Message::CancelEdit => {
                self.editor = None;
                self.error = None;
            }

            Message::OpenImport => self.open_transfer(true),
            Message::OpenExport => self.open_transfer(false),
            Message::TransferPath(v) => {
                if let Some(transfer) = self.transfer.as_mut() {
                    transfer.path = v;
                }
            }
            Message::TransferJson(v) => {
                if let Some(transfer) = self.transfer.as_mut() {
                    transfer.json = v;
                }
            }
            Message::TransferUnderstood(v) => {
                if let Some(transfer) = self.transfer.as_mut() {
                    transfer.understood = v;
                }
            }
            Message::RunTransfer => self.run_transfer(),
            Message::CloseTransfer => {
                self.transfer = None;
                self.error = None;
            }
        }
        Command::none()
    }

    fn view(&self) -> Element<'_, Message> {
        match self.screen {
            Screen::Setup | Screen::Unlock => self.view_auth(),
            Screen::Vault => self.view_vault(),
        }
    }
}

impl App {
    fn with_editor(&mut self, change: impl FnOnce(&mut Editor)) {
        if let Some(editor) = self.editor.as_mut() {
            change(editor);
        }
    }

    fn error_line(&self) -> Element<'_, Message> {
        match &self.error {
            Some(message) => text(message.as_str())
                .size(14)
                .style(theme::Text::Color(ERROR_COLOR))
                .into(),
            None => text("").into(),
        }
    }

    fn notice_line(&self) -> Element<'_, Message> {
        match &self.notice {
            Some(message) => text(message.as_str()).size(14).into(),
            None => text("").into(),
        }
    }

    /// Boutons FR / EN.
    fn lang_switch(&self) -> Element<'_, Message> {
        let style = |lang: Lang| {
            if self.lang == lang {
                theme::Button::Primary
            } else {
                theme::Button::Secondary
            }
        };
        row![
            button(text("FR").size(12))
                .padding([4, 8])
                .style(style(Lang::Fr))
                .on_press(Message::SetLang(Lang::Fr)),
            button(text("EN").size(12))
                .padding([4, 8])
                .style(style(Lang::En))
                .on_press(Message::SetLang(Lang::En)),
        ]
        .spacing(4)
        .into()
    }

    fn view_auth(&self) -> Element<'_, Message> {
        let l = self.lang;
        let setup = self.screen == Screen::Setup;
        let mut form = Column::new().spacing(12).max_width(440);
        form = form.push(
            text(if setup {
                l.t("Créer votre coffre", "Create your vault")
            } else {
                l.t("Coffre verrouillé", "Vault locked")
            })
            .size(28),
        );
        if setup {
            form = form.push(
                text(l.t(
                    "Choisissez un mot de passe maître. Il n'est enregistré nulle part : \
                     s'il est perdu, le coffre est définitivement illisible. \
                     Une phrase de plusieurs mots est idéale.",
                    "Choose a master password. It is stored nowhere: if you lose it, the \
                     vault becomes permanently unreadable. \
                     A phrase of several words is ideal.",
                ))
                .size(14),
            );
        }
        form = form.push(
            text_input(l.t("Mot de passe maître", "Master password"), self.master.as_str())
                .on_input(|s| Message::MasterChanged(Secret::new(s)))
                .on_submit(Message::Submit)
                .secure(true)
                .padding(10),
        );
        if setup {
            form = form.push(
                text_input(
                    l.t(
                        "Confirmer le mot de passe maître",
                        "Confirm the master password",
                    ),
                    self.confirm.as_str(),
                )
                .on_input(|s| Message::ConfirmChanged(Secret::new(s)))
                .on_submit(Message::Submit)
                .secure(true)
                .padding(10),
            );
        }
        let label = match (self.busy, setup) {
            (true, true) => l.t("Préparation du coffre…", "Preparing the vault…"),
            (true, false) => l.t("Déverrouillage…", "Unlocking…"),
            (false, true) => l.t("Créer le coffre", "Create the vault"),
            (false, false) => l.t("Déverrouiller", "Unlock"),
        };
        form = form
            .push(
                button(text(label))
                    .padding([8, 16])
                    .on_press_maybe((!self.busy).then_some(Message::Submit)),
            )
            .push(self.error_line())
            .push(self.notice_line());
        if self.hardening.1 > 0 {
            form = form.push(
                text(match l {
                    Lang::Fr => format!(
                        "Protections système actives : {}/{}",
                        self.hardening.0, self.hardening.1
                    ),
                    Lang::En => format!(
                        "System protections active: {}/{}",
                        self.hardening.0, self.hardening.1
                    ),
                })
                .size(12),
            );
        }
        column![
            container(self.lang_switch())
                .width(Length::Fill)
                .align_x(Horizontal::Right)
                .padding(8),
            container(form)
                .width(Length::Fill)
                .height(Length::Fill)
                .center_x()
                .center_y(),
        ]
        .into()
    }

    fn view_vault(&self) -> Element<'_, Message> {
        let l = self.lang;
        let mut list = Column::new().spacing(4);
        for entry in self.visible_entries() {
            let chosen = self.selected == Some(entry.id);
            let label = column![
                text(entry.title.as_str()).size(15),
                text(entry.username.as_str()).size(12),
            ]
            .spacing(2);
            list = list.push(
                button(label)
                    .width(Length::Fill)
                    .padding(8)
                    .style(if chosen {
                        theme::Button::Primary
                    } else {
                        theme::Button::Secondary
                    })
                    .on_press(Message::Select(entry.id)),
            );
        }
        let count = self.vault.as_ref().map_or(0, |v| v.entries().len());
        let count_text = match l {
            Lang::Fr => format!("{count} entrée(s)"),
            Lang::En if count == 1 => "1 entry".to_string(),
            Lang::En => format!("{count} entries"),
        };
        let left = column![
            text_input(l.t("Rechercher…", "Search…"), &self.search)
                .on_input(Message::SearchChanged)
                .padding(8),
            scrollable(list).height(Length::Fill),
            row![
                text(count_text).size(12),
                container(self.lang_switch())
                    .width(Length::Fill)
                    .align_x(Horizontal::Right),
            ]
            .align_items(Alignment::Center),
            row![
                button(l.t("Nouvelle entrée", "New entry")).on_press(Message::NewEntry),
                button(l.t("Verrouiller", "Lock"))
                    .style(theme::Button::Secondary)
                    .on_press(Message::LockNow),
            ]
            .spacing(8),
            row![
                button(l.t("Importer", "Import"))
                    .style(theme::Button::Secondary)
                    .on_press(Message::OpenImport),
                button(l.t("Exporter", "Export"))
                    .style(theme::Button::Secondary)
                    .on_press(Message::OpenExport),
            ]
            .spacing(8),
        ]
        .spacing(10)
        .padding(12)
        .width(Length::Fixed(320.0));

        let right: Element<'_, Message> = if let Some(editor) = &self.editor {
            self.view_editor(editor)
        } else if let Some(transfer) = &self.transfer {
            self.view_transfer(transfer)
        } else if let Some(entry) = self.selected_entry() {
            self.view_detail(entry)
        } else {
            container(
                text(l.t(
                    "Sélectionnez une entrée ou créez-en une.",
                    "Select an entry or create one.",
                ))
                .size(16),
            )
            .width(Length::Fill)
            .height(Length::Fill)
            .center_x()
            .center_y()
            .into()
        };

        row![left, vertical_rule(1), right].into()
    }

    fn view_transfer<'a>(&'a self, transfer: &'a Transfer) -> Element<'a, Message> {
        let l = self.lang;
        let mut form = Column::new().spacing(10).padding(20).width(Length::Fill);
        if transfer.import {
            form = form
                .push(text(l.t("Importer des mots de passe", "Import passwords")).size(26))
                .push(
                    text(l.t(
                        "Formats lus : CSV (Chrome, Edge, Firefox, Bitwarden, KeePassXC, LastPass, \
                         1Password, Dashlane…), JSON Bitwarden non chiffré, XML KeePass ou KeePassXC. \
                         Les fichiers .kdbx ne sont pas encore pris en charge : exportez d'abord la \
                         base en XML ou en CSV depuis KeePass.",
                        "Supported formats: CSV (Chrome, Edge, Firefox, Bitwarden, KeePassXC, \
                         LastPass, 1Password, Dashlane…), unencrypted Bitwarden JSON, KeePass or \
                         KeePassXC XML. .kdbx files are not supported yet: first export the \
                         database as XML or CSV from KeePass.",
                    ))
                    .size(14),
                )
                .push(
                    text_input(
                        l.t(
                            "Chemin du fichier (ex. C:\\Users\\moi\\Downloads\\export.csv)",
                            "File path (e.g. C:\\Users\\me\\Downloads\\export.csv)",
                        ),
                        &transfer.path,
                    )
                    .on_input(Message::TransferPath)
                    .on_submit(Message::RunTransfer)
                    .padding(8),
                )
                .push(
                    text(l.t(
                        "Quand l'import est terminé, supprimez le fichier d'origine : \
                         il contient vos mots de passe en clair.",
                        "When the import is done, delete the original file: \
                         it contains your passwords in clear text.",
                    ))
                    .size(13),
                )
                .push(
                    row![
                        button(l.t("Importer", "Import")).on_press(Message::RunTransfer),
                        button(l.t("Annuler", "Cancel"))
                            .style(theme::Button::Secondary)
                            .on_press(Message::CloseTransfer),
                    ]
                    .spacing(10),
                );
        } else {
            form = form
                .push(text(l.t("Exporter le coffre", "Export the vault")).size(26))
                .push(
                    text(l.t(
                        "Attention : le fichier créé contiendra tous vos mots de passe en clair, \
                         lisibles par n'importe quel programme ou personne ayant accès à ce fichier. \
                         Ne l'ouvrez pas dans un tableur, ne l'envoyez pas, et supprimez-le après usage.",
                        "Warning: the file created will contain all your passwords in clear text, \
                         readable by any program or person with access to the file. \
                         Do not open it in a spreadsheet, do not send it, and delete it after use.",
                    ))
                    .size(14)
                    .style(theme::Text::Color(ERROR_COLOR)),
                )
                .push(
                    text_input(
                        l.t(
                            "Chemin du nouveau fichier (ex. C:\\Users\\moi\\Desktop\\export.csv)",
                            "Path of the new file (e.g. C:\\Users\\me\\Desktop\\export.csv)",
                        ),
                        &transfer.path,
                    )
                    .on_input(Message::TransferPath)
                    .padding(8),
                )
                .push(
                    checkbox(
                        l.t("JSON Bitwarden (sinon CSV)", "Bitwarden JSON (otherwise CSV)"),
                        transfer.json,
                    )
                    .on_toggle(Message::TransferJson),
                )
                .push(
                    checkbox(
                        l.t(
                            "J'ai compris que le fichier sera en clair",
                            "I understand the file will be in clear text",
                        ),
                        transfer.understood,
                    )
                    .on_toggle(Message::TransferUnderstood),
                )
                .push(
                    row![
                        button(l.t("Exporter", "Export"))
                            .on_press_maybe(transfer.understood.then_some(Message::RunTransfer)),
                        button(l.t("Annuler", "Cancel"))
                            .style(theme::Button::Secondary)
                            .on_press(Message::CloseTransfer),
                    ]
                    .spacing(10),
                );
        }
        form.push(self.error_line()).into()
    }

    fn view_detail<'a>(&'a self, entry: &'a Entry) -> Element<'a, Message> {
        let l = self.lang;
        let password: Element<'a, Message> = if self.show_password {
            // Déchiffré uniquement pendant l'affichage ; iced en garde une copie le temps du rendu.
            match self.vault.as_ref().and_then(|v| v.password(&entry.id).ok()) {
                Some(p) => text(p.as_str().to_owned()).into(),
                None => text(l.t("(illisible)", "(unreadable)")).into(),
            }
        } else {
            text("••••••••••••").into()
        };
        let delete: Element<'a, Message> = if self.confirm_delete {
            row![
                text(l.t(
                    "Supprimer définitivement cette entrée ?",
                    "Permanently delete this entry?",
                )),
                button(l.t("Oui, supprimer", "Yes, delete"))
                    .style(theme::Button::Destructive)
                    .on_press(Message::ConfirmDelete),
                button(l.t("Annuler", "Cancel"))
                    .style(theme::Button::Secondary)
                    .on_press(Message::CancelDelete),
            ]
            .spacing(10)
            .align_items(Alignment::Center)
            .into()
        } else {
            button(l.t("Supprimer", "Delete"))
                .style(theme::Button::Destructive)
                .on_press(Message::AskDelete)
                .into()
        };
        column![
            text(entry.title.as_str()).size(26),
            text(entry.url.as_str()).size(14),
            horizontal_rule(1),
            text(l.t("Identifiant", "Username")).size(12),
            row![
                text(entry.username.as_str()),
                button(l.t("Copier", "Copy"))
                    .style(theme::Button::Secondary)
                    .on_press(Message::CopyUsername),
            ]
            .spacing(12)
            .align_items(Alignment::Center),
            text(l.t("Mot de passe", "Password")).size(12),
            row![
                password,
                button(l.t("Copier", "Copy"))
                    .style(theme::Button::Secondary)
                    .on_press(Message::CopyPassword),
            ]
            .spacing(12)
            .align_items(Alignment::Center),
            checkbox(
                l.t("Afficher le mot de passe", "Show password"),
                self.show_password
            )
            .on_toggle(Message::ShowPassword),
            horizontal_rule(1),
            row![
                button(l.t("Modifier", "Edit")).on_press(Message::EditSelected),
                delete
            ]
            .spacing(12)
            .align_items(Alignment::Center),
            self.error_line(),
            self.notice_line(),
        ]
        .spacing(10)
        .padding(20)
        .width(Length::Fill)
        .into()
    }

    fn view_editor<'a>(&'a self, editor: &'a Editor) -> Element<'a, Message> {
        let l = self.lang;
        let options: Element<'a, Message> = if editor.passphrase {
            column![
                text(match l {
                    Lang::Fr => format!("Nombre de mots : {}", editor.words),
                    Lang::En => format!("Number of words: {}", editor.words),
                })
                .size(13),
                slider(3..=10u8, editor.words, Message::WordsChanged),
            ]
            .spacing(6)
            .into()
        } else {
            column![
                text(match l {
                    Lang::Fr => format!("Longueur : {}", editor.options.length),
                    Lang::En => format!("Length: {}", editor.options.length),
                })
                .size(13),
                slider(
                    8..=64u8,
                    editor.options.length as u8,
                    Message::LengthChanged
                ),
                row![
                    checkbox("a-z", editor.options.lowercase).on_toggle(Message::LowercaseToggled),
                    checkbox("A-Z", editor.options.uppercase).on_toggle(Message::UppercaseToggled),
                    checkbox("0-9", editor.options.digits).on_toggle(Message::DigitsToggled),
                    checkbox(l.t("Symboles", "Symbols"), editor.options.symbols)
                        .on_toggle(Message::SymbolsToggled),
                ]
                .spacing(14),
                checkbox(
                    l.t(
                        "Éviter les caractères ambigus (I l 1 O 0 o)",
                        "Avoid ambiguous characters (I l 1 O 0 o)",
                    ),
                    editor.options.avoid_ambiguous
                )
                .on_toggle(Message::AmbiguousToggled),
            ]
            .spacing(8)
            .into()
        };
        let entropy: Element<'a, Message> = match editor.entropy {
            Some(bits) => text(match l {
                Lang::Fr => format!("Entropie du mot de passe généré : environ {bits:.0} bits"),
                Lang::En => format!("Generated password entropy: about {bits:.0} bits"),
            })
            .size(13)
            .into(),
            None => text("").into(),
        };
        column![
            text(if editor.id.is_some() {
                l.t("Modifier l'entrée", "Edit entry")
            } else {
                l.t("Nouvelle entrée", "New entry")
            })
            .size(26),
            text_input(l.t("Titre", "Title"), &editor.title)
                .on_input(Message::TitleChanged)
                .padding(8),
            text_input(
                l.t("Adresse du site (https://…)", "Website address (https://…)"),
                &editor.url
            )
            .on_input(Message::UrlChanged)
            .padding(8),
            text_input(l.t("Identifiant", "Username"), &editor.username)
                .on_input(Message::UsernameChanged)
                .padding(8),
            text_input(
                if editor.id.is_some() {
                    l.t(
                        "Nouveau mot de passe (vide = inchangé)",
                        "New password (empty = unchanged)",
                    )
                } else {
                    l.t("Mot de passe", "Password")
                },
                editor.password.as_str(),
            )
            .on_input(|s| Message::PasswordChanged(Secret::new(s)))
            .secure(!editor.show_password)
            .padding(8),
            checkbox(l.t("Afficher", "Show"), editor.show_password)
                .on_toggle(Message::ShowEditorPassword),
            horizontal_rule(1),
            text(l.t("Générateur", "Generator")).size(16),
            checkbox(
                l.t("Phrase de passe (mots)", "Passphrase (words)"),
                editor.passphrase
            )
            .on_toggle(Message::PassphraseToggled),
            options,
            button(l.t("Générer", "Generate"))
                .style(theme::Button::Secondary)
                .on_press(Message::Generate),
            entropy,
            horizontal_rule(1),
            row![
                button(l.t("Enregistrer", "Save")).on_press(Message::SaveEntry),
                button(l.t("Annuler", "Cancel"))
                    .style(theme::Button::Secondary)
                    .on_press(Message::CancelEdit),
            ]
            .spacing(10),
            self.error_line(),
        ]
        .spacing(10)
        .padding(20)
        .width(Length::Fill)
        .into()
    }
}

// --------------------------------------------------------------------- main

fn parse_args() -> (Option<PathBuf>, bool) {
    let mut path = None;
    let mut compat = false;
    let mut args = std::env::args_os().skip(1);
    while let Some(arg) = args.next() {
        match arg.to_str() {
            Some("--compat") => compat = true,
            Some("--vault") => path = args.next().map(PathBuf::from),
            _ => {}
        }
    }
    (path, compat)
}

fn main() -> iced::Result {
    // Une panique ne doit ni afficher son contenu (il pourrait citer un secret) ni
    // passer par le rapport de plantage de Windows : on sort proprement.
    #[cfg(not(debug_assertions))]
    std::panic::set_hook(Box::new(|_| std::process::exit(101)));

    winsec::install_crash_policy();
    let (vault_path, compat) = parse_args();
    let report = winsec::harden_process(!compat);
    let hardening = (report.iter().filter(|(_, ok)| *ok).count(), report.len());

    let path = vault_path
        .or_else(storage::default_vault_path)
        .unwrap_or_else(|| PathBuf::from("coffre.vault"));

    let lang_path = path.with_file_name("kip.lang");
    let lang = Lang::load(&lang_path).unwrap_or(if winsec::system_ui_is_french() {
        Lang::Fr
    } else {
        Lang::En
    });
    // Sur le fil principal, avant l'interface : sa boucle de messages sert l'icône.
    winsec::install_tray(tray_text(lang));

    let mut settings = Settings::with_flags(Flags {
        path,
        hardening,
        lang,
    });
    settings.window = window::Settings {
        size: Size::new(980.0, 640.0),
        min_size: Some(Size::new(760.0, 480.0)),
        position: window::Position::Centered,
        // Logo de Kip (64 x 64, octets RGBA bruts).
        icon: window::icon::from_rgba(include_bytes!("../assets/kip_64.rgba").to_vec(), 64, 64).ok(),
        ..window::Settings::default()
    };
    let result = App::run(settings);
    winsec::remove_tray();
    // Quelle que soit la façon dont la fenêtre se ferme, on ne laisse pas un mot de
    // passe dans le presse-papiers.
    winsec::clipboard_clear_pending();
    result
}
