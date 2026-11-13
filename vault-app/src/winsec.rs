//! Intégration Windows : seul endroit de l'application qui contient du code `unsafe`.
//!
//! Les déclarations FFI sont écrites à la main (signatures Win32 stables) pour
//! n'ajouter aucune dépendance. Sur un autre système, des versions inertes
//! permettent de compiler et de tester le reste de l'application.

pub use imp::{
    clipboard_clear_pending, clipboard_set_sensitive, exclude_windows_from_capture, harden_process,
    idle_time, install_crash_policy, lock_memory, session_locked, unlock_memory,
};

#[cfg(windows)]
mod imp {
    use std::ffi::c_void;
    use std::mem::size_of;
    use std::ptr::{copy_nonoverlapping, null, null_mut, write_volatile};
    use std::sync::atomic::{compiler_fence, AtomicU32, AtomicUsize, Ordering};
    use std::time::Duration;

    type Handle = *mut c_void;
    type Bool = i32;

    #[link(name = "kernel32")]
    extern "system" {
        fn VirtualLock(address: *const c_void, size: usize) -> Bool;
        fn VirtualUnlock(address: *const c_void, size: usize) -> Bool;
        fn GlobalAlloc(flags: u32, bytes: usize) -> Handle;
        fn GlobalLock(mem: Handle) -> *mut c_void;
        fn GlobalUnlock(mem: Handle) -> Bool;
        fn GlobalFree(mem: Handle) -> Handle;
        fn SetProcessMitigationPolicy(policy: i32, buffer: *const c_void, length: usize) -> Bool;
        fn GetCurrentProcessId() -> u32;
        fn GetTickCount() -> u32;
        fn SetErrorMode(mode: u32) -> u32;
        fn SetUnhandledExceptionFilter(
            filter: Option<unsafe extern "system" fn(*const c_void) -> i32>,
        ) -> *const c_void;
    }

    #[link(name = "user32")]
    extern "system" {
        fn OpenClipboard(owner: Handle) -> Bool;
        fn CloseClipboard() -> Bool;
        fn EmptyClipboard() -> Bool;
        fn SetClipboardData(format: u32, mem: Handle) -> Handle;
        fn RegisterClipboardFormatW(name: *const u16) -> u32;
        fn GetClipboardSequenceNumber() -> u32;
        fn EnumWindows(
            callback: unsafe extern "system" fn(Handle, isize) -> Bool,
            param: isize,
        ) -> Bool;
        fn GetWindowThreadProcessId(window: Handle, process_id: *mut u32) -> u32;
        fn SetWindowDisplayAffinity(window: Handle, affinity: u32) -> Bool;
        fn CreateWindowExW(
            ex_style: u32,
            class_name: *const u16,
            window_name: *const u16,
            style: u32,
            x: i32,
            y: i32,
            width: i32,
            height: i32,
            parent: Handle,
            menu: Handle,
            instance: Handle,
            param: *const c_void,
        ) -> Handle;
        fn OpenInputDesktop(flags: u32, inherit: Bool, access: u32) -> Handle;
        fn CloseDesktop(desktop: Handle) -> Bool;
        fn GetLastInputInfo(info: *mut LastInputInfo) -> Bool;
    }

    #[repr(C)]
    struct LastInputInfo {
        size: u32,
        time: u32,
    }

    // Identifiants de PROCESS_MITIGATION_POLICY (winnt.h).
    const POLICY_EXTENSION_POINT_DISABLE: i32 = 6;
    const POLICY_SIGNATURE: i32 = 8;
    const POLICY_IMAGE_LOAD: i32 = 10;
    const POLICY_CHILD_PROCESS: i32 = 13;

    const CF_UNICODETEXT: u32 = 13;
    const GMEM_MOVEABLE: u32 = 0x0002;
    const WDA_EXCLUDEFROMCAPTURE: u32 = 0x0000_0011;
    const DESKTOP_SWITCHDESKTOP: u32 = 0x0100;
    const SEM_FAILCRITICALERRORS: u32 = 0x0001;
    const SEM_NOGPFAULTERRORBOX: u32 = 0x0002;
    const SEM_NOOPENFILEERRORBOX: u32 = 0x8000;
    const EXCEPTION_EXECUTE_HANDLER: i32 = 1;
    /// HWND_MESSAGE : fenêtre « message seulement », invisible.
    const HWND_MESSAGE: isize = -3;

    /// Échec d'une opération sur le presse-papiers.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct ClipboardError;

    fn wide(text: &str) -> Vec<u16> {
        text.encode_utf16().chain(std::iter::once(0)).collect()
    }

    /// Écrase un tampon de façon que le compilateur ne puisse pas supprimer l'écriture.
    fn wipe(buffer: &mut [u16]) {
        for unit in buffer.iter_mut() {
            // SAFETY: `unit` est une référence valide et alignée vers un u16.
            unsafe { write_volatile(unit, 0) };
        }
        compiler_fence(Ordering::SeqCst);
    }

    // ---------------------------------------------------------------- plantages

    unsafe extern "system" fn swallow_exception(_: *const c_void) -> i32 {
        // Termine le processus sans passer par le rapport d'erreurs Windows :
        // aucun fichier d'image mémoire (dump) n'est écrit avec les secrets dedans.
        EXCEPTION_EXECUTE_HANDLER
    }

    /// Désactive les boîtes de dialogue d'erreur et le rapport de plantage.
    /// Les `panic!` Rust sont traités à part (voir `main`) : avec `panic = "abort"`
    /// un abandon brutal passerait par le rapport d'erreurs.
    pub fn install_crash_policy() {
        // SAFETY: appels sans pré-condition ; le filtre est une fonction `extern "system"` statique.
        unsafe {
            SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX);
            SetUnhandledExceptionFilter(Some(swallow_exception));
        }
    }

    // --------------------------------------------------------------- mitigations

    fn set_policy(policy: i32, flags: u32) -> bool {
        // Toutes les structures PROCESS_MITIGATION_*_POLICY employées ici tiennent
        // dans un DWORD de drapeaux.
        let buffer = flags;
        // SAFETY: `buffer` vit pendant l'appel et sa taille est passée avec le pointeur.
        unsafe {
            SetProcessMitigationPolicy(
                policy,
                &buffer as *const u32 as *const c_void,
                size_of::<u32>(),
            ) != 0
        }
    }

    /// Applique les mitigations réglables à l'exécution et renvoie le résultat de
    /// chacune. DEP, ASLR et CFG ne sont pas réglables ici : ils sont activés à
    /// l'édition de liens (voir `.cargo/config.toml`).
    ///
    /// Avec `strict`, on n'accepte plus que les DLL signées par Microsoft et on
    /// désactive les points d'extension hérités. Cela peut gêner des logiciels
    /// tiers qui s'injectent dans les applications (certains antivirus, lecteurs
    /// d'écran, méthodes de saisie) : l'option `--compat` les saute.
    pub fn harden_process(strict: bool) -> Vec<(&'static str, bool)> {
        let mut report = vec![
            // Aucun processus enfant (bit 0 : NoChildProcessCreation).
            (
                "pas de processus enfant",
                set_policy(POLICY_CHILD_PROCESS, 0b001),
            ),
            // Pas d'image distante, pas d'image d'intégrité basse, System32 d'abord (bits 0 à 2).
            (
                "chargement d'images restreint",
                set_policy(POLICY_IMAGE_LOAD, 0b111),
            ),
        ];
        if strict {
            // Bit 0 : MicrosoftSignedOnly.
            report.push((
                "DLL signées Microsoft uniquement",
                set_policy(POLICY_SIGNATURE, 0b1),
            ));
            // Bit 0 : DisableExtensionPoints.
            report.push((
                "points d'extension hérités désactivés",
                set_policy(POLICY_EXTENSION_POINT_DISABLE, 0b1),
            ));
        }
        report
    }

    // ------------------------------------------------------------------- mémoire

    /// Verrouille une plage en RAM pour qu'elle ne soit pas écrite dans le fichier d'échange.
    /// À utiliser sur de petites plages (la limite par défaut est de quelques dizaines de pages).
    pub fn lock_memory(ptr: *const u8, len: usize) -> bool {
        // SAFETY: l'appel ne déréférence pas le pointeur ; une plage invalide renvoie une erreur.
        unsafe { VirtualLock(ptr as *const c_void, len) != 0 }
    }

    /// Libère le verrouillage posé par `lock_memory`.
    pub fn unlock_memory(ptr: *const u8, len: usize) -> bool {
        // SAFETY: idem `lock_memory`.
        unsafe { VirtualUnlock(ptr as *const c_void, len) != 0 }
    }

    // ------------------------------------------------------------ capture d'écran

    unsafe extern "system" fn protect_if_ours(window: Handle, count: isize) -> Bool {
        let mut pid = 0u32;
        GetWindowThreadProcessId(window, &mut pid);
        if pid == GetCurrentProcessId()
            && SetWindowDisplayAffinity(window, WDA_EXCLUDEFROMCAPTURE) != 0
        {
            // SAFETY: `count` est l'adresse du compteur de `exclude_windows_from_capture`,
            // vivant pendant toute l'énumération.
            *(count as *mut usize) += 1;
        }
        1 // continuer l'énumération
    }

    /// Exclut les fenêtres de ce processus des captures d'écran et des
    /// enregistrements (la fenêtre apparaît noire). Renvoie le nombre de fenêtres
    /// protégées ; 0 tant que la fenêtre n'existe pas encore ou si Windows est
    /// trop ancien (avant Windows 10 2004).
    pub fn exclude_windows_from_capture() -> usize {
        let mut count = 0usize;
        // SAFETY: le pointeur vers `count` reste valide pendant l'appel, qui est synchrone.
        unsafe {
            EnumWindows(protect_if_ours, &mut count as *mut usize as isize);
        }
        count
    }

    // --------------------------------------------------------------- inactivité

    /// Durée écoulée depuis la dernière frappe ou le dernier clic, toutes applications confondues.
    pub fn idle_time() -> Duration {
        let mut info = LastInputInfo {
            size: size_of::<LastInputInfo>() as u32,
            time: 0,
        };
        // SAFETY: `info` est correctement initialisée avec sa taille.
        unsafe {
            if GetLastInputInfo(&mut info) == 0 {
                return Duration::ZERO;
            }
            // Les deux compteurs bouclent ensemble tous les 49,7 jours : la soustraction cyclique reste exacte.
            Duration::from_millis(u64::from(GetTickCount().wrapping_sub(info.time)))
        }
    }

    /// Vrai quand la session est verrouillée (le bureau actif n'est pas accessible).
    /// Vrai aussi pendant une invite UAC, ce qui est voulu.
    pub fn session_locked() -> bool {
        // SAFETY: appel sans pré-condition ; le bureau obtenu est refermé juste après.
        unsafe {
            let desktop = OpenInputDesktop(0, 0, DESKTOP_SWITCHDESKTOP);
            if desktop.is_null() {
                true
            } else {
                CloseDesktop(desktop);
                false
            }
        }
    }

    // ------------------------------------------------------------ presse-papiers

    /// Fenêtre propriétaire du presse-papiers. Sans propriétaire, `SetClipboardData`
    /// échoue après `EmptyClipboard` : on crée une fenêtre invisible, une seule fois.
    static OWNER: AtomicUsize = AtomicUsize::new(0);
    /// Numéro de séquence du presse-papiers juste après notre copie (0 = aucune copie en attente).
    static PENDING_SEQUENCE: AtomicU32 = AtomicU32::new(0);

    fn owner_window() -> Handle {
        let existing = OWNER.load(Ordering::Acquire);
        if existing != 0 {
            return existing as Handle;
        }
        let class = wide("STATIC");
        let name = wide("");
        // SAFETY: les deux chaînes sont terminées par un zéro et vivent pendant l'appel.
        let window = unsafe {
            CreateWindowExW(
                0,
                class.as_ptr(),
                name.as_ptr(),
                0,
                0,
                0,
                0,
                0,
                HWND_MESSAGE as Handle,
                null_mut(),
                null_mut(),
                null(),
            )
        };
        OWNER.store(window as usize, Ordering::Release);
        window
    }

    /// Ouvre le presse-papiers, avec quelques essais : un autre programme peut l'occuper un instant.
    fn open_clipboard() -> bool {
        let owner = owner_window();
        for _ in 0..10 {
            // SAFETY: `owner` est une fenêtre de ce processus (ou nul, ce qui reste permis).
            if unsafe { OpenClipboard(owner) } != 0 {
                return true;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        false
    }

    /// Place `len` octets dans une zone globale et la confie au presse-papiers (ouvert).
    fn put_clipboard_bytes(format: u32, data: *const u8, len: usize) -> bool {
        // SAFETY: `data` pointe sur `len` octets lisibles (garanti par les appelants) ; la
        // zone allouée fait exactement `len` octets ; en cas d'échec de `SetClipboardData`
        // la propriété reste à nous et on la libère.
        unsafe {
            let memory = GlobalAlloc(GMEM_MOVEABLE, len);
            if memory.is_null() {
                return false;
            }
            let target = GlobalLock(memory);
            if target.is_null() {
                GlobalFree(memory);
                return false;
            }
            copy_nonoverlapping(data, target as *mut u8, len);
            GlobalUnlock(memory);
            if SetClipboardData(format, memory).is_null() {
                GlobalFree(memory);
                return false;
            }
            true
        }
    }

    fn put_clipboard_flag(format_name: &str) {
        let name = wide(format_name);
        // SAFETY: `name` est terminé par un zéro.
        let format = unsafe { RegisterClipboardFormatW(name.as_ptr()) };
        if format != 0 {
            let zero = 0u32.to_le_bytes();
            put_clipboard_bytes(format, zero.as_ptr(), zero.len());
        }
    }

    /// Copie `text` dans le presse-papiers en demandant à Windows de ne pas le
    /// conserver : hors de l'historique (Win+V), hors de la synchronisation cloud
    /// et hors des programmes de surveillance. Mémorise la copie pour pouvoir
    /// l'effacer plus tard avec `clipboard_clear_pending`.
    pub fn clipboard_set_sensitive(text: &str) -> Result<(), ClipboardError> {
        // Capacité exacte suffisante (un point de code UTF-16 ne dépasse jamais son
        // nombre d'octets UTF-8) : aucune réallocation, donc aucune copie résiduelle du secret.
        let mut units: Vec<u16> = Vec::with_capacity(text.len() + 1);
        units.extend(text.encode_utf16());
        units.push(0);

        if !open_clipboard() {
            wipe(&mut units);
            return Err(ClipboardError);
        }
        // SAFETY: le presse-papiers est ouvert par nous.
        unsafe { EmptyClipboard() };
        let stored = put_clipboard_bytes(
            CF_UNICODETEXT,
            units.as_ptr() as *const u8,
            units.len() * size_of::<u16>(),
        );
        if stored {
            put_clipboard_flag("CanIncludeInClipboardHistory");
            put_clipboard_flag("CanUploadToCloudClipboard");
            put_clipboard_flag("ExcludeClipboardContentFromMonitorProcessing");
        }
        // SAFETY: fermeture du presse-papiers ouvert plus haut.
        unsafe { CloseClipboard() };
        wipe(&mut units);

        if !stored {
            return Err(ClipboardError);
        }
        // SAFETY: appel sans pré-condition.
        let sequence = unsafe { GetClipboardSequenceNumber() };
        PENDING_SEQUENCE.store(sequence, Ordering::SeqCst);
        Ok(())
    }

    /// Efface le presse-papiers si, et seulement si, il contient encore notre copie
    /// (ne détruit pas ce que l'utilisateur a copié depuis).
    pub fn clipboard_clear_pending() {
        let sequence = PENDING_SEQUENCE.swap(0, Ordering::SeqCst);
        if sequence == 0 {
            return;
        }
        // SAFETY: appel sans pré-condition.
        if unsafe { GetClipboardSequenceNumber() } != sequence {
            return;
        }
        if open_clipboard() {
            // SAFETY: le presse-papiers est ouvert par nous.
            unsafe {
                EmptyClipboard();
                CloseClipboard();
            }
        }
    }
}

#[cfg(not(windows))]
mod imp {
    use std::time::Duration;

    /// Échec d'une opération sur le presse-papiers.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct ClipboardError;

    pub fn install_crash_policy() {}

    pub fn harden_process(_strict: bool) -> Vec<(&'static str, bool)> {
        Vec::new()
    }

    pub fn lock_memory(_ptr: *const u8, _len: usize) -> bool {
        false
    }

    pub fn unlock_memory(_ptr: *const u8, _len: usize) -> bool {
        false
    }

    pub fn exclude_windows_from_capture() -> usize {
        0
    }

    pub fn idle_time() -> Duration {
        Duration::ZERO
    }

    pub fn session_locked() -> bool {
        false
    }

    pub fn clipboard_set_sensitive(_text: &str) -> Result<(), ClipboardError> {
        Err(ClipboardError)
    }

    pub fn clipboard_clear_pending() {}
}
