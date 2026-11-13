//! Intégration Windows : seul endroit de l'application qui contient du code `unsafe`.
//!
//! Les déclarations FFI sont écrites à la main (signatures Win32 stables) pour
//! n'ajouter aucune dépendance. Sur un autre système, des versions inertes
//! permettent de compiler et de tester le reste de l'application.

pub use imp::{
    clipboard_clear_pending, clipboard_set_sensitive, exclude_windows_from_capture, harden_process,
    idle_time, install_crash_policy, install_tray, lock_memory, remove_tray, session_locked,
    set_tray_text, system_ui_is_french, take_tray_request, unlock_memory,
};

/// Titre de la fenêtre principale. La zone de notification retrouve la fenêtre grâce à lui.
pub const WINDOW_TITLE: &str = "Kip";

/// Textes de l'icône de la zone de notification (infobulle et menu), dans la langue courante.
#[derive(Debug, Clone, Default)]
pub struct TrayText {
    pub tooltip: String,
    pub open: String,
    pub lock: String,
    pub quit: String,
}

/// Demande faite depuis le menu de l'icône, à traiter par l'application.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrayRequest {
    Lock,
    Quit,
}

#[cfg(windows)]
mod imp {
    use std::ffi::c_void;
    use std::mem::{size_of, zeroed};
    use std::ptr::{copy_nonoverlapping, null, null_mut, write_volatile};
    use std::sync::atomic::{compiler_fence, AtomicU32, AtomicUsize, Ordering};
    use std::sync::Mutex;
    use std::time::Duration;

    use super::{TrayRequest, TrayText, WINDOW_TITLE};

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
        fn GetModuleHandleW(name: *const u16) -> Handle;
        fn GetUserDefaultUILanguage() -> u16;
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
        fn RegisterClassExW(class: *const WndClassExW) -> u16;
        fn DefWindowProcW(window: Handle, message: u32, wparam: usize, lparam: isize) -> isize;
        fn RegisterWindowMessageW(name: *const u16) -> u32;
        fn PostMessageW(window: Handle, message: u32, wparam: usize, lparam: isize) -> Bool;
        fn GetCursorPos(point: *mut Point) -> Bool;
        fn CreatePopupMenu() -> Handle;
        fn AppendMenuW(menu: Handle, flags: u32, id: usize, text: *const u16) -> Bool;
        fn TrackPopupMenu(
            menu: Handle,
            flags: u32,
            x: i32,
            y: i32,
            reserved: i32,
            window: Handle,
            rect: *const c_void,
        ) -> i32;
        fn DestroyMenu(menu: Handle) -> Bool;
        fn SetForegroundWindow(window: Handle) -> Bool;
        fn ShowWindow(window: Handle, command: i32) -> Bool;
        fn ShowWindowAsync(window: Handle, command: i32) -> Bool;
        fn IsIconic(window: Handle) -> Bool;
        fn IsWindowVisible(window: Handle) -> Bool;
        fn IsWindow(window: Handle) -> Bool;
        fn GetWindowTextW(window: Handle, text: *mut u16, max: i32) -> i32;
        fn LoadIconW(instance: Handle, name: *const u16) -> Handle;
        fn CreateIconFromResourceEx(
            bits: *const u8,
            size: u32,
            is_icon: Bool,
            version: u32,
            width: i32,
            height: i32,
            flags: u32,
        ) -> Handle;
        fn GetSystemMetrics(index: i32) -> i32;
    }

    #[link(name = "shell32")]
    extern "system" {
        fn Shell_NotifyIconW(message: u32, data: *mut NotifyIconData) -> Bool;
    }

    type WndProc = unsafe extern "system" fn(Handle, u32, usize, isize) -> isize;

    #[repr(C)]
    struct WndClassExW {
        size: u32,
        style: u32,
        proc_: Option<WndProc>,
        class_extra: i32,
        window_extra: i32,
        instance: Handle,
        icon: Handle,
        cursor: Handle,
        background: Handle,
        menu_name: *const u16,
        class_name: *const u16,
        icon_small: Handle,
    }

    #[repr(C)]
    struct Point {
        x: i32,
        y: i32,
    }

    #[repr(C)]
    struct Guid {
        data1: u32,
        data2: u16,
        data3: u16,
        data4: [u8; 8],
    }

    /// NOTIFYICONDATAW (shellapi.h), disposition de Windows Vista et suivants.
    #[repr(C)]
    struct NotifyIconData {
        size: u32,
        window: Handle,
        id: u32,
        flags: u32,
        callback: u32,
        icon: Handle,
        tip: [u16; 128],
        state: u32,
        state_mask: u32,
        info: [u16; 256],
        timeout_or_version: u32,
        info_title: [u16; 64],
        info_flags: u32,
        guid: Guid,
        balloon_icon: Handle,
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

    // Zone de notification.
    const NIM_ADD: u32 = 0;
    const NIM_MODIFY: u32 = 1;
    const NIM_DELETE: u32 = 2;
    const NIF_MESSAGE: u32 = 0x1;
    const NIF_ICON: u32 = 0x2;
    const NIF_TIP: u32 = 0x4;
    /// WM_APP + 1 : message envoyé par Windows à la fenêtre de l'icône.
    const WM_TRAY: u32 = 0x8001;
    const WM_NULL: u32 = 0x0000;
    const WM_LBUTTONUP: u32 = 0x0202;
    const WM_LBUTTONDBLCLK: u32 = 0x0203;
    const WM_RBUTTONUP: u32 = 0x0205;
    const WS_EX_TOOLWINDOW: u32 = 0x0000_0080;
    const MF_STRING: u32 = 0x0000;
    const MF_SEPARATOR: u32 = 0x0800;
    const TPM_RIGHTBUTTON: u32 = 0x0002;
    const TPM_BOTTOMALIGN: u32 = 0x0020;
    const TPM_RETURNCMD: u32 = 0x0100;
    const SW_HIDE: i32 = 0;
    const SW_SHOW: i32 = 5;
    const SW_RESTORE: i32 = 9;
    /// IDI_APPLICATION : icône d'application standard (MAKEINTRESOURCE(32512)).
    const IDI_APPLICATION: usize = 32512;
    /// SM_CXSMICON : largeur d'une petite icône (celle de la zone de notification).
    const SM_CXSMICON: i32 = 49;
    /// Version 3.0 des données d'icône, exigée par `CreateIconFromResourceEx`.
    const ICON_VERSION: u32 = 0x0003_0000;
    const MENU_OPEN: usize = 1;
    const MENU_LOCK: usize = 2;
    const MENU_QUIT: usize = 3;

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

    // ----------------------------------------------------- zone de notification

    static TRAY_WINDOW: AtomicUsize = AtomicUsize::new(0);
    static MAIN_WINDOW: AtomicUsize = AtomicUsize::new(0);
    static TASKBAR_CREATED: AtomicU32 = AtomicU32::new(0);
    /// Demande du menu en attente : 0 aucune, 1 verrouiller, 2 quitter.
    static REQUEST: AtomicU32 = AtomicU32::new(0);
    static TEXT: Mutex<Option<TrayText>> = Mutex::new(None);
    static TRAY_ICON: AtomicUsize = AtomicUsize::new(0);

    // Logo de Kip, en PNG (Windows sait lire le PNG dans une icône depuis Vista).
    const ICON_16: &[u8] = include_bytes!("../assets/kip_16.png");
    const ICON_24: &[u8] = include_bytes!("../assets/kip_24.png");
    const ICON_32: &[u8] = include_bytes!("../assets/kip_32.png");
    const ICON_48: &[u8] = include_bytes!("../assets/kip_48.png");

    /// Icône de la zone de notification, à la taille que demande Windows (16 à 48 px selon
    /// l'échelle de l'écran). Créée une fois et gardée pour toute la durée du processus ;
    /// repli sur l'icône d'application standard si la création échoue.
    fn tray_icon() -> Handle {
        let cached = TRAY_ICON.load(Ordering::Acquire);
        if cached != 0 {
            return cached as Handle;
        }
        // SAFETY: appel sans pré-condition.
        let wanted = unsafe { GetSystemMetrics(SM_CXSMICON) };
        let (png, size) = match wanted {
            ..=16 => (ICON_16, 16),
            17..=24 => (ICON_24, 24),
            25..=32 => (ICON_32, 32),
            _ => (ICON_48, 48),
        };
        // SAFETY: `png` est un tableau statique dont la taille est passée avec le pointeur.
        let mut icon = unsafe {
            CreateIconFromResourceEx(png.as_ptr(), png.len() as u32, 1, ICON_VERSION, size, size, 0)
        };
        if icon.is_null() {
            // SAFETY: icône standard du système, aucune pré-condition.
            icon = unsafe { LoadIconW(null_mut(), IDI_APPLICATION as *const u16) };
        }
        TRAY_ICON.store(icon as usize, Ordering::Release);
        icon
    }

    /// Vrai si l'interface de Windows est en français (pour choisir la langue au premier lancement).
    pub fn system_ui_is_french() -> bool {
        // SAFETY: appel sans pré-condition. Le français est la langue principale 0x0C.
        let id = unsafe { GetUserDefaultUILanguage() };
        (id & 0x03ff) == 0x000c
    }

    struct Search {
        pid: u32,
        found: Handle,
    }

    unsafe extern "system" fn find_main(window: Handle, param: isize) -> Bool {
        // SAFETY: `param` est l'adresse du `Search` de `main_window`, vivant pendant l'énumération.
        let search = &mut *(param as *mut Search);
        let mut pid = 0u32;
        GetWindowThreadProcessId(window, &mut pid);
        if pid != search.pid {
            return 1;
        }
        let mut buffer = [0u16; 16];
        let length = GetWindowTextW(window, buffer.as_mut_ptr(), buffer.len() as i32);
        if length > 0 && String::from_utf16_lossy(&buffer[..length as usize]) == WINDOW_TITLE {
            search.found = window;
            return 0; // trouvée : on arrête l'énumération
        }
        1
    }

    /// Fenêtre principale de l'application (visible, réduite ou masquée), ou nul si elle n'existe pas encore.
    fn main_window() -> Handle {
        let cached = MAIN_WINDOW.load(Ordering::Acquire) as Handle;
        // SAFETY: `IsWindow` accepte n'importe quelle valeur de poignée.
        if !cached.is_null() && unsafe { IsWindow(cached) } != 0 {
            return cached;
        }
        let mut search = Search {
            // SAFETY: appel sans pré-condition.
            pid: unsafe { GetCurrentProcessId() },
            found: null_mut(),
        };
        // SAFETY: `search` reste valide pendant l'appel, qui est synchrone.
        unsafe { EnumWindows(find_main, &mut search as *mut Search as isize) };
        MAIN_WINDOW.store(search.found as usize, Ordering::Release);
        search.found
    }

    /// Réaffiche la fenêtre principale, même masquée et réduite, et la met au premier plan.
    fn restore_main_window() {
        let window = main_window();
        if window.is_null() {
            return;
        }
        // SAFETY: `window` est une fenêtre de ce processus ; appelé depuis son fil (procédure
        // de fenêtre de l'icône) ou, pour `ShowWindowAsync`, depuis n'importe quel fil.
        unsafe {
            ShowWindow(window, SW_SHOW);
            ShowWindow(window, SW_RESTORE);
            SetForegroundWindow(window);
        }
    }

    fn notify(message: u32) -> bool {
        let window = TRAY_WINDOW.load(Ordering::Acquire) as Handle;
        if window.is_null() {
            return false;
        }
        // SAFETY: la structure ne contient que des entiers, des tableaux d'entiers et des
        // pointeurs : le tout-zéro est une valeur valide.
        let mut data: NotifyIconData = unsafe { zeroed() };
        data.size = size_of::<NotifyIconData>() as u32;
        data.window = window;
        data.id = 1;
        data.flags = NIF_MESSAGE | NIF_ICON | NIF_TIP;
        data.callback = WM_TRAY;
        data.icon = tray_icon();
        if let Ok(guard) = TEXT.lock() {
            if let Some(text) = guard.as_ref() {
                // 127 unités au plus : la dernière reste le zéro final.
                for (slot, unit) in data.tip.iter_mut().zip(text.tooltip.encode_utf16().take(127)) {
                    *slot = unit;
                }
            }
        }
        // SAFETY: `data` est initialisée, avec sa taille.
        unsafe { Shell_NotifyIconW(message, &mut data) != 0 }
    }

    fn show_menu(window: Handle) {
        let (open, lock, quit) = match TEXT.lock() {
            Ok(guard) => match guard.as_ref() {
                Some(t) => (wide(&t.open), wide(&t.lock), wide(&t.quit)),
                None => (wide(""), wide(""), wide("")),
            },
            Err(_) => (wide(""), wide(""), wide("")),
        };
        // SAFETY: les textes sont terminés par un zéro et vivent pendant les appels ; le menu
        // est détruit avant de sortir ; `window` est la fenêtre de l'icône, de ce fil.
        let command = unsafe {
            let menu = CreatePopupMenu();
            if menu.is_null() {
                return;
            }
            AppendMenuW(menu, MF_STRING, MENU_OPEN, open.as_ptr());
            AppendMenuW(menu, MF_STRING, MENU_LOCK, lock.as_ptr());
            AppendMenuW(menu, MF_SEPARATOR, 0, null());
            AppendMenuW(menu, MF_STRING, MENU_QUIT, quit.as_ptr());
            let mut point = Point { x: 0, y: 0 };
            GetCursorPos(&mut point);
            // Sans cela, le menu ne se ferme pas quand on clique ailleurs.
            SetForegroundWindow(window);
            let command = TrackPopupMenu(
                menu,
                TPM_RETURNCMD | TPM_RIGHTBUTTON | TPM_BOTTOMALIGN,
                point.x,
                point.y,
                0,
                window,
                null(),
            );
            PostMessageW(window, WM_NULL, 0, 0);
            DestroyMenu(menu);
            command
        };
        match command as usize {
            MENU_OPEN => restore_main_window(),
            MENU_LOCK => REQUEST.store(1, Ordering::SeqCst),
            MENU_QUIT => REQUEST.store(2, Ordering::SeqCst),
            _ => {}
        }
    }

    unsafe extern "system" fn tray_proc(
        window: Handle,
        message: u32,
        wparam: usize,
        lparam: isize,
    ) -> isize {
        if message == WM_TRAY {
            match (lparam & 0xffff) as u32 {
                WM_LBUTTONUP | WM_LBUTTONDBLCLK => restore_main_window(),
                WM_RBUTTONUP => show_menu(window),
                _ => {}
            }
            return 0;
        }
        let created = TASKBAR_CREATED.load(Ordering::Relaxed);
        if created != 0 && message == created {
            // L'explorateur Windows a redémarré : l'icône a disparu, on la remet.
            notify(NIM_ADD);
            return 0;
        }
        DefWindowProcW(window, message, wparam, lparam)
    }

    fn store_text(text: TrayText) {
        if let Ok(mut guard) = TEXT.lock() {
            *guard = Some(text);
        }
    }

    /// Place l'icône dans la zone de notification et fait disparaître la fenêtre de la barre
    /// des tâches quand on la réduit (un clic sur l'icône la rouvre). À appeler sur le fil
    /// principal, avant le lancement de l'interface : c'est sa boucle de messages qui sert l'icône.
    pub fn install_tray(text: TrayText) {
        store_text(text);
        let class = wide("KipTrayWindow");
        let name = wide("");
        // SAFETY: les chaînes sont terminées par un zéro et vivent pendant les appels ; la
        // classe renvoie vers une fonction `extern "system"` statique.
        unsafe {
            let instance = GetModuleHandleW(null());
            let window_class = WndClassExW {
                size: size_of::<WndClassExW>() as u32,
                style: 0,
                proc_: Some(tray_proc),
                class_extra: 0,
                window_extra: 0,
                instance,
                icon: null_mut(),
                cursor: null_mut(),
                background: null_mut(),
                menu_name: null(),
                class_name: class.as_ptr(),
                icon_small: null_mut(),
            };
            if RegisterClassExW(&window_class) == 0 {
                return;
            }
            // Fenêtre jamais affichée : elle ne sert qu'à recevoir les messages de l'icône.
            let window = CreateWindowExW(
                WS_EX_TOOLWINDOW,
                class.as_ptr(),
                name.as_ptr(),
                0,
                0,
                0,
                0,
                0,
                null_mut(),
                null_mut(),
                instance,
                null(),
            );
            if window.is_null() {
                return;
            }
            TRAY_WINDOW.store(window as usize, Ordering::Release);
            let broadcast = wide("TaskbarCreated");
            TASKBAR_CREATED.store(RegisterWindowMessageW(broadcast.as_ptr()), Ordering::Relaxed);
        }
        notify(NIM_ADD);

        // Surveille la réduction de la fenêtre. Un fil dédié évite de réveiller (et de
        // redessiner) l'interface : il ne fait qu'un appel système léger toutes les 150 ms.
        let _ = std::thread::Builder::new()
            .name("kip-tray".into())
            .spawn(|| loop {
                std::thread::sleep(Duration::from_millis(150));
                let window = main_window();
                if window.is_null() {
                    continue;
                }
                // SAFETY: `window` est une fenêtre de ce processus ; `ShowWindowAsync` poste la
                // commande au fil propriétaire au lieu de l'attendre.
                unsafe {
                    if IsIconic(window) != 0 && IsWindowVisible(window) != 0 {
                        ShowWindowAsync(window, SW_HIDE);
                    }
                }
            });
    }

    /// Change les textes de l'icône (changement de langue).
    pub fn set_tray_text(text: TrayText) {
        store_text(text);
        notify(NIM_MODIFY);
    }

    /// Demande du menu de l'icône (verrouiller, quitter), à traiter une seule fois.
    pub fn take_tray_request() -> Option<TrayRequest> {
        match REQUEST.swap(0, Ordering::SeqCst) {
            1 => Some(TrayRequest::Lock),
            2 => Some(TrayRequest::Quit),
            _ => None,
        }
    }

    /// Retire l'icône (à la fermeture de l'application).
    pub fn remove_tray() {
        notify(NIM_DELETE);
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

    pub fn system_ui_is_french() -> bool {
        true
    }

    pub fn install_tray(_text: super::TrayText) {}

    pub fn set_tray_text(_text: super::TrayText) {}

    pub fn take_tray_request() -> Option<super::TrayRequest> {
        None
    }

    pub fn remove_tray() {}
}
