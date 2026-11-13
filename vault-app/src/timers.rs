//! Logique de temps de l'application, sans dépendance ni appel système :
//! les horloges et l'inactivité sont fournies par l'appelant, ce qui rend le
//! module testable.

use std::time::{Duration, Instant, SystemTime};

/// Écart entre deux ticks (de 1 s) au-delà duquel on considère que la machine
/// a été mise en veille.
pub const SUSPEND_GAP: Duration = Duration::from_secs(10);

/// Pourquoi le coffre doit être verrouillé.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockReason {
    /// Aucune activité de l'utilisateur pendant le délai configuré.
    Inactivity,
    /// La machine a été mise en veille ou l'horloge a fait un saut.
    Suspend,
    /// La session Windows est verrouillée.
    SessionLocked,
}

impl LockReason {
    /// Message affiché sur l'écran de déverrouillage, en français ou en anglais.
    pub fn message(self, english: bool) -> &'static str {
        match (self, english) {
            (LockReason::Inactivity, false) => "Coffre verrouillé après inactivité.",
            (LockReason::Suspend, false) => "Coffre verrouillé (mise en veille).",
            (LockReason::SessionLocked, false) => "Coffre verrouillé (session Windows verrouillée).",
            (LockReason::Inactivity, true) => "Vault locked after inactivity.",
            (LockReason::Suspend, true) => "Vault locked (sleep).",
            (LockReason::SessionLocked, true) => "Vault locked (Windows session locked).",
        }
    }
}

/// Décide quand verrouiller le coffre. L'inactivité est celle de la session
/// Windows entière (dernière frappe ou clic, quelle que soit l'application).
#[derive(Debug, Clone)]
pub struct AutoLock {
    timeout: Duration,
    last_mono: Instant,
    last_wall: SystemTime,
}

impl AutoLock {
    /// Crée le contrôleur ; `timeout` est le délai d'inactivité avant verrouillage.
    pub fn new(timeout: Duration, mono: Instant, wall: SystemTime) -> Self {
        Self {
            timeout,
            last_mono: mono,
            last_wall: wall,
        }
    }

    /// À appeler au déverrouillage : repart d'un état neuf.
    pub fn reset(&mut self, mono: Instant, wall: SystemTime) {
        self.last_mono = mono;
        self.last_wall = wall;
    }

    /// À appeler à intervalle régulier (1 s). `idle` est la durée depuis la
    /// dernière entrée utilisateur. Renvoie la raison du verrouillage, le cas échéant.
    pub fn tick(
        &mut self,
        mono: Instant,
        wall: SystemTime,
        idle: Duration,
        session_locked: bool,
    ) -> Option<LockReason> {
        let mono_gap = mono.saturating_duration_since(self.last_mono);
        // Si l'horloge murale recule (changement d'heure), on n'y voit pas une veille.
        let wall_gap = wall
            .duration_since(self.last_wall)
            .unwrap_or(Duration::ZERO);
        self.last_mono = mono;
        self.last_wall = wall;

        if session_locked {
            return Some(LockReason::SessionLocked);
        }
        if mono_gap.max(wall_gap) > SUSPEND_GAP {
            return Some(LockReason::Suspend);
        }
        if idle >= self.timeout {
            return Some(LockReason::Inactivity);
        }
        None
    }
}

/// Échéance d'effacement du presse-papiers.
#[derive(Debug, Clone, Copy)]
pub struct ClipboardTimer {
    deadline: Instant,
}

impl ClipboardTimer {
    /// Démarre un compte à rebours de `ttl`.
    pub fn new(now: Instant, ttl: Duration) -> Self {
        Self {
            deadline: now + ttl,
        }
    }

    /// Vrai quand le presse-papiers doit être effacé.
    pub fn due(&self, now: Instant) -> bool {
        now >= self.deadline
    }

    /// Temps restant avant l'effacement.
    pub fn remaining(&self, now: Instant) -> Duration {
        self.deadline.saturating_duration_since(now)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TIMEOUT: Duration = Duration::from_secs(300);

    fn secs(n: u64) -> Duration {
        Duration::from_secs(n)
    }

    /// Contrôleur démarré à t = 0 ; l'horloge murale suit l'horloge monotone.
    fn setup() -> (AutoLock, Instant, SystemTime) {
        let mono = Instant::now();
        let wall = SystemTime::UNIX_EPOCH + secs(1_800_000_000);
        (AutoLock::new(TIMEOUT, mono, wall), mono, wall)
    }

    #[test]
    fn stays_unlocked_while_the_user_is_active() {
        let (mut lock, mono, wall) = setup();
        for i in 1..=600 {
            let r = lock.tick(mono + secs(i), wall + secs(i), secs(2), false);
            assert_eq!(r, None, "tick {i}");
        }
    }

    #[test]
    fn locks_exactly_at_the_inactivity_timeout() {
        let (mut lock, mono, wall) = setup();
        assert_eq!(
            lock.tick(mono + secs(1), wall + secs(1), secs(299), false),
            None
        );
        assert_eq!(
            lock.tick(mono + secs(2), wall + secs(2), secs(300), false),
            Some(LockReason::Inactivity)
        );
    }

    #[test]
    fn session_lock_takes_precedence() {
        let (mut lock, mono, wall) = setup();
        assert_eq!(
            lock.tick(mono + secs(1), wall + secs(1), secs(999), true),
            Some(LockReason::SessionLocked)
        );
    }

    #[test]
    fn detects_suspend_from_either_clock() {
        let (mut lock, mono, wall) = setup();
        // Seule l'horloge murale a avancé : la monotone s'est arrêtée pendant la veille.
        assert_eq!(
            lock.tick(mono + secs(1), wall + secs(3600), secs(1), false),
            Some(LockReason::Suspend)
        );
        // Seule l'horloge monotone a avancé.
        let (mut lock, mono, wall) = setup();
        assert_eq!(
            lock.tick(mono + secs(3600), wall + secs(1), secs(1), false),
            Some(LockReason::Suspend)
        );
    }

    #[test]
    fn a_gap_of_exactly_the_threshold_is_not_a_suspend() {
        let (mut lock, mono, wall) = setup();
        let r = lock.tick(mono + SUSPEND_GAP, wall + SUSPEND_GAP, secs(1), false);
        assert_eq!(r, None);
        let r = lock.tick(
            mono + SUSPEND_GAP + secs(11),
            wall + SUSPEND_GAP + secs(11),
            secs(1),
            false,
        );
        assert_eq!(r, Some(LockReason::Suspend));
    }

    #[test]
    fn clock_going_backwards_does_not_lock() {
        let (mut lock, mono, wall) = setup();
        let r = lock.tick(mono + secs(1), wall - secs(7200), secs(1), false);
        assert_eq!(r, None);
        // Et le tick suivant repart de la nouvelle heure.
        let r = lock.tick(mono + secs(2), wall - secs(7199), secs(1), false);
        assert_eq!(r, None);
    }

    #[test]
    fn reset_forgets_a_long_pause() {
        let (mut lock, mono, wall) = setup();
        lock.reset(mono + secs(600), wall + secs(600));
        let r = lock.tick(mono + secs(601), wall + secs(601), secs(1), false);
        assert_eq!(r, None);
    }

    #[test]
    fn every_reason_has_a_message() {
        for reason in [
            LockReason::Inactivity,
            LockReason::Suspend,
            LockReason::SessionLocked,
        ] {
            assert!(reason.message(false).starts_with("Coffre verrouillé"));
            assert!(reason.message(true).starts_with("Vault locked"));
        }
    }

    #[test]
    fn clipboard_timer_fires_at_the_deadline() {
        let now = Instant::now();
        let timer = ClipboardTimer::new(now, secs(20));
        assert!(!timer.due(now));
        assert!(!timer.due(now + secs(19)));
        assert!(timer.due(now + secs(20)));
        assert!(timer.due(now + secs(500)));
        assert_eq!(timer.remaining(now + secs(5)), secs(15));
        assert_eq!(timer.remaining(now + secs(60)), Duration::ZERO);
    }
}
