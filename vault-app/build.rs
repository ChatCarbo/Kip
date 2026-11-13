//! Intègre le logo à `kip.exe` (icône affichée dans l'explorateur de fichiers et dans la
//! barre des tâches). Au mieux : si le compilateur de ressources de Windows (`rc.exe`, livré
//! avec les outils de build de Visual Studio) est introuvable, on compile quand même.

fn main() {
    println!("cargo:rerun-if-changed=assets/kip.ico");
    println!("cargo:rerun-if-changed=build.rs");

    #[cfg(windows)]
    {
        let mut resource = winresource::WindowsResource::new();
        resource.set_icon("assets/kip.ico");
        resource.set("ProductName", "Kip");
        resource.set("FileDescription", "Kip, gestionnaire de mots de passe");
        if let Err(error) = resource.compile() {
            println!("cargo:warning=icône de l'exécutable non intégrée : {error}");
        }
    }
}
