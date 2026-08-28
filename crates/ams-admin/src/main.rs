//! L'outil de contrôle et de configuration — binaire `air-mail-admin` (C12).
//!
//! # Ce qu'il fait aujourd'hui, et ce qu'il fera
//!
//! C11 veut une configuration **binaire** (Cap'n Proto), et cet outil doit en
//! être le seul moyen de production et de lecture. Le format n'existe pas
//! encore : `ams-config` est vide. Les commandes de configuration viendront donc
//! avec lui.
//!
//! Ce qu'il sait faire dès maintenant est ce dont un administrateur a besoin en
//! premier : **regarder une boîte**. Et ce regard n'est pas une commodité — c'est
//! la reconstruction de C13 exécutée à la demande, celle qui prouve que les
//! fichiers suffisent à retrouver ce que l'index dirait.

use std::path::PathBuf;
use std::process::ExitCode;

use ams_store::Maildir;

/// Le texte de `--help`.
const AIDE: &str = "\
air-mail-admin — contrôle et configuration d'air-mail-server

USAGE
    air-mail-admin <COMMANDE> [ARGUMENTS]

COMMANDES
    summary <maildir>   relit une boîte et rend ce que ses noms de fichiers
                        portent : messages numérotés, messages à adopter, noms
                        illisibles, et le prochain UID.
    --help              ce texte
    --version           la version

CE QUI N'EST PAS ENCORE LÀ
    Les commandes de CONFIGURATION. Le format binaire que le projet exige
    n'existe pas encore ; le serveur se règle en attendant par sa ligne de
    commande.
";

fn main() -> ExitCode {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    match arguments
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .as_slice()
    {
        [] | ["--help" | "-h"] => {
            println!("{AIDE}");
            ExitCode::SUCCESS
        }
        ["--version" | "-V"] => {
            println!("air-mail-admin {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        ["summary", racine] => resumer(PathBuf::from(racine)),
        autre => {
            eprintln!("air-mail-admin : commande inconnue : {autre:?}");
            eprintln!("Essayez `air-mail-admin --help`.");
            ExitCode::from(2)
        }
    }
}

/// Relit une boîte et rend ce que ses noms portent.
fn resumer(racine: PathBuf) -> ExitCode {
    // Le nom d'hôte ne sert qu'à composer de NOUVEAUX noms ; relire n'en a pas
    // besoin, mais l'ouverture ADOPTE ce qui traîne, et l'adoption en compose.
    let boite = match Maildir::open(&racine, b"air-mail-admin") {
        Ok(boite) => boite,
        Err(erreur) => {
            eprintln!("air-mail-admin : `{}` : {erreur}", racine.display());
            return ExitCode::FAILURE;
        }
    };
    let resume = match boite.summary() {
        Ok(resume) => resume,
        Err(erreur) => {
            eprintln!("air-mail-admin : `{}` : {erreur}", racine.display());
            return ExitCode::FAILURE;
        }
    };

    println!("boîte             {}", racine.display());
    println!("messages          {}", resume.numbered);
    println!("sans UID          {}", resume.unnumbered);
    println!("noms illisibles   {}", resume.unreadable);
    println!("prochain UID      {}", resume.next_uid.value());
    if resume.exhausted {
        // Ce n'est pas un détail : au-delà, il n'y a plus d'UID à donner sans
        // changer l'`UIDVALIDITY`, ce qui fait retélécharger la boîte entière à
        // tous les clients.
        println!("ATTENTION         la boîte a épuisé ses UID ; son `UIDVALIDITY` doit changer");
    }
    ExitCode::SUCCESS
}
