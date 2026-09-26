// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Ce que le journal fait du disque : il s'y crée, s'y relit, et se recrée
//! quand ce qu'il y trouve ne se lit pas.

use super::{NOM, reconcilier};

/// Un répertoire d'essai, effacé quand il tombe.
struct Atelier(std::path::PathBuf);

impl Drop for Atelier {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn atelier(nom: &str) -> Atelier {
    let chemin = std::env::temp_dir().join(std::format!(
        "ams-journal-{nom}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&chemin);
    std::fs::create_dir_all(&chemin).expect("un répertoire d'essai");
    Atelier(chemin)
}

/// **IL SE CRÉE, SE RELIT, ET N'AVANCE QUE SI LA BOÎTE A BOUGÉ.**
#[tokio::test(flavor = "multi_thread")]
async fn le_journal_se_cree_puis_se_relit() {
    let atelier = atelier("cree");
    let premier = reconcilier(&atelier.0, 7, &[(1, 0), (2, 0)]).expect("créé");
    assert!(atelier.0.join(NOM).exists());
    let encore = reconcilier(&atelier.0, 7, &[(1, 0), (2, 0)]).expect("relu");
    assert_eq!(encore, premier, "rien n'a bougé, rien n'avance");
    let apres = reconcilier(&atelier.0, 7, &[(1, 1)]).expect("relu");
    assert_eq!(apres.modseq, premier.modseq + 2);
}

/// **UN JOURNAL ILLISIBLE SE RECRÉE**, plus haut que tout ce que l'ancien
/// avait attribué — ses curseurs deviennent périmés, et les clients relisent
/// une fois.
#[tokio::test(flavor = "multi_thread")]
async fn un_journal_illisible_se_recree() {
    let atelier = atelier("abime");
    let ancien = reconcilier(&atelier.0, 7, &[(1, 0)]).expect("créé");
    std::fs::write(atelier.0.join(NOM), b"ceci n'est pas un journal").expect("abîmé");
    let neuf = reconcilier(&atelier.0, 7, &[(1, 0)]).expect("recréé");
    assert!(neuf.floor >= ancien.modseq);
    assert!(neuf.since(ancien.modseq.saturating_sub(1), 50, 50).is_err());
}
