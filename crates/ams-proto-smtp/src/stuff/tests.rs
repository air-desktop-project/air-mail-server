//! Ce qu'un corps devient avant de partir.

use super::{Stuffer, stuffed_max};
use crate::Error;

/// Farcit un corps entier, clôture comprise.
fn farcir(corps: &[u8]) -> Result<std::vec::Vec<u8>, Error> {
    let mut sortie = std::vec![0_u8; stuffed_max(corps.len())];
    let mut plume = Stuffer::new();
    let ecrits = plume.push(corps, &mut sortie)?;
    let fin = plume.finish(sortie.get_mut(ecrits..).expect("place"))?;
    sortie.truncate(ecrits.saturating_add(fin));
    Ok(sortie)
}

#[test]
fn un_corps_ordinaire_passe_tel_quel() {
    assert_eq!(
        farcir(b"Bonjour.\r\nAu revoir.\r\n").expect("farcissable"),
        b"Bonjour.\r\nAu revoir.\r\n.\r\n"
    );
}

/// **La contrebande SMTP dans sa forme la plus simple** : sans ce doublement,
/// le message se terminerait tout seul, et la suite serait lue comme des
/// commandes.
#[test]
fn c_est_ici_que_le_message_ne_peut_plus_se_terminer_tout_seul() {
    let mechant = b"Bonjour\r\n.\r\nMAIL FROM:<attaquant@ailleurs.test>\r\n";
    let farci = farcir(mechant).expect("farcissable");
    assert_eq!(
        farci,
        &b"Bonjour\r\n..\r\nMAIL FROM:<attaquant@ailleurs.test>\r\n.\r\n"[..]
    );
    // La seule ligne au point est la dernière.
    assert_eq!(farci.windows(5).filter(|f| *f == b"\r\n.\r\n").count(), 1);
}

/// **Vrai au départ** : un message qui COMMENCE par un point doit être farci
/// lui aussi.
#[test]
fn un_point_en_tete_de_message_est_farci() {
    assert_eq!(farcir(b".\r\n").expect("farcissable"), b"..\r\n.\r\n");
    assert_eq!(
        farcir(b".point\r\n").expect("farcissable"),
        b"..point\r\n.\r\n"
    );
}

#[test]
fn un_point_au_milieu_d_une_ligne_ne_l_est_pas() {
    assert_eq!(farcir(b"a.b\r\n").expect("farcissable"), b"a.b\r\n.\r\n");
}

/// **Le découpage n'a aucune importance** : l'état traverse les appels, et un
/// point qui ouvre une ligne est farci même s'il arrive seul dans son morceau.
#[test]
fn le_decoupage_ne_change_rien() {
    let corps = b"un\r\n.deux\r\n...\r\ntrois";
    let entier = farcir(corps).expect("farcissable");
    for coupure in 0..=corps.len() {
        let mut sortie = std::vec![0_u8; stuffed_max(corps.len())];
        let mut plume = Stuffer::new();
        let (avant, apres) = corps.split_at(coupure);
        let mut ecrits = plume.push(avant, &mut sortie).expect("farcissable");
        ecrits = ecrits.saturating_add(
            plume
                .push(apres, sortie.get_mut(ecrits..).expect("place"))
                .expect("farcissable"),
        );
        ecrits = ecrits.saturating_add(
            plume
                .finish(sortie.get_mut(ecrits..).expect("place"))
                .expect("clôturable"),
        );
        sortie.truncate(ecrits);
        assert_eq!(sortie, entier, "coupure {coupure}");
    }
}

/// **Un corps qui ne finit pas par un saut de ligne en reçoit un.** Sans lui, le
/// point de clôture s'ajouterait à la dernière ligne au lieu d'en ouvrir une, et
/// le message n'aurait pas de fin.
#[test]
fn un_corps_inacheve_recoit_son_saut_de_ligne() {
    assert_eq!(
        farcir(b"sans fin").expect("farcissable"),
        b"sans fin\r\n.\r\n"
    );
    // Un corps VIDE est un message vide, et il se clôt tout de suite.
    assert_eq!(farcir(b"").expect("farcissable"), b".\r\n");
}

/// **On pourrait « réparer » un `LF` seul. On ne le fait pas** : ce que nous
/// émettrions ne serait plus ce que nous avons lu, et la signature DKIM qui
/// couvre ce corps ne vaudrait plus rien.
#[test]
fn un_saut_de_ligne_isole_fait_refuser_le_message() {
    for mechant in [&b"a\nb"[..], b"a\rb", b"a\n", b"\n"] {
        assert_eq!(
            farcir(mechant),
            Err(Error::MalformedLineEnding),
            "{mechant:?}"
        );
    }
    // Un `CR` en dernier octet n'est pas un saut de ligne : il en attend un.
    assert_eq!(farcir(b"a\r"), Err(Error::MalformedLineEnding));
}

/// Le tampon peut céder n'importe où : sur un point doublé, sur le saut de
/// ligne qu'on ajoute, sur la ligne au point. On essaie donc toutes les tailles,
/// pour deux corps — l'un qui finit par un saut de ligne, l'autre non, parce que
/// la clôture n'écrit pas la même chose dans les deux cas.
#[test]
fn un_tampon_trop_court_dit_ce_qu_il_aurait_fallu() {
    for corps in [&b"..\r\n"[..], b"sans fin"] {
        let entier = farcir(corps).expect("farcissable");
        for taille in 0..entier.len() {
            let mut sortie = std::vec![0_u8; taille];
            let mut plume = Stuffer::new();
            let issue = plume
                .push(corps, &mut sortie)
                .and_then(|ecrits| plume.finish(sortie.get_mut(ecrits..).expect("place")));
            assert!(
                matches!(issue, Err(Error::BufferTooSmall { .. })),
                "{corps:?} taille {taille} : {issue:?}"
            );
        }
    }
}

#[test]
fn la_majoration_majore() {
    assert_eq!(stuffed_max(0), 5);
    assert_eq!(stuffed_max(10), 25);
    assert_eq!(stuffed_max(usize::MAX), usize::MAX);
}

#[test]
fn ce_qui_farcit_se_montre_et_se_defaut() {
    let plume = Stuffer::default();
    assert!(!std::format!("{plume:?}").is_empty());
    let mut copie = plume;
    let mut sortie = [0_u8; 8];
    assert_eq!(copie.push(b"ab", &mut sortie).expect("farcissable"), 2);
}
