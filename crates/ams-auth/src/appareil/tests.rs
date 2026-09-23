//! Ce que la vérification accepte, et les quatre façons dont elle refuse.

use super::{CLE_OCTETS, Cle, Refus, SIGNATURE_OCTETS, verifier};
use p256::ecdsa::signature::hazmat::PrehashSigner as _;
use p256::ecdsa::{Signature, SigningKey};

/// Une clef d'épreuve, tirée d'octets FIXES.
///
/// **PAS D'ALÉA DANS UN ESSAI** : un essai qui tire au sort échoue un jour sur
/// mille, et ce jour-là personne ne sait pourquoi.
fn paire() -> (SigningKey, Cle) {
    let graine = [7_u8; 32];
    let privee = SigningKey::from_slice(&graine).expect("une clef valide");
    let publique = Cle::lire(privee.verifying_key().to_sec1_point(false).as_bytes())
        .expect("la publique se relit");
    (privee, publique)
}

/// Un condensat d'épreuve, également fixe.
const CONDENSAT: [u8; 32] = [42; 32];

/// Signe ce condensat, en forme fixe et basse.
fn signer(privee: &SigningKey, condensat: &[u8; 32]) -> [u8; SIGNATURE_OCTETS] {
    let signature: Signature = privee.sign_prehash(condensat).expect("signable");
    // **ON NE NORMALISE PAS `s`**, et c'est le sujet : le signataire produit
    // l'une ou l'autre forme au hasard, comme le font les enclaves réelles.
    let octets = signature.to_bytes();
    let mut sortie = [0_u8; SIGNATURE_OCTETS];
    for (place, lu) in sortie.iter_mut().zip(octets.iter()) {
        *place = *lu;
    }
    sortie
}

/// **CE QUI EST SIGNÉ SE VÉRIFIE.** L'aller-retour, d'abord.
#[test]
fn une_signature_juste_est_acceptee() {
    let (privee, publique) = paire();
    let signature = signer(&privee, &CONDENSAT);
    assert_eq!(verifier(&publique, &CONDENSAT, &signature), Ok(()));
}

/// **UNE CLEF SE RELIT TELLE QU'ON L'A ÉCRITE.**
///
/// Sans cela, une clef enrôlée un jour ne serait plus la même après un
/// aller-retour par le magasin — et toutes ses signatures échoueraient sans que
/// rien ne dise pourquoi.
#[test]
fn une_clef_fait_l_aller_retour_sans_changer() {
    let (_, publique) = paire();
    let octets = publique.octets();
    assert_eq!(octets.len(), CLE_OCTETS);
    assert_eq!(octets[0], 0x04, "forme non compressée (§2.3.3 de SEC 1)");
    let relue = Cle::lire(&octets).expect("relisible");
    assert_eq!(relue.octets(), octets);
}

/// **UN AUTRE CONDENSAT NE PASSE PAS.** C'est la propriété de base : la
/// signature couvre CE message, et non un message.
#[test]
fn un_autre_condensat_ne_correspond_pas() {
    let (privee, publique) = paire();
    let signature = signer(&privee, &CONDENSAT);
    let autre = [43_u8; 32];
    assert_eq!(
        verifier(&publique, &autre, &signature),
        Err(Refus::NeCorrespondPas)
    );
}

/// **UNE AUTRE CLEF NE PASSE PAS.**
#[test]
fn une_autre_clef_ne_correspond_pas() {
    let (privee, _) = paire();
    let signature = signer(&privee, &CONDENSAT);
    let etrangere = SigningKey::from_slice(&[9_u8; 32]).expect("valide");
    let publique =
        Cle::lire(etrangere.verifying_key().to_sec1_point(false).as_bytes()).expect("relisible");
    assert_eq!(
        verifier(&publique, &CONDENSAT, &signature),
        Err(Refus::NeCorrespondPas)
    );
}

/// **LA JUMELLE MALLÉABLE EST ACCEPTÉE, ET IL FAUT QUE CE SOIT ÉCRIT.**
///
/// # POURQUOI CET ESSAI EXISTE DANS CE SENS-LÀ
///
/// La première écriture de ce module REFUSAIT la forme haute, au nom de la
/// malléabilité. C'était une faute : la forme basse est une convention du
/// Bitcoin, pas une règle d'ECDSA, et les enclaves réelles produisent les deux
/// au hasard — **dix-neuf sur quarante, mesuré ici**.
///
/// La règle aurait donc refusé une signature légitime sur deux, sur les cinq
/// plateformes, en se manifestant par « l'ouverture de session échoue une fois
/// sur deux ». Cet essai fige le bon comportement pour qu'on ne le reperde pas.
#[test]
fn la_jumelle_malleable_est_acceptee() {
    let (privee, publique) = paire();
    let originale = signer(&privee, &CONDENSAT);
    assert_eq!(verifier(&publique, &CONDENSAT, &originale), Ok(()));

    // La jumelle : `s` devient `n − s`. Fabricable sans la clef privée.
    let lue = Signature::from_slice(&originale).expect("lisible");
    let jumelle_lue = Signature::from_scalars(lue.r(), -lue.s()).expect("l'opposé est valide");
    let octets = jumelle_lue.to_bytes();
    let mut jumelle = [0_u8; SIGNATURE_OCTETS];
    for (place, lu) in jumelle.iter_mut().zip(octets.iter()) {
        *place = *lu;
    }

    assert_ne!(jumelle, originale, "la jumelle diffère bien de l'originale");
    assert_eq!(
        verifier(&publique, &CONDENSAT, &jumelle),
        Ok(()),
        "les deux formes prouvent la même chose, et les deux doivent passer"
    );
}

/// **UNE TAILLE DE SIGNATURE QUI N'EST PAS LA NÔTRE EST REFUSÉE.**
///
/// C'est ce qui ferme la forme DER : un client qui l'enverrait obtient un refus
/// net plutôt qu'une lecture approximative.
#[test]
fn une_signature_de_mauvaise_taille_est_refusee() {
    let (privee, publique) = paire();
    let signature = signer(&privee, &CONDENSAT);
    for taille in [0_usize, 1, 63, 65, 70, 72] {
        let mut tronquee = std::vec![0_u8; taille];
        for (place, lu) in tronquee.iter_mut().zip(signature.iter()) {
            *place = *lu;
        }
        assert_eq!(
            verifier(&publique, &CONDENSAT, &tronquee),
            Err(Refus::TailleDeSignature),
            "taille {taille}"
        );
    }
}

/// **`r` OU `s` NUL EST HORS DOMAINE.**
#[test]
fn une_valeur_nulle_est_hors_domaine() {
    let (_, publique) = paire();
    assert_eq!(
        verifier(&publique, &CONDENSAT, &[0_u8; SIGNATURE_OCTETS]),
        Err(Refus::ValeurHorsDomaine)
    );
    // `r` valable, `s` nul.
    let mut moitie = [0_u8; SIGNATURE_OCTETS];
    moitie[31] = 1;
    assert_eq!(
        verifier(&publique, &CONDENSAT, &moitie),
        Err(Refus::ValeurHorsDomaine)
    );
}

/// **UN CONDENSAT DE MAUVAISE TAILLE NE PASSE PAS.**
///
/// L'appelant condense lui-même ; s'il se trompe d'algorithme, il doit
/// l'apprendre ici plutôt que d'obtenir un refus qu'il croira cryptographique.
#[test]
fn un_condensat_de_mauvaise_taille_est_refuse() {
    let (privee, publique) = paire();
    let signature = signer(&privee, &CONDENSAT);
    for taille in [0_usize, 20, 31, 33, 64] {
        assert_eq!(
            verifier(&publique, &std::vec![7_u8; taille], &signature),
            Err(Refus::NeCorrespondPas),
            "taille {taille}"
        );
    }
}

/// **UNE CLEF QUI N'EST PAS UN POINT N'EST PAS UNE CLEF.**
///
/// L'accepter ouvrirait les attaques par courbe invalide : on ferait de
/// l'arithmétique sur une courbe que l'attaquant a choisie, et dont l'ordre est
/// assez petit pour qu'il en déduise le secret.
#[test]
fn une_clef_qui_n_est_pas_un_point_est_refusee() {
    // La bonne taille, le bon préfixe, des coordonnées qui ne sont sur rien.
    let mut faux = [0_u8; CLE_OCTETS];
    faux[0] = 0x04;
    faux[1] = 1;
    assert_eq!(Cle::lire(&faux).err(), Some(Refus::CleIrrecevable));

    // Et les mauvaises tailles.
    for taille in [0_usize, 32, 33, 64, 66] {
        assert_eq!(
            Cle::lire(&std::vec![4_u8; taille]).err(),
            Some(Refus::CleIrrecevable),
            "taille {taille}"
        );
    }
}

/// **LA CLEF NE S'AFFICHE PAS EN ENTIER**, même publique : soixante-cinq octets
/// dans un journal n'apprennent rien et encombrent tout.
#[test]
fn la_trace_d_une_clef_reste_courte() {
    let (_, publique) = paire();
    let rendu = std::format!("{publique:?}");
    assert_eq!(rendu, "Cle(<P-256>)");
}

/// **UNE CLEF COPIÉE EST LA MÊME CLEF.**
///
/// Le magasin en fait des copies à chaque lecture — une copie qui différerait de
/// son original ferait échouer les signatures d'un appareil sur deux lectures,
/// et l'on chercherait le défaut dans la cryptographie.
#[test]
fn une_clef_copiee_verifie_les_memes_signatures() {
    let (privee, publique) = paire();
    let copie = publique.clone();
    assert_eq!(copie.octets(), publique.octets());

    let signature = signer(&privee, &CONDENSAT);
    assert_eq!(verifier(&copie, &CONDENSAT, &signature), Ok(()));
}

/// Un refus se copie et se compare — c'est ce dont l'appelant a besoin pour le
/// ranger dans sa trace sans le consommer.
#[test]
fn un_refus_se_copie() {
    let refus = Refus::NeCorrespondPas;
    let copie = refus;
    assert_eq!(copie, refus);
    assert_eq!(copie.clone(), Refus::NeCorrespondPas);
}
