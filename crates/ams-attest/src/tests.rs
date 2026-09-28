// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! La politique, éprouvée règle par règle.
//!
//! Deux sortes de vecteurs :
//!
//! - `vecteurs/synthese/` : des chaînes fabriquées par `fabriquer.py` sous une
//!   racine d'essai, avec ce qu'on choisit. Chacune ne diffère de `tee.der` que
//!   par UNE chose, et doit être refusée pour ELLE ;
//! - `vecteurs/google/` : des chaînes RÉELLES, publiées par Google dans
//!   `android-key-attestation` (Apache 2.0). Elles viennent d'appareils de test
//!   déverrouillés : elles éprouvent la cryptographie et la lecture, et doivent
//!   être refusées pour ce qu'elles sont.

use super::{Attestation, CHAIN_MAX, GOOGLE_ROOTS, Policy, Refusal, SecurityLevel, verify};
use sha2::Digest as _;
use std::vec::Vec;

/// 2026-09-28 à minuit UTC.
const MAINTENANT: i64 = 1_790_553_600;

macro_rules! vecteur {
    ($nom:literal) => {
        include_bytes!(concat!("vecteurs/synthese/", $nom))
    };
}

const RACINE: &[u8] = vecteur!("racine.spki");
const RACINE_RSA: &[u8] = vecteur!("racine-rsa.spki");
const PAQUET: &[u8] = b"org.airdesktop.mail";

fn appareil() -> [u8; 65] {
    <[u8; 65]>::try_from(&vecteur!("appareil.sec1")[..]).expect("soixante-cinq octets")
}

fn empreinte() -> [u8; 32] {
    <[u8; 32]>::try_from(&vecteur!("empreinte.bin")[..]).expect("trente-deux octets")
}

fn defi() -> &'static [u8] {
    vecteur!("defi.bin")
}

/// La politique d'essai, sous la racine d'essai.
fn juger(chaine: &[u8]) -> Result<Attestation, Refusal> {
    let racines = [RACINE, RACINE_RSA];
    let signataires = [empreinte()];
    let politique = Policy {
        roots: &racines,
        package: PAQUET,
        signers: &signataires,
        revoked: &[],
    };
    verify(chaine, &appareil(), defi(), &politique, MAINTENANT)
}

#[test]
fn une_attestation_tee_en_regle_est_acceptee() {
    assert_eq!(
        juger(vecteur!("tee.der")),
        Ok(Attestation {
            level: SecurityLevel::TrustedEnvironment,
            keymint_version: 200,
            os_patch_level: Some(202_609),
        })
    );
}

#[test]
fn une_attestation_strongbox_dit_son_niveau() {
    assert_eq!(
        juger(vecteur!("strongbox.der")).map(|lue| lue.level),
        Ok(SecurityLevel::StrongBox)
    );
}

/// **UN INTERMÉDIAIRE SIGNÉ EN RSA** — la forme de la racine historique de
/// Google, sous SHA-384 ici.
#[test]
fn une_racine_rsa_se_verifie() {
    assert!(juger(vecteur!("rsa.der")).is_ok());
}

/// **CHAQUE RÈGLE REFUSE POUR ELLE-MÊME** : chaque vecteur ne diffère du
/// vecteur accepté que par une chose.
#[test]
fn chaque_ecart_est_refuse_pour_sa_raison() {
    let cas: [(&[u8], Refusal); 16] = [
        (
            vecteur!("sans-racine-de-confiance.der"),
            Refusal::NoRootOfTrust,
        ),
        (vecteur!("extension-illisible.der"), Refusal::Malformed),
        (vecteur!("application-illisible.der"), Refusal::Malformed),
        (vecteur!("logiciel.der"), Refusal::Software),
        (vecteur!("deverrouille.der"), Refusal::UnverifiedBoot),
        (vecteur!("non-verifie.der"), Refusal::UnverifiedBoot),
        (vecteur!("importee.der"), Refusal::Imported),
        (vecteur!("autre-paquet.der"), Refusal::OtherApplication),
        (vecteur!("sans-application.der"), Refusal::OtherApplication),
        (vecteur!("autre-signataire.der"), Refusal::OtherSigner),
        (vecteur!("deux-signataires.der"), Refusal::OtherSigner),
        (vecteur!("autre-racine.der"), Refusal::UnknownRoot),
        (vecteur!("autre-cle.der"), Refusal::OtherKey),
        (vecteur!("future.der"), Refusal::Expired),
        (vecteur!("sans-extension.der"), Refusal::NoAttestation),
        (&vecteur!("tee.der")[..40], Refusal::Malformed),
    ];
    for (chaine, attendu) in cas {
        assert_eq!(juger(chaine), Err(attendu), "{}", attendu.describe());
    }
}

#[test]
fn un_autre_defi_est_refuse() {
    let racines = [RACINE];
    let signataires = [empreinte()];
    let politique = Policy {
        roots: &racines,
        package: PAQUET,
        signers: &signataires,
        revoked: &[],
    };
    assert_eq!(
        verify(
            vecteur!("tee.der"),
            &appareil(),
            b"autre",
            &politique,
            MAINTENANT
        ),
        Err(Refusal::OtherChallenge)
    );
}

/// **LES DATES DES CERTIFICATS COMPTENT** — sauf celles de la racine, épinglée
/// par sa clef.
#[test]
fn hors_de_ses_dates_une_chaine_est_refusee() {
    let racines = [RACINE];
    let signataires = [empreinte()];
    let politique = Policy {
        roots: &racines,
        package: PAQUET,
        signers: &signataires,
        revoked: &[],
    };
    let chaine = vecteur!("tee.der");
    // 2024 : avant le début de validité ; 2036 : après la fin.
    for instant in [1_704_067_200, 2_082_758_400] {
        assert_eq!(
            verify(chaine, &appareil(), defi(), &politique, instant),
            Err(Refusal::Expired)
        );
    }
}

/// Découpe une chaîne en ses certificats.
fn certificats(chaine: &[u8]) -> Vec<&[u8]> {
    let mut lecteur = crate::der::Lecteur::new(chaine);
    let mut tous = Vec::new();
    while !lecteur.fini() {
        tous.push(lecteur.lire().expect("lisible").brut);
    }
    tous
}

#[test]
fn une_chaine_trop_courte_trop_longue_ou_dans_le_desordre_est_refusee() {
    let tee: &[u8] = vecteur!("tee.der");
    assert_eq!(juger(&[]), Err(Refusal::ChainLength));
    let parts = certificats(tee);
    assert_eq!(juger(parts[0]), Err(Refusal::ChainLength));
    // Neuf certificats : refusés avant d'en vérifier un seul.
    let trop: Vec<u8> = [tee, tee, tee].concat();
    assert_eq!(certificats(&trop).len(), 9);
    const _: () = assert!(9 > CHAIN_MAX);
    assert_eq!(juger(&trop), Err(Refusal::ChainLength));
    // La racine d'abord : la feuille n'est plus signée par ce qui la suit.
    let desordre: Vec<u8> = [parts[2], parts[1], parts[0]].concat();
    assert_eq!(juger(&desordre), Err(Refusal::BadSignature));
    // Un élément qui n'est pas un certificat.
    let intrus: Vec<u8> = [&[0x04, 0x01, 0x00][..], parts[1], parts[2]].concat();
    assert_eq!(juger(&intrus), Err(Refusal::Malformed));
}

/// **UNE CLEF RÉVOQUÉE FAIT REFUSER SA CHAÎNE**, à quelque étage qu'elle soit
/// — et seulement elle : un autre numéro ne change rien.
#[test]
fn une_clef_revoquee_fait_refuser_la_chaine() {
    let chaine = vecteur!("tee.der");
    let series: Vec<u128> = certificats(chaine)
        .iter()
        .map(|brut| {
            crate::x509::lire(brut)
                .expect("lisible")
                .serie
                .expect("seize octets")
        })
        .collect();
    let racines = [RACINE];
    let signataires = [empreinte()];
    for serie in &series {
        let mut revoques = std::vec![1_u128, *serie, u128::MAX];
        revoques.sort_unstable();
        let politique = Policy {
            roots: &racines,
            package: PAQUET,
            signers: &signataires,
            revoked: &revoques,
        };
        assert_eq!(
            verify(chaine, &appareil(), defi(), &politique, MAINTENANT),
            Err(Refusal::Revoked)
        );
    }
    let autres = [2_u128, 3];
    let politique = Policy {
        roots: &racines,
        package: PAQUET,
        signers: &signataires,
        revoked: &autres,
    };
    assert!(verify(chaine, &appareil(), defi(), &politique, MAINTENANT).is_ok());
}

/// **UNE VRAIE CLEF D'USINE RÉVOQUÉE** : l'intermédiaire de la vraie chaîne de
/// Google, déclaré révoqué, la fait refuser — avant même qu'on regarde sa
/// clef d'appareil.
#[test]
fn une_vraie_chaine_revoquee_est_refusee() {
    let chaine = include_bytes!("vecteurs/google/ec-tee.der");
    let intermediaire = crate::x509::lire(certificats(chaine)[1]).expect("lisible");
    let revoques = [intermediaire.serie.expect("seize octets")];
    // Le numéro que `openssl x509 -serial` écrit, en hexadécimal comme la liste.
    assert_eq!(revoques[0], 0x1320_6311_7896_3882_0911);
    let signataires = [empreinte()];
    let politique = Policy {
        roots: &GOOGLE_ROOTS,
        package: PAQUET,
        signers: &signataires,
        revoked: &revoques,
    };
    assert_eq!(
        verify(chaine, &appareil(), b"abc", &politique, MAINTENANT),
        Err(Refusal::Revoked)
    );
}

/// **LES RACINES SONT CELLES DE LA DOCUMENTATION D'ANDROID** : deux clefs, et
/// leurs empreintes sont celles qu'on a relevées sur les certificats publiés.
#[test]
fn les_racines_de_google_sont_celles_de_la_documentation() {
    let empreintes: Vec<std::string::String> = GOOGLE_ROOTS
        .iter()
        .map(|racine| {
            sha2::Sha256::digest(racine)
                .iter()
                .map(|octet| std::format!("{octet:02x}"))
                .collect()
        })
        .collect();
    assert_eq!(
        empreintes,
        [
            "feb2ea7551ee316ed4bb443c8293b884dbfdea40b603ee3e4f4a897e4580fbae",
            "3ee44512a1af2beb39c889490c60ea3f82e43f5d5a5532f5ab9419f676cd07ec",
        ]
    );
}

/// La politique de Google, pour les chaînes réelles.
fn juger_chez_google(chaine: &[u8], cle: &[u8; 65], defi: &[u8]) -> Result<Attestation, Refusal> {
    let signataires = [empreinte()];
    let politique = Policy {
        roots: &GOOGLE_ROOTS,
        package: PAQUET,
        signers: &signataires,
        revoked: &[],
    };
    verify(chaine, cle, defi, &politique, MAINTENANT)
}

/// **UNE VRAIE CHAÎNE REMONTE À LA RACINE DE GOOGLE** — P-256, P-384 signé en
/// RSA, puis la racine RSA-4096. Sa clef n'est pas la nôtre, et c'est la
/// première chose qu'on lui reproche : tout ce qui précède a donc tenu.
#[test]
fn une_vraie_chaine_remonte_a_google() {
    let appareil = appareil();
    assert_eq!(
        juger_chez_google(
            include_bytes!("vecteurs/google/ec-tee.der"),
            &appareil,
            b"abc"
        ),
        Err(Refusal::OtherKey)
    );
    // La feuille RSA : une clef qui ne peut pas être celle d'un appareil.
    assert_eq!(
        juger_chez_google(
            include_bytes!("vecteurs/google/rsa-tee.der"),
            &appareil,
            b"abc"
        ),
        Err(Refusal::OtherKey)
    );
}

/// **SOUS SA PROPRE CLEF, LA VRAIE CHAÎNE EST LUE JUSQU'AU BOUT** — et refusée
/// pour ce qu'est l'appareil qui l'a produite : un téléphone de test,
/// déverrouillé.
#[test]
fn une_vraie_attestation_d_appareil_deverrouille_est_refusee() {
    let chaine = include_bytes!("vecteurs/google/ec-tee.der");
    let feuille = crate::x509::lire(certificats(chaine)[0]).expect("lisible");
    let crate::x509::Cle::P256(point) = feuille.cle else {
        panic!("une feuille P-256");
    };
    let cle = <[u8; 65]>::try_from(point).expect("un point non compressé");
    assert_eq!(
        juger_chez_google(chaine, &cle, b"abc"),
        Err(Refusal::UnverifiedBoot)
    );
    assert_eq!(
        juger_chez_google(chaine, &cle, b"abd"),
        Err(Refusal::OtherChallenge)
    );
}

/// **UNE CHAÎNE DE PRÉ-PRODUCTION NE PASSE PAS** : sa racine n'est pas l'une
/// des deux de Google.
#[test]
fn une_chaine_hors_production_est_refusee() {
    let resultat = juger_chez_google(
        include_bytes!("vecteurs/google/ec-strongbox.der"),
        &appareil(),
        b"abc",
    );
    assert!(
        matches!(resultat, Err(Refusal::UnknownRoot | Refusal::BadSignature)),
        "{resultat:?}"
    );
}

#[test]
fn chaque_refus_et_chaque_niveau_se_disent() {
    let tous = [
        Refusal::Malformed,
        Refusal::Unsupported,
        Refusal::ChainLength,
        Refusal::BadSignature,
        Refusal::Expired,
        Refusal::UnknownRoot,
        Refusal::OtherKey,
        Refusal::NoAttestation,
        Refusal::OtherChallenge,
        Refusal::Software,
        Refusal::Imported,
        Refusal::UnverifiedBoot,
        Refusal::NoRootOfTrust,
        Refusal::OtherApplication,
        Refusal::OtherSigner,
        Refusal::Revoked,
    ];
    let dits: std::collections::BTreeSet<&str> = tous.iter().map(|r| r.describe()).collect();
    assert_eq!(dits.len(), tous.len(), "deux refus se disent pareil");
    assert_eq!(SecurityLevel::TrustedEnvironment.name(), "tee");
    assert_eq!(SecurityLevel::StrongBox.name(), "strongbox");
    assert!(!std::format!("{:?}{:?}", tous[0], SecurityLevel::StrongBox).is_empty());
}

/// **AUCUN OCTET ALTÉRÉ NE FAIT PANIQUER, ET AUCUN N'EST ACCEPTÉ** — hors du
/// certificat racine.
///
/// Chaque octet de la chaîne acceptée, remplacé par quelques valeurs : dans la
/// feuille et l'intermédiaire, chacune doit être refusée. Le certificat
/// racine, lui, n'est cru QUE par sa clef, épinglée : ses dates, ses noms et sa
/// signature ne comptent pas, et une altération qui laisse sa clef intacte peut
/// passer — c'est exactement ce que veut dire « épinglée par sa clef ». Toucher
/// à la clef, en revanche, la rend inconnue.
///
/// C'est aussi ce qui fait passer chaque lecture par son chemin d'erreur, champ
/// par champ.
#[test]
fn aucune_alteration_hors_de_la_racine_n_est_acceptee() {
    let tee: &[u8] = vecteur!("tee.der");
    let parts = certificats(tee);
    let debut_racine = parts[0].len() + parts[1].len();
    let racine = tee.len() - parts[2].len()..tee.len();
    assert_eq!(racine.start, debut_racine);
    let cle_racine = tee
        .windows(RACINE.len())
        .position(|fenetre| fenetre == RACINE)
        .expect("la clef racine est dans la chaîne");
    let cle_racine = cle_racine..cle_racine + RACINE.len();
    for rang in 0..tee.len() {
        for valeur in [0x00_u8, 0xFF, tee[rang] ^ 0x01] {
            if valeur == tee[rang] {
                continue;
            }
            let mut altere = tee.to_vec();
            altere[rang] = valeur;
            let jugee = juger(&altere);
            if jugee.is_ok() {
                assert!(
                    racine.contains(&rang) && !cle_racine.contains(&rang),
                    "octet {rang} altéré en {valeur:#04x}, et accepté"
                );
            }
        }
    }
}

/// Un constructeur DER, pour les essais qui fabriquent ce qu'un téléphone
/// n'écrirait pas.
pub(crate) mod fabrique {
    use std::vec::Vec;

    /// Un élément : étiquette (déjà encodée), longueur, contenu.
    pub(crate) fn tlv(etiquette: &[u8], contenu: &[u8]) -> Vec<u8> {
        let mut sortie = etiquette.to_vec();
        let n = contenu.len();
        if n < 0x80 {
            sortie.push(u8::try_from(n).expect("court"));
        } else if n < 0x100 {
            sortie.extend_from_slice(&[0x81, u8::try_from(n).expect("court")]);
        } else {
            let deux = u16::try_from(n).expect("moins de 64 Kio").to_be_bytes();
            sortie.extend_from_slice(&[0x82, deux[0], deux[1]]);
        }
        sortie.extend_from_slice(contenu);
        sortie
    }

    /// Une `SEQUENCE` de ces éléments.
    pub(crate) fn seq(elements: &[&[u8]]) -> Vec<u8> {
        tlv(&[0x30], &elements.concat())
    }

    /// Un `SET` de ces éléments.
    pub(crate) fn ensemble(elements: &[&[u8]]) -> Vec<u8> {
        tlv(&[0x31], &elements.concat())
    }

    /// Un `OCTET STRING`.
    pub(crate) fn octets(contenu: &[u8]) -> Vec<u8> {
        tlv(&[0x04], contenu)
    }

    /// Un `INTEGER` d'un octet.
    pub(crate) fn entier(valeur: u8) -> Vec<u8> {
        tlv(&[0x02], &[valeur])
    }

    /// Un `ENUMERATED` d'un octet.
    pub(crate) fn enumere(valeur: u8) -> Vec<u8> {
        tlv(&[0x0A], &[valeur])
    }

    /// Un élément de contexte construit, en forme haute au-delà de 30.
    pub(crate) fn contexte(numero: u32, contenu: &[u8]) -> Vec<u8> {
        if numero < 31 {
            return tlv(&[0xA0 | u8::try_from(numero).expect("petit")], contenu);
        }
        let mut groupes = Vec::new();
        let mut reste = numero;
        loop {
            groupes.insert(0, u8::try_from(reste & 0x7F).expect("sept bits"));
            reste >>= 7;
            if reste == 0 {
                break;
            }
        }
        let dernier = groupes.len().saturating_sub(1);
        for groupe in &mut groupes[..dernier] {
            *groupe |= 0x80;
        }
        let mut etiquette = std::vec![0xBF];
        etiquette.extend_from_slice(&groupes);
        tlv(&etiquette, contenu)
    }
}
