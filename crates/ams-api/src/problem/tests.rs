// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Ce qu'un document d'erreur dit, et ce qu'il ne dit pas.

use std::string::{String, ToString};

use super::{JSON_MEDIA_TYPE, PROBLEM_MEDIA_TYPE, problem};
use crate::error::Reason;

/// Toutes les raisons, pour que chaque essai les parcoure toutes.
///
/// # ELLE EST EXHAUSTIVE PAR CONSTRUCTION, ET ELLE NE L'ÉTAIT PAS
///
/// C'était une liste tenue à la main, qui en nommait DIX sur dix-sept. Sept
/// motifs — dont `SessionClosed`, `BadMessage` et `BadJsonBody` — n'étaient
/// parcourus par aucun de ces essais, et rien ne le disait : une liste écrite à
/// part se désynchronise au premier ajout, et son premier symptôme est un
/// document d'erreur que personne n'a lu.
///
/// Le `match` ci-dessous la rend exhaustive **à la compilation** : un motif de
/// plus ne compile pas tant qu'on ne l'y a pas mis. C'est la même discipline
/// que `Resource::scope`, et pour la même raison.
fn toutes() -> [Reason; 29] {
    // Ce `match` ne sert qu'à faire échouer la compilation si un motif
    // s'ajoute : sa valeur est jetée, sa VÉRIFICATION est tout l'objet.
    const fn _exhaustive(reason: Reason) -> u8 {
        match reason {
            Reason::BadPath => 0,
            Reason::PathTooLong => 1,
            Reason::NoSuchResource => 2,
            Reason::MethodNotAllowed => 3,
            Reason::Forbidden => 4,
            Reason::BadPassword => 5,
            Reason::BadToken => 6,
            Reason::TokenExpired => 7,
            Reason::SessionClosed => 8,
            Reason::BadKey => 9,
            Reason::BadAccount => 10,
            Reason::BadMessage => 11,
            Reason::BadJsonBody => 12,
            Reason::BadJson => 13,
            Reason::JsonTooDeep => 14,
            Reason::BufferTooSmall => 15,
            Reason::NotImplemented => 16,
            Reason::AlreadyEnrolled => 17,
            Reason::LimitReached => 18,
            Reason::BadQuery => 19,
            Reason::SyncExpired => 20,
            Reason::BodyTooLarge => 21,
            Reason::AttachmentsNeedDraft => 22,
            Reason::DraftConflict => 23,
            Reason::BadIdempotencyKey => 24,
            Reason::IdempotencyKeyReused => 25,
            Reason::IdempotencyInFlight => 26,
            Reason::UnknownEncoding => 27,
            Reason::NotADevice => 28,
        }
    }
    [
        Reason::BadPath,
        Reason::PathTooLong,
        Reason::NoSuchResource,
        Reason::MethodNotAllowed,
        Reason::Forbidden,
        Reason::BadPassword,
        Reason::BadToken,
        Reason::TokenExpired,
        Reason::SessionClosed,
        Reason::BadKey,
        Reason::BadAccount,
        Reason::BadMessage,
        Reason::BadJsonBody,
        Reason::BadJson,
        Reason::JsonTooDeep,
        Reason::BufferTooSmall,
        Reason::NotImplemented,
        Reason::AlreadyEnrolled,
        Reason::LimitReached,
        Reason::BadQuery,
        Reason::SyncExpired,
        Reason::BodyTooLarge,
        Reason::AttachmentsNeedDraft,
        Reason::DraftConflict,
        Reason::BadIdempotencyKey,
        Reason::IdempotencyKeyReused,
        Reason::IdempotencyInFlight,
        Reason::UnknownEncoding,
        Reason::NotADevice,
    ]
}

/// Rend le document écrit pour cette faute.
fn document(reason: Reason) -> String {
    let mut place = [0_u8; 256];
    let ecrit = problem(reason, &mut place).expect("écrivable");
    core::str::from_utf8(ecrit).expect("de l'UTF-8").to_string()
}

/// Un document d'erreur porte les trois membres de §3.1 de RFC 9457.
#[test]
fn le_document_porte_les_trois_membres() {
    let dit = document(Reason::NoSuchResource);
    assert_eq!(
        dit,
        "{\"type\":\"/problems/not-found\",\"title\":\"aucune ressource ici\",\"status\":404}"
    );
}

/// Chaque raison écrit un document lisible, avec son code.
#[test]
fn chaque_raison_ecrit_son_document() {
    for reason in toutes() {
        let dit = document(reason);
        assert!(
            dit.starts_with("{\"type\":\"/problems/"),
            "{reason:?} : {dit}"
        );
        assert!(dit.contains("\"title\":\""), "{reason:?}");
        assert!(
            dit.contains(&std::format!("\"status\":{}", reason.status().value())),
            "{reason:?} : {dit}"
        );
        assert!(dit.ends_with('}'), "{reason:?}");
    }
}

/// **LE TYPE VIENT DU CODE D'ÉTAT, ET NON DE LA RAISON** : deux raisons qui
/// partagent un code sont indiscernables, jusque dans le document d'erreur.
///
/// Sans cette règle, le `type` rendrait immédiatement la distinction que le code
/// 404 venait d'effacer — et le document défferait le travail du code d'état.
#[test]
fn l_absence_et_l_interdit_ecrivent_le_meme_document() {
    assert_eq!(
        document(Reason::NoSuchResource),
        document(Reason::Forbidden),
        "les deux documents doivent être indiscernables, octet pour octet"
    );
}

/// **CE QUI EST NÔTRE SE DIT D'UNE SEULE FAÇON** : le détailler dirait ce que
/// notre code a fait de travers.
///
/// # ET `NotImplemented` EN EST EXCLU, DÉLIBÉRÉMENT
///
/// Il porte 501, donc la classe 5, et cet essai le rangeait d'office parmi nos
/// fautes. **Ce n'en est pas une.** Les quatre autres disent « notre code a
/// échoué », et le client n'y peut rien : lui en dire plus ne l'avancerait pas.
/// 501 dit « ce serveur ne sert pas cela », et le client PEUT en tirer quelque
/// chose — cesser de demander, ne pas proposer l'écran qui va avec. Le noyer
/// dans `/problems/internal` lui ferait croire à une panne passagère, et
/// réessayer indéfiniment une capacité que l'exploitant n'a pas configurée.
///
/// L'essai énumère donc les deux camps SÉPARÉMENT, et leur réunion est tout le
/// 5xx : un motif de plus dans cette classe échouera ici tant que personne ne
/// l'aura rangé d'un côté ou de l'autre.
#[test]
fn nos_propres_fautes_se_disent_pareil() {
    const NOTRES: [Reason; 4] = [
        Reason::BadKey,
        Reason::BadJson,
        Reason::JsonTooDeep,
        Reason::BufferTooSmall,
    ];
    for reason in NOTRES {
        assert!(
            document(reason).contains("/problems/internal"),
            "{reason:?} nomme autre chose"
        );
    }

    // CE QUI N'EST PAS UNE FAUTE, ET QUI PORTE POURTANT UN 5xx.
    assert!(document(Reason::NotImplemented).contains("/problems/not-implemented"));

    // **LES DEUX CAMPS ÉPUISENT LA CLASSE 5** : sans ce compte, un motif de plus
    // s'ajouterait sans que ni l'un ni l'autre ne le réclame.
    let dans_la_classe_5 = toutes()
        .into_iter()
        .filter(|reason| reason.status().class() == 5)
        .count();
    assert_eq!(
        dans_la_classe_5,
        NOTRES.len() + 1,
        "un motif 5xx n'est rangé dans aucun des deux camps"
    );
}

/// **LE TYPE DE MÉDIA N'EST PAS `application/json`** (§3 de RFC 9457) : un
/// intermédiaire peut reconnaître une erreur sans lire le corps.
#[test]
fn le_type_de_media_distingue_une_erreur() {
    assert_eq!(PROBLEM_MEDIA_TYPE, "application/problem+json");
    assert_eq!(JSON_MEDIA_TYPE, "application/json");
    assert_ne!(PROBLEM_MEDIA_TYPE, JSON_MEDIA_TYPE);
}

/// **NOTRE TAMPON, NOTRE FAUTE.**
#[test]
fn un_tampon_trop_court_est_notre_faute() {
    for taille in 0..document(Reason::NoSuchResource).len() {
        let mut petit = std::vec![0_u8; taille];
        let faute = problem(Reason::NoSuchResource, &mut petit).expect_err("trop court");
        assert_eq!(faute.reason(), Reason::BufferTooSmall, "{taille}");
    }
}

/// **UN MOT DE PASSE ACTUEL FAUX SE DIT 403, ET NON 404 NI 401.**
///
/// Les trois codes racontent trois choses différentes, et le client agit
/// différemment sur chacun : 404 le ferait chercher une route disparue, 401 lui
/// ferait recommencer une authentification qui a réussi, 403 lui dit ce qui est
/// vrai — la requête est comprise, et refusée.
///
/// L'essai tient aussi le `type`, parce qu'il vient du CODE : un 403 qui
/// retomberait sur `/problems/internal` accuserait le serveur d'une faute qui
/// est celle de qui tape son ancien mot de passe.
#[test]
fn un_mot_de_passe_actuel_faux_se_dit_403() {
    assert_eq!(Reason::BadPassword.status().value(), 403);
    assert_eq!(
        document(Reason::BadPassword),
        "{\"type\":\"/problems/forbidden\",\"title\":\"le mot de passe actuel ne \
         correspond pas\",\"status\":403}"
    );

    // Et il ne se confond avec aucun des deux voisins.
    assert_ne!(
        Reason::BadPassword.status(),
        Reason::Forbidden.status(),
        "une portée refusée se cache derrière un 404 ; celui-ci n'a rien à cacher"
    );
    assert_ne!(Reason::BadPassword.status(), Reason::BadToken.status());
}

/// **LE DOCUMENT PORTE LE MÊME CODE QUE LA LIGNE DE STATUT.**
///
/// # CE DÉFAUT A ÉTÉ VU EN PRODUCTION, ET CET ESSAI LE FIGE
///
/// `pas_encore` composait son document avec `NoSuchResource` — statut 404 —
/// puis posait 501 sur la réponse. Le client lisait donc `"status":404` sous une
/// ligne de statut à 501. §3.1 de RFC 9457 demande que les deux coïncident, et
/// un client qui croirait le corps chercherait une route disparue au lieu d'une
/// capacité non configurée.
///
/// Le bras était inatteignable jusqu'à ce que `/v1/me/devices` l'emprunte.
#[test]
fn le_code_du_document_est_celui_de_la_reponse() {
    for reason in toutes() {
        let dit = document(reason);
        let attendu = std::format!("\"status\":{}", reason.status().value());
        assert!(
            dit.contains(&attendu),
            "{reason:?} : le document doit porter {attendu}, il dit {dit}"
        );
    }
}

/// **`NotImplemented` A SON PROPRE TYPE DE DOCUMENT**, et non celui d'une faute
/// interne : ce qui manque est une capacité que l'exploitant n'a pas
/// configurée, et le dire lui épargne de chercher le défaut chez son client.
#[test]
fn ce_que_le_serveur_ne_sert_pas_se_dit() {
    assert_eq!(
        document(Reason::NotImplemented),
        "{\"type\":\"/problems/not-implemented\",\"title\":\"ce serveur ne sert pas cette \
         ressource\",\"status\":501}"
    );
}

/// **UN CURSEUR PÉRIMÉ DIT `410`, ET SON PROPRE TYPE** : le client doit le
/// distinguer d'une ressource absente — l'un relit la boîte, l'autre renonce.
#[test]
fn un_curseur_perime_se_dit_gone() {
    let dit = document(Reason::SyncExpired);
    assert!(dit.contains("/problems/gone"), "{dit}");
    assert!(dit.contains("\"status\":410"), "{dit}");
}

/// **UN CORPS TROP LONG DIT `413`, ET SON PROPRE TYPE** : c'est la TAILLE qui
/// gêne, et le client doit pouvoir le distinguer d'un corps mal formé.
#[test]
fn un_corps_trop_long_se_dit_content_too_large() {
    let dit = document(Reason::BodyTooLarge);
    assert!(dit.contains("/problems/content-too-large"), "{dit}");
    assert!(dit.contains("\"status\":413"), "{dit}");
}

/// **UN MESSAGE AVEC PIÈCES JOINTES DIT `422`, ET OÙ ALLER.**
#[test]
fn des_pieces_jointes_d_un_seul_tenant_se_disent_422() {
    let dit = document(Reason::AttachmentsNeedDraft);
    assert!(dit.contains("/problems/attachments-need-draft"), "{dit}");
    assert!(dit.contains("\"status\":422"), "{dit}");
    assert!(dit.contains("/v1/drafts"), "{dit}");
}

/// **UNE CLÉ RÉUTILISÉE DIT `422` SOUS SON PROPRE TYPE** — distinct de celui
/// des pièces jointes, qui partage le code.
#[test]
fn une_cle_reutilisee_a_son_propre_type() {
    let dit = document(Reason::IdempotencyKeyReused);
    assert!(dit.contains("/problems/idempotency-key-reused"), "{dit}");
    assert!(dit.contains("\"status\":422"), "{dit}");
    assert!(document(Reason::IdempotencyInFlight).contains("\"status\":409"));
    assert!(document(Reason::BadIdempotencyKey).contains("/problems/bad-request"));
}

/// **UN ENCODAGE INCONNU DIT `422` SOUS SON PROPRE TYPE**, et renvoie au brut.
#[test]
fn un_encodage_inconnu_a_son_propre_type() {
    let dit = document(Reason::UnknownEncoding);
    assert!(dit.contains("/problems/unknown-encoding"), "{dit}");
    assert!(dit.contains("\"status\":422"), "{dit}");
}

/// **UNE SESSION SANS APPAREIL DIT `409`**, et comment en avoir une.
#[test]
fn une_session_sans_appareil_dit_409() {
    let dit = document(Reason::NotADevice);
    assert!(dit.contains("\"status\":409"), "{dit}");
    assert!(dit.contains("clef"), "{dit}");
}
