// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! `SCRAM-SHA-256` et `SCRAM-SHA-256-PLUS` (RFC 5802, RFC 7677, RFC 9266).
//!
//! # CE QUE CE MODULE FAIT, ET CE QU'IL NE FAIT PAS
//!
//! Il **analyse** les quatre messages de l'échange et **calcule** ce que
//! l'arithmétique de §3 demande. Il ne décide de rien : il ne sait pas si un
//! compte existe, ne lit aucun magasin, n'alloue pas (C1, C3). C'est la
//! politique de l'appelant qui compare, et elle seule.
//!
//! # POURQUOI CE MÉCANISME, ALORS QUE LE DÉPÔT L'AVAIT REFUSÉ
//!
//! `lib.rs` portait un refus daté du 2026-09-06 — et ce refus énonçait lui-même
//! les trois conditions qui le renverseraient. **La troisième est remplie** :
//! le vérificateur ne vit pas dans le fichier de comptes, mais dans un magasin
//! séparé, chiffré par une clé que ce fichier ne porte pas. Et `-PLUS` répond à
//! la seconde objection par un autre bout : une `ServerKey` volée ne sert à
//! rien à qui ne tient pas AUSSI la session TLS du client, puisque la preuve
//! est liée à l'exportateur de clés de cette session-là.
//!
//! Ce qui reste vrai du refus, et qu'on ne cache pas : le vérificateur se
//! dérive par **PBKDF2** ([`derive_salted_password`]), que §2.2 de RFC 5802
//! impose parce que c'est le CLIENT qui le calcule. On ne peut pas y substituer
//! l'`argon2id` du magasin sans cesser d'interopérer. Le chiffrement du magasin
//! est ce qui compense, et le compte d'itérations ce qui renchérit.
//!
//! # L'ORDRE DES CHOSES (§3)
//!
//! ```text
//! client → n,,n=jean,r=<nonce client>                     `client-first`
//! serveur → r=<nonce client><nonce serveur>,s=<sel>,i=<n>  `server-first`
//! client → c=<liaison>,r=<les deux nonces>,p=<preuve>      `client-final`
//! serveur → v=<signature serveur>                          `server-final`
//! ```
//!
//! Le **`AuthMessage`** est la concaténation, séparée par des virgules, du
//! `client-first-bare`, du `server-first` entier et du `client-final` SANS son
//! `,p=…`. Les deux côtés le reconstruisent ; c'est ce qui lie les trois
//! messages entre eux, et c'est pourquoi [`ClientFinal::sans_preuve`] existe.

use sha2::{Digest as _, Sha256};

use crate::mac::{BLOC, MAC_OCTETS, hmac_sha256};

/// Ce qu'une empreinte SHA-256 occupe — et donc chaque clé de SCRAM.
pub const CLE_OCTETS: usize = MAC_OCTETS;

/// La liaison de canal de RFC 9266 : `tls-exporter`, et rien d'autre.
///
/// **`tls-unique` ET `tls-server-end-point` SONT ÉCARTÉS**, et ce n'est pas un
/// raccourci. Le premier n'existe pas en TLS 1.3 (il dérivait d'un message de
/// poignée de main que la version a supprimé) ; le second lie au CERTIFICAT, ce
/// qui ne protège de rien quand l'attaquant en présente un valide. `tls-exporter`
/// lie à la session elle-même, et vaut pour TLS 1.2 comme pour TLS 1.3 — sous
/// réserve, en 1.2, du secret maître étendu, que `rustls` négocie toujours.
pub const LIAISON: &str = "tls-exporter";

/// Ce qu'un message de SCRAM peut avoir de mal fait.
///
/// **AUCUNE VARIANTE NE DIT « LE MOT DE PASSE EST FAUX »**, et c'est délibéré :
/// ce module ne le sait pas. Il dit qu'un message est mal formé, jamais qu'une
/// preuve est mauvaise — c'est l'appelant qui compare, avec [`egales`].
///
/// [`egales`]: crate::egales
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// Un attribut attendu manque, ou arrive dans le désordre.
    Malformed,
    /// L'en-tête GS2 n'est pas l'un des trois que §5.1 permet.
    Gs2,
    /// Un attribut obligatoire est vide — un nonce, un sel, une preuve.
    Empty,
    /// Le nom d'utilisateur porte un `=` qui n'introduit ni `=2C` ni `=3D`.
    ///
    /// §5.1 : c'est le seul échappement du champ `n=`, et un `=` isolé est une
    /// faute plutôt qu'un caractère.
    Escape,
    /// Le compte d'itérations ne se lit pas, ou vaut moins que le minimum.
    Iterations,
    /// Une valeur en base64 ne se décode pas, ou ne fait pas la taille voulue.
    Base64,
    /// Le message est plus long que ce que ce module accepte.
    TooLong,
}

/// Le plus petit compte d'itérations que §3.1 de RFC 7677 tolère.
pub const ITERATIONS_MIN: u32 = 4_096;

/// Ce que ce module accepte de lire d'un coup.
///
/// **UNE BORNE, PARCE QUE RIEN D'AUTRE NE BORNE.** Un `client-first` arrive
/// d'un pair non authentifié ; sans plafond, un nom d'utilisateur de plusieurs
/// mébioctets ferait travailler l'analyse pour rien. La valeur est large au
/// regard de ce qu'un échange légitime contient — un nom, deux nonces, un sel.
pub const MESSAGE_MAX: usize = 4_096;

/// L'en-tête GS2 d'un `client-first` (§5.1, §7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Gs2 {
    /// `n,,` — le client ne sait pas lier le canal.
    SansLiaison,
    /// `y,,` — le client sait lier, mais croit que le serveur ne sait pas.
    ///
    /// **C'EST LA RÉTROGRADATION QUE §6 FAIT DÉTECTER** : si le serveur a
    /// annoncé `-PLUS`, ce `y` ne peut venir que d'un tiers qui a retiré
    /// l'annonce du fil. L'appelant doit alors REFUSER — ce module se contente
    /// de rapporter ce qu'il a lu.
    LiaisonRefusee,
    /// `p=tls-exporter,,` — le client lie, et voici à quoi.
    Liee,
}

/// Le `client-first` analysé.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientFirst<'a> {
    /// L'en-tête GS2, tel qu'il a été lu.
    pub gs2: Gs2,
    /// L'en-tête GS2 en octets — il entre TEL QUEL dans le `c=` du client-final.
    pub gs2_brut: &'a [u8],
    /// Le nom d'utilisateur, **encore échappé** (`=2C`, `=3D`).
    ///
    /// Le déséchapper demanderait d'écrire quelque part, donc d'allouer (C3) :
    /// [`desechapper`] le fait dans un tampon que l'appelant fournit.
    pub username: &'a [u8],
    /// Le nonce du client, tel quel.
    pub nonce: &'a [u8],
    /// `n=…,r=…` — la partie qui entre dans le `AuthMessage`.
    pub bare: &'a [u8],
}

/// Le `client-final` analysé.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientFinal<'a> {
    /// `c=` décodé : l'en-tête GS2 suivi, s'il y a lieu, des données de liaison.
    pub channel_binding: &'a [u8],
    /// Le nonce complet, qui doit reprendre celui du serveur à l'identique.
    pub nonce: &'a [u8],
    /// La preuve du client, décodée — 32 octets.
    pub proof: [u8; CLE_OCTETS],
    /// Le message sans son `,p=…` : la troisième part du `AuthMessage`.
    pub sans_preuve: &'a [u8],
}

/// Analyse un `client-first` (§7 : `gs2-header client-first-bare`).
///
/// # Errors
///
/// [`Error`] — en-tête GS2 inconnu, attributs manquants ou vides, échappement
/// mal formé, message trop long.
pub fn parse_client_first(message: &[u8]) -> Result<ClientFirst<'_>, Error> {
    if message.len() > MESSAGE_MAX {
        return Err(Error::TooLong);
    }
    // ── L'EN-TÊTE GS2 ───────────────────────────────────────────────────────
    //
    // §5.1 en permet trois formes, et **l'identité d'autorisation `a=` n'est
    // pas de celles qu'on accepte** : ce serveur ne sait pas agir pour un
    // tiers, exactement comme `parse_plain` le refuse déjà. La virgule vide
    // entre l'en-tête et le corps est donc obligatoire.
    let (gs2, reste) = if let Some(reste) = apres(message, b"n,,") {
        (Gs2::SansLiaison, reste)
    } else if let Some(reste) = apres(message, b"y,,") {
        (Gs2::LiaisonRefusee, reste)
    } else if let Some(reste) = apres(message, b"p=tls-exporter,,") {
        (Gs2::Liee, reste)
    } else {
        return Err(Error::Gs2);
    };
    // **PAS DE GARDE ICI**, et c'est voulu : `entete` vaut la différence de deux
    // longueurs du MÊME message, donc une borne valide par construction. Un
    // `ok_or(…)?` ouvrirait une branche qu'aucune entrée ne peut atteindre, et
    // C2 les refuse — ce ne sont pas des gardes, mais des affirmations que rien
    // ne vérifie.
    let entete = message.len().saturating_sub(reste.len());
    let gs2_brut = message.get(..entete).unwrap_or_default();

    // ── LE CORPS : `n=<nom>,r=<nonce>` ──────────────────────────────────────
    //
    // §5 permet des attributs d'extension APRÈS `r=`, et demande de les
    // ignorer. On coupe donc sur la première virgule qui suit le nonce plutôt
    // que d'exiger la fin du message.
    let apres_n = apres(reste, b"n=").ok_or(Error::Malformed)?;
    let (username, apres_nom) = jusqu_a_virgule(apres_n);
    verifier_echappement(username)?;
    let apres_r = apres(apres_nom, b"r=").ok_or(Error::Malformed)?;
    let (nonce, _) = jusqu_a_virgule(apres_r);
    if username.is_empty() || nonce.is_empty() {
        return Err(Error::Empty);
    }
    Ok(ClientFirst {
        gs2,
        gs2_brut,
        username,
        nonce,
        bare: reste,
    })
}

/// Analyse un `client-final` (§7), en déchiffrant son `c=` dans `liaison`.
///
/// `liaison` reçoit l'en-tête GS2 et, s'il y a lieu, les données de liaison de
/// canal : c'est l'appelant qui fournit le tampon, puisque cette crate n'alloue
/// pas. Il doit faire au moins [`MESSAGE_MAX`] octets.
///
/// # Errors
///
/// [`Error`] — attributs manquants, base64 illisible, preuve qui ne fait pas
/// trente-deux octets, tampon trop court.
pub fn parse_client_final<'a>(
    message: &'a [u8],
    liaison: &'a mut [u8],
) -> Result<ClientFinal<'a>, Error> {
    if message.len() > MESSAGE_MAX {
        return Err(Error::TooLong);
    }
    let apres_c = apres(message, b"c=").ok_or(Error::Malformed)?;
    let (c_encode, apres_liaison) = jusqu_a_virgule(apres_c);
    let ecrits = crate::decode_base64(c_encode, liaison).map_err(|_| Error::Base64)?;

    let apres_r = apres(apres_liaison, b"r=").ok_or(Error::Malformed)?;
    let (nonce, apres_nonce) = jusqu_a_virgule(apres_r);
    if nonce.is_empty() {
        return Err(Error::Empty);
    }

    // **`p=` EST LE DERNIER ATTRIBUT, ET §7 L'EXIGE.** C'est ce qui permet de
    // reconstruire le `AuthMessage` en coupant le message à cet endroit précis.
    let debut_preuve = position(message, b",p=").ok_or(Error::Malformed)?;
    // `position` rend un rang DANS `message` : la coupe est valide, et la garde
    // serait inatteignable (même raison qu'en `parse_client_first`).
    let sans_preuve = message.get(..debut_preuve).unwrap_or_default();
    // `apres_nonce` commence APRÈS la virgule qui clôt le nonce : l'attribut de
    // preuve s'y lit donc `p=`, sans sa virgule. Une seconde tentative avec
    // `,p=` serait une branche qu'aucune entrée ne peut atteindre — et C2 refuse
    // les gardes inatteignables, qui ne sont pas des gardes mais des
    // affirmations non vérifiées.
    let apres_p = apres(apres_nonce, b"p=").ok_or(Error::Malformed)?;
    let (preuve_encodee, _) = jusqu_a_virgule(apres_p);
    let mut preuve = [0_u8; CLE_OCTETS];
    let lus = crate::decode_base64(preuve_encodee, &mut preuve).map_err(|_| Error::Base64)?;
    if lus != CLE_OCTETS {
        return Err(Error::Base64);
    }

    // `decode_base64` rend ce qu'il a écrit DANS `liaison` : la coupe est
    // valide par construction.
    let channel_binding = liaison.get(..ecrits).unwrap_or_default();
    Ok(ClientFinal {
        channel_binding,
        nonce,
        proof: preuve,
        sans_preuve,
    })
}

/// Déséchappe un `n=` (§5.1 : `=2C` pour `,`, `=3D` pour `=`) dans `sortie`.
///
/// Rend combien d'octets ont été écrits.
///
/// # Errors
///
/// [`Error::Escape`] — un `=` qui n'introduit ni `2C` ni `3D` ;
/// [`Error::TooLong`] — le tampon est trop court.
pub fn desechapper(nom: &[u8], sortie: &mut [u8]) -> Result<usize, Error> {
    let mut ecrits = 0_usize;
    let mut rang = 0_usize;
    while let Some(octet) = nom.get(rang) {
        let (valeur, avance) = match octet {
            b'=' => match (
                nom.get(rang.saturating_add(1)),
                nom.get(rang.saturating_add(2)),
            ) {
                (Some(b'2'), Some(b'C')) => (b',', 3),
                (Some(b'3'), Some(b'D')) => (b'=', 3),
                _ => return Err(Error::Escape),
            },
            autre => (*autre, 1),
        };
        *sortie.get_mut(ecrits).ok_or(Error::TooLong)? = valeur;
        ecrits = ecrits.saturating_add(1);
        rang = rang.saturating_add(avance);
    }
    Ok(ecrits)
}

/// `Hi(str, salt, i)` de §2.2 : PBKDF2-HMAC-SHA-256, une seule sortie de bloc.
///
/// # POURQUOI ÉCRIT ICI, ET NON PRIS D'UNE CRATE
///
/// La même raison que pour le HMAC : PBKDF2 sur un seul bloc tient en dix
/// lignes, et RFC 7677 §3 en donne un vecteur d'essai. Un vecteur prouve le
/// résultat ; une dépendance ne prouve que la provenance. Et le cas général de
/// PBKDF2 — plusieurs blocs, une longueur demandée — n'a pas d'emploi ici :
/// SCRAM-SHA-256 veut exactement trente-deux octets, soit un bloc.
///
/// **LE COMPTE D'ITÉRATIONS EST PAYÉ PAR LE CLIENT AUSSI**, à chaque ouverture
/// de session. C'est ce qui en borne la hausse : ce n'est pas `argon2id`, dont
/// seul le serveur paie le coût.
#[must_use]
pub fn derive_salted_password(
    mot_de_passe: &[u8],
    sel: &[u8],
    iterations: u32,
) -> [u8; CLE_OCTETS] {
    // U1 = HMAC(mot de passe, sel ‖ INT(1)) — le compteur de bloc de PBKDF2,
    // sur quatre octets en gros-boutien, et il vaut 1 puisqu'il n'y a qu'un bloc.
    let mut message = [0_u8; MESSAGE_MAX];
    let coupe = sel.len().min(MESSAGE_MAX.saturating_sub(4));
    let mut longueur = 0_usize;
    for (ou, lu) in message.iter_mut().zip(sel.get(..coupe).unwrap_or_default()) {
        *ou = *lu;
        longueur = longueur.saturating_add(1);
    }
    // **LA PLACE EXISTE TOUJOURS** : `coupe` a réservé les quatre octets du
    // compteur en bornant le sel à `MESSAGE_MAX - 4`. Un `if let` laisserait ici
    // une branche que rien ne peut prendre.
    for (place, octet) in message
        .get_mut(longueur..longueur.saturating_add(4))
        .unwrap_or_default()
        .iter_mut()
        .zip([0, 0, 0, 1])
    {
        *place = octet;
    }
    longueur = longueur.saturating_add(4);
    let mut u = hmac_sha256(mot_de_passe, message.get(..longueur).unwrap_or_default());
    let mut sortie = u;
    // **`iterations - 1` TOURS DE PLUS** : §5.2 de RFC 8018 compte U1 dans le
    // total. Un compte de 1 rend donc U1 seul, et c'est le bon comportement.
    for _ in 1..iterations {
        u = hmac_sha256(mot_de_passe, &u);
        for (accumule, nouveau) in sortie.iter_mut().zip(u) {
            *accumule ^= nouveau;
        }
    }
    sortie
}

/// `ClientKey = HMAC(SaltedPassword, "Client Key")` (§3).
#[must_use]
pub fn client_key(salted: &[u8; CLE_OCTETS]) -> [u8; CLE_OCTETS] {
    hmac_sha256(salted, b"Client Key")
}

/// `ServerKey = HMAC(SaltedPassword, "Server Key")` (§3).
///
/// **CELLE-LÀ EST DANGEREUSE À STOCKER EN CLAIR** : §9 dit qu'elle permet
/// d'usurper le SERVEUR auprès des clients. C'est la raison pour laquelle le
/// magasin qui la porte est chiffré, et non le fichier de comptes.
#[must_use]
pub fn server_key(salted: &[u8; CLE_OCTETS]) -> [u8; CLE_OCTETS] {
    hmac_sha256(salted, b"Server Key")
}

/// `StoredKey = H(ClientKey)` (§3).
#[must_use]
pub fn stored_key(client_key: &[u8; CLE_OCTETS]) -> [u8; CLE_OCTETS] {
    Sha256::digest(client_key).into()
}

/// `ClientSignature = HMAC(StoredKey, AuthMessage)`, puis `ClientKey` retrouvée.
///
/// Le serveur ne connaît pas `ClientKey` : il la **reconstitue** en défaisant le
/// ou-exclusif de la preuve, puis vérifie que son empreinte est bien la
/// `StoredKey` qu'il détient. C'est tout le mécanisme de §3, et c'est ce qui
/// fait qu'un magasin volé ne permet pas de se faire passer pour le CLIENT.
#[must_use]
pub fn client_key_depuis_preuve(
    stored: &[u8; CLE_OCTETS],
    auth_message: &[u8],
    preuve: &[u8; CLE_OCTETS],
) -> [u8; CLE_OCTETS] {
    let signature = hmac_sha256(stored, auth_message);
    let mut retrouvee = [0_u8; CLE_OCTETS];
    for ((ou, p), s) in retrouvee.iter_mut().zip(preuve).zip(signature) {
        *ou = p ^ s;
    }
    retrouvee
}

/// `ServerSignature = HMAC(ServerKey, AuthMessage)` (§3) — le `v=` final.
#[must_use]
pub fn server_signature(server_key: &[u8; CLE_OCTETS], auth_message: &[u8]) -> [u8; CLE_OCTETS] {
    hmac_sha256(server_key, auth_message)
}

/// `ClientProof = ClientKey XOR ClientSignature` (§3) — ce qu'un CLIENT envoie.
///
/// Écrite ici pour que le banc puisse jouer un vrai client : une implémentation
/// qu'on n'éprouve que contre elle-même ne prouve que sa cohérence.
#[must_use]
pub fn client_proof(
    client_key: &[u8; CLE_OCTETS],
    stored: &[u8; CLE_OCTETS],
    auth_message: &[u8],
) -> [u8; CLE_OCTETS] {
    let signature = hmac_sha256(stored, auth_message);
    let mut preuve = [0_u8; CLE_OCTETS];
    for ((ou, c), s) in preuve.iter_mut().zip(client_key).zip(signature) {
        *ou = c ^ s;
    }
    preuve
}

/// Lit le compte d'itérations d'un `i=` (§7 : `posit-number`, sans zéro en tête).
///
/// # Errors
///
/// [`Error::Iterations`] — vide, non numérique, zéro en tête, débordement, ou
/// sous [`ITERATIONS_MIN`].
pub fn parse_iterations(champ: &[u8]) -> Result<u32, Error> {
    if champ.is_empty() || champ.first() == Some(&b'0') {
        return Err(Error::Iterations);
    }
    let mut valeur = 0_u32;
    for octet in champ {
        let chiffre = octet
            .checked_sub(b'0')
            .filter(|c| *c <= 9)
            .ok_or(Error::Iterations)?;
        valeur = valeur
            .checked_mul(10)
            .and_then(|v| v.checked_add(u32::from(chiffre)))
            .ok_or(Error::Iterations)?;
    }
    if valeur < ITERATIONS_MIN {
        return Err(Error::Iterations);
    }
    Ok(valeur)
}

// ── Les petites mains de l'analyse ──────────────────────────────────────────

/// Ce qui suit `prefixe`, si `message` commence par lui.
fn apres<'a>(message: &'a [u8], prefixe: &[u8]) -> Option<&'a [u8]> {
    message
        .get(..prefixe.len())
        .filter(|debut| *debut == prefixe)
        .and_then(|_| message.get(prefixe.len()..))
}

/// Ce qui précède la première virgule, et ce qui la suit.
fn jusqu_a_virgule(message: &[u8]) -> (&[u8], &[u8]) {
    match message.iter().position(|octet| *octet == b',') {
        Some(rang) => (
            message.get(..rang).unwrap_or_default(),
            message.get(rang.saturating_add(1)..).unwrap_or_default(),
        ),
        None => (message, &[]),
    }
}

/// Où commence `motif` dans `message`.
fn position(message: &[u8], motif: &[u8]) -> Option<usize> {
    message
        .windows(motif.len())
        .position(|fenetre| fenetre == motif)
}

/// Le `n=` ne porte-t-il que des échappements licites ?
fn verifier_echappement(nom: &[u8]) -> Result<(), Error> {
    let mut rang = 0_usize;
    while let Some(octet) = nom.get(rang) {
        if *octet == b'=' {
            match (
                nom.get(rang.saturating_add(1)),
                nom.get(rang.saturating_add(2)),
            ) {
                (Some(b'2'), Some(b'C')) | (Some(b'3'), Some(b'D')) => {
                    rang = rang.saturating_add(3)
                }
                _ => return Err(Error::Escape),
            }
        } else {
            rang = rang.saturating_add(1);
        }
    }
    Ok(())
}

/// La taille de bloc de SHA-256, reprise de [`crate::mac`] pour le PBKDF2.
const _: () = assert!(BLOC == 64);

#[cfg(test)]
mod tests;
