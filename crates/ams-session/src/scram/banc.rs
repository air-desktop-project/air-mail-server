// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Le serveur et le client SCRAM que les bancs de session jouent.
//!
//! # POURQUOI UN SEUL BANC POUR LES DEUX PROTOCOLES
//!
//! SMTP et IMAP conduisent le MÊME échange : seuls l'enveloppe des messages et
//! le moment du verdict diffèrent. Deux politiques d'essai, une par protocole,
//! feraient deux fois la même arithmétique — et le jour où l'une se tromperait,
//! elle se tromperait seule, en silence, en rendant son propre banc vert.
//!
//! # ET LE CLIENT CALCULE PAR `ams-sasl`, PAS PAR LUI-MÊME
//!
//! Une implémentation éprouvée contre elle-même ne prouve que sa cohérence. Le
//! client de ces bancs emprunte le chemin que le vecteur de RFC 7677 valide, et
//! le serveur d'ici vérifie par le sien.

use crate::policy::ScramFirst;

/// Ce que la politique d'un banc sait faire de SCRAM.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AvecScram {
    /// Elle ne le sert pas : le cas d'un serveur sans magasin.
    Aucun,
    /// Elle le conduit de bout en bout.
    Complet,
    /// Elle le commence et ne sait pas le conclure — `scram_final` reste celui
    /// du trait, qui refuse.
    SansConclure,
}

/// Le seul compte que les bancs connaissent.
pub const COMPTE: &[u8] = b"jean";
/// Son mot de passe.
pub const SECRET: &[u8] = b"ouvre-toi";
/// Son sel, et les tours de PBKDF2 qui vont avec.
pub const SEL: [u8; 16] = [5; 16];
pub const TOURS: u32 = 4_096;
/// Le nonce que le serveur du banc ajoute — fixe, pour que le banc soit
/// reproductible. Un vrai serveur en tire un neuf à chaque échange.
pub const NONCE_SERVEUR: &[u8] = b"noncedeserveur";

/// Le `server-first` de RFC 5802 §3, écrit dans `sortie`.
pub fn server_first(mode: AvecScram, client_first: &[u8], sortie: &mut [u8]) -> Option<ScramFirst> {
    if mode == AvecScram::Aucun {
        return None;
    }
    // **LE SEUL ÉCHEC POSSIBLE ICI EST CELUI D'UN MESSAGE ILLISIBLE**, et un
    // essai l'emprunte. Tout ce qui suit est composé dans un tampon que ce banc
    // remplit lui-même : un `?` de plus y serait un garde que rien ne peut
    // atteindre, et C2 le compterait à jamais découvert.
    let lu = ams_sasl::parse_client_first(client_first).ok()?;
    let mut message = std::vec::Vec::from(&b"r="[..]);
    message.extend_from_slice(lu.nonce);
    message.extend_from_slice(NONCE_SERVEUR);
    // Le sel de l'exemple, encodé — `[5; 16]` fait `BQUFBQUFBQUFBQUFBQUFBQ==`.
    message.extend_from_slice(b",s=BQUFBQUFBQUFBQUFBQUFBQ==,i=4096");
    let ecrits = message.len();
    sortie
        .get_mut(..ecrits)
        .expect("la session offre 256 octets, et ce message en fait moins de cent")
        .copy_from_slice(&message);
    // Le `client-first-bare` commence après l'en-tête GS2, que l'analyse vient
    // de mesurer : la soustraction ne peut pas passer sous zéro.
    let debut_bare = client_first.len().saturating_sub(lu.bare.len());
    Some(ScramFirst { ecrits, debut_bare })
}

/// Vérifie la preuve, et écrit le `server-final` (`v=…`) dans `sortie`.
pub fn server_final(
    mode: AvecScram,
    bare: &[u8],
    first: &[u8],
    client_final: &[u8],
    sortie: &mut [u8],
) -> Option<usize> {
    if mode != AvecScram::Complet {
        return None;
    }
    let mut liaison = [0_u8; 1024];
    let lu = ams_sasl::parse_client_final(client_final, &mut liaison).ok()?;
    let message = auth_message(bare, first, lu.sans_preuve);

    let salted = ams_sasl::derive_salted_password(SECRET, &SEL, TOURS);
    let stored = ams_sasl::stored_key(&ams_sasl::client_key(&salted));
    let retrouvee = ams_sasl::client_key_depuis_preuve(&stored, &message, &lu.proof);
    if !ams_sasl::egales(&ams_sasl::stored_key(&retrouvee), &stored) {
        return None;
    }
    let signature = ams_sasl::server_signature(&ams_sasl::server_key(&salted), &message);
    let mut encode = [0_u8; 64];
    let dit = ams_mime::encode_base64_line(&signature, &mut encode)
        .expect("quarante-quatre octets de base64 tiennent dans soixante-quatre");
    let mut rendu = std::vec::Vec::from(&b"v="[..]);
    rendu.extend_from_slice(dit);
    sortie
        .get_mut(..rendu.len())
        .expect("la session offre 256 octets, et `v=` plus la signature en font 46")
        .copy_from_slice(&rendu);
    Some(rendu.len())
}

/// Le `AuthMessage` de RFC 5802 §3 : les trois messages, virgules comprises.
pub fn auth_message(bare: &[u8], first: &[u8], sans_preuve: &[u8]) -> std::vec::Vec<u8> {
    let mut message = std::vec::Vec::new();
    message.extend_from_slice(bare);
    message.push(b',');
    message.extend_from_slice(first);
    message.push(b',');
    message.extend_from_slice(sans_preuve);
    message
}

/// Le client calcule sa preuve, et rend le `client-final` complet.
pub fn client_final(bare: &[u8], server_first: &[u8]) -> std::vec::Vec<u8> {
    let sans_preuve = {
        let mut v = std::vec::Vec::from(&b"c=biws,r="[..]);
        // Le `r=` du client-final reprend le nonce COMPLET du server-first.
        let nonce = server_first
            .get(2..)
            .and_then(|reste| reste.split(|octet| *octet == b',').next())
            .expect("nonce");
        v.extend_from_slice(nonce);
        v
    };
    let message = auth_message(bare, server_first, &sans_preuve);
    let salted = ams_sasl::derive_salted_password(SECRET, &SEL, TOURS);
    let ck = ams_sasl::client_key(&salted);
    let preuve = ams_sasl::client_proof(&ck, &ams_sasl::stored_key(&ck), &message);
    let mut encode = [0_u8; 64];
    let preuve_b64 = ams_mime::encode_base64_line(&preuve, &mut encode).expect("base64");

    let mut complet = sans_preuve;
    complet.extend_from_slice(b",p=");
    complet.extend_from_slice(preuve_b64);
    complet
}

/// Ce que le pair écrirait sur le fil : du base64, en une ligne.
pub fn en_base64(clair: &[u8]) -> std::string::String {
    let mut place = [0_u8; 1024];
    std::string::String::from_utf8_lossy(
        ams_mime::encode_base64_line(clair, &mut place).expect("base64"),
    )
    .into_owned()
}
