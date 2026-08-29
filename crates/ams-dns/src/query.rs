//! L'encodage d'une question.

use crate::name;
use crate::{CLASS_IN, Error, KIND_OPT, Kind};

/// La taille d'un tampon qui suffit toujours à une question.
///
/// Douze octets d'en-tête, un nom (255 au plus), quatre octets de type et de
/// classe, onze pour l'`OPT` d'EDNS(0). On arrondit au-dessus : un tampon serré
/// n'économise rien sur une pile et se paie en cas particuliers.
pub const QUERY_MAX: usize = 512;

/// La taille de réponse annoncée par EDNS(0).
///
/// **Mille deux cent trente-deux octets**, la valeur du « DNS flag day 2020 » :
/// c'est ce qui passe sans fragmentation IPv6 sur un chemin dont le MTU est de
/// 1280. Annoncer plus fait fragmenter, et un datagramme fragmenté est un
/// datagramme qu'un tiers peut plus facilement compléter à sa façon.
const EDNS_PAYLOAD: u16 = 1232;

/// Encode une question, et rend les octets à émettre.
///
/// # Ce que la question dit, et ce qu'elle tait
///
/// - **`RD` est posé** : on s'adresse à un résolveur récursif, et on lui demande
///   de faire le travail. Ce serveur ne suit aucune délégation lui-même.
/// - **Une seule question**, parce qu'aucun serveur n'en traite deux.
/// - **EDNS(0)** annonce 1232 octets, ce qui évite la reprise en TCP sur la
///   plupart des politiques SPF sans faire fragmenter.
/// - **Pas de `DO`** : on ne demande pas les signatures DNSSEC, parce qu'on ne
///   saurait pas les valider. Prétendre le contraire serait pire que de s'en
///   passer.
///
/// L'identifiant vient de l'appelant : il doit être **imprévisible**, et l'aléa
/// appartient à l'étage qui en a une source. Un identifiant prévisible laisse un
/// tiers répondre à notre place.
///
/// # Errors
///
/// [`Error::BufferTooSmall`] si `sortie` ne suffit pas, ou les erreurs de nom.
pub fn encode_query<'a>(
    sortie: &'a mut [u8],
    id: u16,
    nom: &[u8],
    kind: Kind,
) -> Result<&'a [u8], Error> {
    let mut ecrits = 0_usize;
    // ── L'en-tête ───────────────────────────────────────────────────────────
    // id, drapeaux (RD), une question, aucune réponse, aucune autorité, un
    // enregistrement additionnel : l'`OPT`.
    ecrits = pousser(sortie, ecrits, &id.to_be_bytes())?;
    ecrits = pousser(sortie, ecrits, &0x0100_u16.to_be_bytes())?;
    ecrits = pousser(sortie, ecrits, &1_u16.to_be_bytes())?;
    ecrits = pousser(sortie, ecrits, &0_u16.to_be_bytes())?;
    ecrits = pousser(sortie, ecrits, &0_u16.to_be_bytes())?;
    ecrits = pousser(sortie, ecrits, &1_u16.to_be_bytes())?;

    // ── La question ─────────────────────────────────────────────────────────
    // `unwrap_or_default` porte l'impossible dans la bibliothèque standard :
    // `ecrits` vaut douze, et l'en-tête n'a pu s'écrire que si le tampon les
    // portait. Un tampon vide fera dire non à l'écriture du nom, une ligne plus
    // bas — au bon endroit.
    let reste = sortie.get_mut(ecrits..).unwrap_or_default();
    ecrits = ecrits.saturating_add(name::ecrire(reste, nom)?);
    ecrits = pousser(sortie, ecrits, &kind.code().to_be_bytes())?;
    ecrits = pousser(sortie, ecrits, &CLASS_IN.to_be_bytes())?;

    // ── L'`OPT` d'EDNS(0) (RFC 6891 §6.1.2) ─────────────────────────────────
    // Nom racine, type OPT, « classe » = la taille de réponse acceptée, TTL nul
    // (version 0, aucun drapeau — `DO` compris), et pas d'option.
    ecrits = pousser(sortie, ecrits, &[0])?;
    ecrits = pousser(sortie, ecrits, &KIND_OPT.to_be_bytes())?;
    ecrits = pousser(sortie, ecrits, &EDNS_PAYLOAD.to_be_bytes())?;
    ecrits = pousser(sortie, ecrits, &0_u32.to_be_bytes())?;
    ecrits = pousser(sortie, ecrits, &0_u16.to_be_bytes())?;

    sortie.get(..ecrits).ok_or(Error::BufferTooSmall)
}

/// Écrit `morceau` à `position`, et rend la position suivante.
fn pousser(sortie: &mut [u8], position: usize, morceau: &[u8]) -> Result<usize, Error> {
    let fin = position.saturating_add(morceau.len());
    let place = sortie.get_mut(position..fin).ok_or(Error::BufferTooSmall)?;
    place.copy_from_slice(morceau);
    Ok(fin)
}

#[cfg(test)]
mod tests;
