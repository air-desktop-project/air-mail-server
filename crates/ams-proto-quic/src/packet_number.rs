// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Le numéro de paquet, tronqué à l'écriture et reconstruit à la lecture
//! (RFC 9000 §17.1, annexes A.2 et A.3).
//!
//! # UN NUMÉRO DE SOIXANTE-DEUX BITS QUI TIENT SUR UN OCTET
//!
//! Un numéro de paquet va jusqu'à 2^62 - 1, et l'écrire en entier dans chaque
//! paquet coûterait huit octets sur des paquets qui en font parfois quarante.
//! On n'écrit donc que les bits de POIDS FAIBLE, et le receveur reconstruit le
//! reste à partir de ce qu'il a déjà reçu.
//!
//! **C'est une fenêtre glissante, et elle peut glisser sur le mauvais bord.**
//! Si l'écrivain tronque trop court, deux numéros différents se réduisent aux
//! mêmes bits, et le receveur en choisit un — le mauvais. Le paquet est alors
//! déchiffré avec le mauvais nonce, l'authentification échoue, et le paquet est
//! jeté. Cela ne casse pas la sécurité ; cela casse la connexion, en silence.
//!
//! # LE CHIFFREMENT LES CACHE, ET C'EST POUR CELA QU'ILS COMPTENT
//!
//! Ces bits sont protégés par la protection d'en-tête (RFC 9001 §5.4) : un
//! observateur ne voit pas le numéro, et ne peut donc pas relier deux paquets
//! d'une même connexion en les regardant passer. C'est ce qui distingue QUIC de
//! TCP, dont le numéro de séquence est en clair — et c'est aussi pourquoi la
//! troncature ne peut pas se contenter d'être « probablement assez longue ».

use crate::error::{Error, Reason};

/// La plus grande valeur qu'un numéro de paquet puisse prendre : 2^62 - 1.
pub const PACKET_NUMBER_MAX: u64 = (1 << 62) - 1;

/// La taille de l'espace des numéros de paquet : 2^62.
///
/// C'est [`PACKET_NUMBER_MAX`] plus un, et l'annexe A.3 s'en sert telle quelle.
/// **Écrire `MAX` là où la RFC écrit `2^62` décalerait la borne d'une unité**,
/// et changerait la reconstruction pour exactement un numéro — celui du tout
/// dernier paquet que la connexion puisse porter.
const ESPACE: u64 = 1 << 62;

/// Combien d'octets un numéro de paquet peut occuper (§17.1).
pub const PACKET_NUMBER_OCTETS_MAX: usize = 4;

/// Écrit les `octets` de poids faible d'un numéro.
///
/// # Errors
///
/// [`Reason::BadPacketNumberLength`] hors de un..=quatre ;
/// [`Reason::PacketNumberTooLarge`] au-delà de 2^62 - 1 ;
/// [`Reason::BufferTooSmall`].
pub fn encode(numero: u64, octets: usize, out: &mut [u8]) -> Result<usize, Error> {
    if numero > PACKET_NUMBER_MAX {
        return Err(Error::new(Reason::PacketNumberTooLarge));
    }
    if octets == 0 || octets > PACKET_NUMBER_OCTETS_MAX {
        return Err(Error::new(Reason::BadPacketNumberLength));
    }
    let place = out
        .get_mut(..octets)
        .ok_or_else(|| Error::new(Reason::BufferTooSmall))?;
    let huit = numero.to_be_bytes();
    // On ne garde que la queue : `octets` vaut au plus quatre, et `huit` en a
    // huit — la soustraction ne peut pas manquer.
    let depuis = huit.len().saturating_sub(octets);
    for (place, lu) in place.iter_mut().zip(huit.get(depuis..).unwrap_or_default()) {
        *place = *lu;
    }
    Ok(octets)
}

/// Combien d'octets il FAUT pour que le pair puisse reconstruire.
///
/// `largest_acked` est le plus grand numéro que le pair a acquitté ; `None`
/// s'il n'en a acquitté aucun.
///
/// # LA RÈGLE DE L'ANNEXE A.2, ET POURQUOI ELLE EST CE QU'ELLE EST
///
/// Il faut assez de bits pour distinguer **deux fois** le nombre de paquets
/// non acquittés. Deux fois, parce que la fenêtre de reconstruction est centrée
/// sur le numéro attendu : la moitié devant, la moitié derrière. Un bit de moins
/// et deux numéros se confondent ; le paquet est déchiffré avec le mauvais
/// nonce, jeté sans un mot, et la connexion s'éteint sans que rien ne dise
/// pourquoi.
///
/// # Errors
///
/// [`Reason::PacketNumberTooLarge`] au-delà de 2^62 - 1, ou si `largest_acked`
/// dépasse `numero` — un pair ne peut pas acquitter ce qu'on n'a pas envoyé.
pub fn encoded_len(numero: u64, largest_acked: Option<u64>) -> Result<usize, Error> {
    if numero > PACKET_NUMBER_MAX {
        return Err(Error::new(Reason::PacketNumberTooLarge));
    }
    let non_acquittes = match largest_acked {
        // Rien d'acquitté : tous les paquets depuis le premier comptent.
        None => numero.saturating_add(1),
        Some(acquitte) => numero
            .checked_sub(acquitte)
            .ok_or_else(|| Error::new(Reason::PacketNumberTooLarge))?,
    };
    // Il faut `log2(non_acquittes) + 1` bits, puis deux fois cela — soit un bit
    // de plus. `ilog2` d'une valeur nulle paniquerait : le `max(1)` l'écarte, et
    // `saturating_add` fait le reste.
    let bits = non_acquittes.max(1).ilog2().saturating_add(2);
    let octets = bits.saturating_add(7) / 8;
    // Au-delà de quatre octets, on écrit quatre : c'est la borne de §17.1, et
    // un pair qui perdrait 2^31 paquets d'affilée a d'autres soucis.
    Ok(usize::try_from(octets)
        .unwrap_or(PACKET_NUMBER_OCTETS_MAX)
        .clamp(1, PACKET_NUMBER_OCTETS_MAX))
}

/// Reconstruit un numéro complet à partir de ses bits de poids faible.
///
/// `largest` est le plus grand numéro DÉJÀ TRAITÉ dans cet espace, `tronque` ce
/// que le paquet portait, et `octets` sa longueur.
///
/// # L'ALGORITHME DE L'ANNEXE A.3, ET IL SE SUIT À LA LETTRE
///
/// On prend le numéro attendu, on lui substitue les bits reçus, puis on regarde
/// si le candidat tombe trop loin d'un côté ou de l'autre : dans ce cas, c'est
/// que la fenêtre a glissé, et il faut ajouter ou retirer une fenêtre entière.
///
/// **Les deux gardes de bord ne sont pas décoratives.** Sans la première, un
/// numéro proche de zéro remonterait sous zéro ; sans la seconde, un numéro
/// proche de 2^62 déborderait. La RFC les écrit toutes les deux, et elles
/// répondent à deux situations différentes.
///
/// # LE PLUS GRAND TRAITÉ EST UN NUMÉRO, ET IL A DONC UNE BORNE
///
/// Un `largest` hors de l'espace ferait sortir le candidat de l'espace à son
/// tour, et l'on rendrait un numéro qu'aucun paquet ne peut porter. Le fuzz l'a
/// trouvé en trois minutes : rien dans le calcul ne ramenait le résultat dans
/// ses bornes, parce que rien ne vérifiait l'entrée. **Une borne qu'on ne
/// vérifie qu'à la sortie n'est pas une borne : c'est une espérance.**
///
/// # Errors
///
/// [`Reason::BadPacketNumberLength`] hors de un..=quatre ;
/// [`Reason::PacketNumberTooLarge`] si `largest` sort de l'espace ;
/// [`Reason::PacketNumberSpaceExhausted`] s'il en atteint la borne.
pub fn decode(largest: Option<u64>, tronque: u64, octets: usize) -> Result<u64, Error> {
    if octets == 0 || octets > PACKET_NUMBER_OCTETS_MAX {
        return Err(Error::new(Reason::BadPacketNumberLength));
    }
    if largest.is_some_and(|vu| vu > PACKET_NUMBER_MAX) {
        return Err(Error::new(Reason::PacketNumberTooLarge));
    }
    // **À LA BORNE, IL N'Y A PAS DE SUIVANT.** Le numéro attendu serait 2^62,
    // hors de l'espace, et le candidat qu'on en tirerait aussi. §12.3 exige
    // qu'on ait fermé avant : si on nous le demande quand même, on le dit
    // plutôt que de rendre un numéro qu'aucun paquet ne peut porter.
    if largest == Some(PACKET_NUMBER_MAX) {
        return Err(Error::new(Reason::PacketNumberSpaceExhausted));
    }
    // La fenêtre : deux puissance le nombre de bits reçus. Quatre octets font
    // trente-deux bits, et 2^32 tient largement dans un `u64`.
    let bits = u32::try_from(octets).unwrap_or(0).saturating_mul(8);
    let fenetre = 1_u64.checked_shl(bits).unwrap_or(0);
    let demi = fenetre / 2;
    let masque = fenetre.saturating_sub(1);
    // §A.3 : `expected_pn = largest_pn + 1`. Sans aucun paquet traité, c'est
    // zéro qu'on attend — et non « moins un plus un ».
    let attendu = match largest {
        Some(vu) => vu.saturating_add(1),
        None => 0,
    };
    let candidat = (attendu & !masque) | (tronque & masque);
    // Trop bas : la fenêtre a glissé vers l'avant depuis l'écriture.
    if candidat.saturating_add(demi) <= attendu && candidat < ESPACE.saturating_sub(fenetre) {
        return Ok(candidat.saturating_add(fenetre));
    }
    // Trop haut : c'est un paquet plus ancien qu'il n'y paraît.
    if candidat > attendu.saturating_add(demi) && candidat >= fenetre {
        return Ok(candidat.saturating_sub(fenetre));
    }
    Ok(candidat)
}

#[cfg(test)]
mod tests;
