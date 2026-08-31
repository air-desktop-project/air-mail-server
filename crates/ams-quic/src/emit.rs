// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! La fabrication d'un paquet protégé — l'inverse exact de [`crate::open_packet`].
//!
//! # L'ORDRE EST CELUI DE LA LECTURE, À L'ENVERS
//!
//! 1. écrire l'en-tête EN CLAIR, la longueur du numéro dans son premier octet ;
//! 2. écrire le numéro tronqué (§17.1) ;
//! 3. chiffrer la charge, **l'en-tête servant de données associées** ;
//! 4. **alors seulement**, masquer l'en-tête.
//!
//! La quatrième vient en dernier parce que le masque se calcule sur un
//! échantillon du CHIFFRÉ (§5.4.2 de RFC 9001). Masquer avant de chiffrer
//! prendrait l'échantillon dans du clair, et le pair — qui masque après — ne
//! trouverait pas le même. La faute ne se verrait pas chez nous : elle se
//! verrait chez lui, sous la forme d'un paquet illisible.
//!
//! # ON NE SAIT PAS ÉMETTRE DE `0-RTT`, ET CELA SE VOIT DANS LE TYPE
//!
//! [`Plan`] n'a pas de variante pour lui. Nous ne l'offrons pas (C6) : des
//! données précoces ne sont pas protégées contre le rejeu (§17.2.3), et une
//! requête rejouée est une requête traitée deux fois. **Un champ « veut-on du
//! `0-RTT` ? » finirait par être basculé ; une variante absente ne se bascule
//! pas.**
//!
//! # NI DE `Retry`, NI DE NÉGOCIATION DE VERSION
//!
//! Ceux-là ne portent ni numéro ni charge chiffrée : rien de ce module ne les
//! concerne. Les faire entrer dans le même [`Plan`] obligerait chaque étape à
//! écarter deux cas qui ne lui ressemblent pas — et une étape qui écarte est
//! une étape qu'on peut oublier d'écrire.

use ams_proto_quic::{ConnectionId, VERSION_1, packet_numbers, varints};
use ams_quic_crypto::{PACKET_OCTETS_MAX, TAG_OCTETS};

use crate::protection::Protection;

use crate::error::{Error, Reason};

/// Ce que la protection d'en-tête échantillonne (§5.4.2).
const ECHANTILLON_OCTETS: usize = 16;

/// De combien d'octets l'échantillon suit le début du numéro (§5.4.2).
///
/// **QUATRE, C'EST-À-DIRE LA LONGUEUR MAXIMALE D'UN NUMÉRO.** Le pair qui
/// démasque ne connaît pas encore la longueur réelle — elle est dans l'octet
/// qu'il n'a pas encore démasqué —, donc les deux côtés font comme si elle
/// valait toujours quatre.
const ECHANTILLON_APRES: usize = 4;

/// Le bit fixe, que tout paquet porte (§17.2, §17.3).
const BIT_FIXE: u8 = 0x40;

/// Le bit de forme longue (§17.2).
const BIT_FORME_LONGUE: u8 = 0x80;

/// Les bits de type d'un `Handshake` (§17.2.4).
const TYPE_HANDSHAKE: u8 = 0x20;

/// Le bit de phase de clé d'un en-tête court (§17.3.1).
const BIT_PHASE: u8 = 0x04;

/// Ce que la version occupe dans un en-tête long (§17.2).
const VERSION_OCTETS: usize = 4;

/// Ce qu'on veut écrire, et sous quelle forme.
///
/// # POURQUOI UN `enum` ET NON UNE STRUCTURE À CHAMPS FACULTATIFS
///
/// Un jeton n'existe que dans un `Initial` (§17.2.2), un identifiant de source
/// que dans un en-tête long (§17.3 n'en porte pas), une phase de clé que dans un
/// en-tête court. Une structure unique laisserait renseigner un jeton pour un
/// paquet `1-RTT` — ce qui n'a pas de sens, et qu'aucune écriture ne
/// rattraperait, puisque le champ serait simplement ignoré. **Un réglage sans
/// effet est pire qu'un réglage absent** : on croit l'avoir posé.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Plan<'a> {
    /// Un `Initial` (§17.2.2) — le seul qui porte un jeton.
    Initial {
        /// L'identifiant que le pair attend.
        destination: ConnectionId,
        /// Celui qu'on veut qu'il emploie désormais.
        source: ConnectionId,
        /// Le jeton, ou rien.
        ///
        /// Un serveur n'en émet que dans un `Retry`, donc jamais ici — mais
        /// §17.2.2 place le champ dans TOUS les `Initial`, et une longueur nulle
        /// s'écrit quand même.
        token: &'a [u8],
    },
    /// Un `Handshake` (§17.2.4).
    Handshake {
        /// L'identifiant que le pair attend.
        destination: ConnectionId,
        /// Le nôtre.
        source: ConnectionId,
    },
    /// Un `1-RTT`, à en-tête court (§17.3).
    ///
    /// **IL NE PEUT ÊTRE QUE LE DERNIER D'UN DATAGRAMME** (§12.2) : il ne porte
    /// pas de longueur, donc rien ne dirait où il s'arrête.
    OneRtt {
        /// L'identifiant que le pair attend. **Et pas le nôtre** : un en-tête
        /// court n'en porte qu'un.
        destination: ConnectionId,
        /// La phase de clé (§17.3.1).
        key_phase: bool,
    },
}

impl Plan<'_> {
    /// Les bits de type de cette forme, sans la longueur du numéro.
    const fn premier_octet(&self) -> u8 {
        match self {
            Self::Initial { .. } => BIT_FORME_LONGUE | BIT_FIXE,
            Self::Handshake { .. } => BIT_FORME_LONGUE | BIT_FIXE | TYPE_HANDSHAKE,
            Self::OneRtt { key_phase, .. } => match key_phase {
                true => BIT_FIXE | BIT_PHASE,
                false => BIT_FIXE,
            },
        }
    }

    /// Ce paquet peut-il être suivi d'un autre dans le même datagramme (§12.2) ?
    ///
    /// Un en-tête court ne porte pas de longueur : rien ne dirait où il
    /// s'arrête, donc il ferme le datagramme.
    #[must_use]
    pub const fn can_be_followed(&self) -> bool {
        !matches!(self, Self::OneRtt { .. })
    }
}

/// Où chaque partie d'un paquet commence, et ce qu'il occupera.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Disposition {
    /// Où commence le numéro de paquet — c'est aussi la taille de l'en-tête.
    numero_a: usize,
    /// Ce que le numéro occupe (§17.1).
    numero_octets: usize,
    /// Ce que le paquet entier occupera.
    total: usize,
}

/// Écrit un paquet protégé dans `out`, et rend ce qu'il occupe.
///
/// `frames` porte les trames déjà composées — c'est l'appelant qui les écrit, et
/// c'est lui qui les BOURRE quand il le faut : §14.1 demande qu'un datagramme
/// portant un `Initial` qui sollicite un acquittement atteigne 1200 octets, et
/// le bourrage est une trame `PADDING`, donc de son ressort.
///
/// # LA CHARGE A UN PLANCHER, ET IL VIENT DE §5.4.2
///
/// L'échantillon de protection d'en-tête se prend seize octets, quatre octets
/// après le début du numéro — **comme si le numéro faisait toujours quatre
/// octets**, puisque le pair qui démasque ne connaît pas encore sa longueur
/// réelle. Il faut donc que le numéro et la charge fassent ensemble au moins
/// quatre octets : « at least 3 bytes of frames […] if the packet number is
/// encoded on a single byte, or 2 bytes for a 2-byte packet number encoding ».
///
/// Sans cette garde, on émettrait un paquet que le pair **MUST** jeter, et la
/// connexion se figerait sans que rien ne l'explique.
///
/// # Errors
///
/// [`Reason::WindowTooSmall`] si `out` ne suffit pas ; [`Reason::SendOverflow`]
/// si la charge est trop courte pour porter un échantillon, si le numéro dépasse
/// ce que §12.3 permet, ou si le paquet dépasse ce qu'un datagramme porte.
pub fn seal_packet(
    out: &mut [u8],
    clefs: &(impl Protection + ?Sized),
    plan: &Plan<'_>,
    number: u64,
    largest_acked: Option<u64>,
    frames: &[u8],
) -> Result<usize, Error> {
    let court = || Error::new(Reason::WindowTooSmall);

    let pose = disposer(plan, number, largest_acked, frames.len())?;
    let paquet = out.get_mut(..pose.total).ok_or_else(court)?;

    // **À PARTIR D'ICI, PLUS AUCUNE GARDE N'EST ATTEIGNABLE**, et c'est
    // `disposer` qui l'a rendu vrai : il a vérifié le numéro, la borne de
    // §5.4.2 et celle d'un datagramme, puis calculé la place exacte. Écrire des
    // `?` ici ouvrirait des branches qu'aucun essai ne pourrait emprunter — et
    // C2 les refuse, parce qu'une garde inatteignable n'est pas une garde :
    // c'est une affirmation non vérifiée. Les `expect` ci-dessous DISENT
    // l'affirmation, au lieu de la taire.

    // 1. L'en-tête, en clair, dans la place que `disposer` lui a réservée.
    ecrire_entete(
        paquet.get_mut(..pose.numero_a).unwrap_or_default(),
        plan,
        pose,
        frames.len(),
    );
    // 2. Le numéro tronqué (§17.1).
    packet_numbers::encode(
        number,
        pose.numero_octets,
        paquet.get_mut(pose.numero_a..).unwrap_or_default(),
    )
    .expect("`disposer` a validé le numéro et réservé sa place");
    // 3. **L'EN-TÊTE ENTIER EST LES DONNÉES ASSOCIÉES** (§5.3 de RFC 9001) : du
    //    premier octet à la fin du numéro. Un en-tête modifié en chemin fait
    //    donc échouer l'authentification, ce qui protège la longueur et les
    //    identifiants autant que la charge.
    let fin_du_numero = pose.numero_a.saturating_add(pose.numero_octets);
    let (aad, corps) = paquet.split_at_mut(fin_du_numero);
    corps[..frames.len()].copy_from_slice(frames);
    clefs
        .seal(number, aad, corps, frames.len())
        .expect("`disposer` a borné la charge à ce qu'un datagramme porte");
    // 4. **ET SEULEMENT MAINTENANT** le masque : il se calcule sur le chiffré.
    clefs
        .protect(paquet, pose.numero_a, pose.numero_octets)
        .expect("`disposer` a garanti l'échantillon de §5.4.2");
    Ok(pose.total)
}

/// Combien d'octets de trames tiennent dans `place`, pour ce plan.
///
/// **C'EST LA QUESTION QUE L'APPELANT POSE AVANT DE COMPOSER**, et non après :
/// la garde d'amplification (§8.1) lui donne un budget, et il doit savoir ce qui
/// rentre dedans. Rend zéro quand rien ne rentre.
///
/// La valeur rendue est SÛRE, non pas exacte au dernier octet : la longueur
/// annoncée d'un en-tête long s'écrit sur un varint dont la taille dépend de ce
/// qu'on y met. On la prend au plus large, et l'on perd donc jusqu'à trois
/// octets. **Perdre trois octets par paquet est sans conséquence ; en promettre
/// trois de trop ferait échouer l'écriture après que l'appelant a composé.**
#[must_use]
pub fn payload_capacity(
    plan: &Plan<'_>,
    number: u64,
    largest_acked: Option<u64>,
    place: usize,
) -> usize {
    let Ok(numero_octets) = packet_numbers::encoded_len(number, largest_acked) else {
        return 0;
    };
    // Quatre octets de varint couvrent 2^30 - 1, bien au-delà de ce qu'un
    // datagramme porte : c'est le pire cas, et il ne se dépasse pas.
    let annonce = match plan {
        Plan::OneRtt { .. } => 0,
        Plan::Initial { .. } | Plan::Handshake { .. } => 4,
    };
    place
        .saturating_sub(entete_fixe(plan))
        .saturating_sub(annonce)
        .saturating_sub(numero_octets)
        .saturating_sub(TAG_OCTETS)
}

/// Ce que l'en-tête occupe SANS son champ de longueur.
fn entete_fixe(plan: &Plan<'_>) -> usize {
    match plan {
        Plan::OneRtt { destination, .. } => 1_usize.saturating_add(destination.len()),
        Plan::Initial {
            destination,
            source,
            token,
        } => {
            let jeton = varints::encoded_len(u64::try_from(token.len()).unwrap_or(u64::MAX))
                .unwrap_or(usize::MAX);
            entete_long(*destination, *source)
                .saturating_add(jeton)
                .saturating_add(token.len())
        }
        Plan::Handshake {
            destination,
            source,
        } => entete_long(*destination, *source),
    }
}

/// Le tronc commun d'un en-tête long : premier octet, version, deux
/// identifiants précédés chacun de sa longueur (§17.2).
fn entete_long(destination: ConnectionId, source: ConnectionId) -> usize {
    1_usize
        .saturating_add(VERSION_OCTETS)
        .saturating_add(1)
        .saturating_add(destination.len())
        .saturating_add(1)
        .saturating_add(source.len())
}

/// La valeur du champ `Length` d'un en-tête long (§17.2).
///
/// **ELLE COUVRE LE NUMÉRO, LA CHARGE ET LE TAG** — tout ce qui suit le champ
/// lui-même. C'est elle qui permet de coaliser plusieurs paquets dans un
/// datagramme (§12.2) : sans elle, on ne saurait pas où le paquet s'arrête.
fn longueur_annoncee(numero_octets: usize, charge: usize) -> u64 {
    u64::try_from(
        numero_octets
            .saturating_add(charge)
            .saturating_add(TAG_OCTETS),
    )
    .unwrap_or(u64::MAX)
}

/// Calcule où tout se place, ou dit pourquoi c'est impossible.
fn disposer(
    plan: &Plan<'_>,
    number: u64,
    largest_acked: Option<u64>,
    charge: usize,
) -> Result<Disposition, Error> {
    let refus = || Error::new(Reason::SendOverflow);
    // §17.1 : la longueur du numéro se DÉDUIT de ce qui n'est pas encore
    // acquitté, et n'est pas un choix. La prendre plus courte rendrait le
    // numéro irrécupérable pour le pair.
    let numero_octets = packet_numbers::encoded_len(number, largest_acked).map_err(|_| refus())?;
    // §5.4.2 : de quoi échantillonner, ou rien. L'échantillon commence quatre
    // octets après le numéro et en occupe seize ; il faut donc que le numéro, la
    // charge et le tag atteignent ensemble ces vingt octets.
    //
    // **ON L'ÉCRIT AINSI ET NON « charge >= 3 »**, bien que les deux se valent :
    // l'égalité ne tient que parce que le tag fait justement seize octets, ce
    // qui est vrai des suites de §5.4.2 et de nulle part ailleurs. La forme
    // longue dit d'où vient le nombre ; la forme courte le ferait oublier.
    if numero_octets
        .saturating_add(charge)
        .saturating_add(TAG_OCTETS)
        < ECHANTILLON_APRES.saturating_add(ECHANTILLON_OCTETS)
    {
        return Err(refus());
    }
    // **ET DE QUOI TENIR DANS UN DATAGRAMME.** `ams-quic-crypto` borne ce qu'il
    // chiffre à ce qu'un datagramme UDP peut porter ; le vérifier ICI rend le
    // chiffrement infaillible plus bas, au lieu d'y laisser une branche que nul
    // essai n'atteindrait.
    if charge > PACKET_OCTETS_MAX {
        return Err(refus());
    }
    let annonce = match plan {
        Plan::OneRtt { .. } => 0,
        // La longueur annoncée vaut au plus `PACKET_OCTETS_MAX + 20`, donc son
        // varint tient : `encoded_len` ne refuse qu'au-delà de 2^62.
        Plan::Initial { .. } | Plan::Handshake { .. } => {
            varints::encoded_len(longueur_annoncee(numero_octets, charge))
                .expect("une longueur bornée par un datagramme s'écrit toujours")
        }
    };
    let numero_a = entete_fixe(plan).saturating_add(annonce);
    let total = numero_a
        .saturating_add(numero_octets)
        .saturating_add(charge)
        .saturating_add(TAG_OCTETS);
    // **PAS DE SECONDE VÉRIFICATION DE §5.4.2 ICI**, et ce n'est pas un oubli.
    // Elle dirait « l'échantillon tient dans le paquet fini », c'est-à-dire
    // `numero_a + 4 + 16 <= total` — or `total` vaut `numero_a + numero_octets
    // + charge + 16`, donc c'est mot pour mot la condition déjà posée plus
    // haut. Une garde qui répète une garde n'ajoute rien : elle ajoute une
    // branche que rien ne peut emprunter.
    Ok(Disposition {
        numero_a,
        numero_octets,
        total,
    })
}

/// Écrit l'en-tête en clair, du premier octet à la fin du champ de longueur.
///
/// **`entete` FAIT EXACTEMENT LA TAILLE QU'IL FAUT**, parce que `disposer` l'a
/// calculée. Rien ici ne peut donc manquer de place, et rien ici ne rend de
/// `Result` : les découpes sont des index, qui paniqueraient si l'invariant
/// était rompu — ce qu'un essai verrait, contrairement à une erreur qu'on
/// remonterait sans jamais l'atteindre.
fn ecrire_entete(entete: &mut [u8], plan: &Plan<'_>, pose: Disposition, charge: usize) {
    // §17.2 et §17.3 : les deux bits de poids faible portent la longueur du
    // numéro, MOINS UN. Un numéro d'un octet s'annonce par zéro.
    let longueur = u8::try_from(pose.numero_octets.saturating_sub(1))
        .expect("§17.1 borne un numéro à quatre octets");
    entete[0] = plan.premier_octet() | longueur;
    let mut rang = 1_usize;

    match plan {
        Plan::OneRtt { destination, .. } => ecrire(entete, &mut rang, destination.as_bytes()),
        Plan::Initial {
            destination,
            source,
            token,
        } => {
            ecrire(entete, &mut rang, &VERSION_1.to_be_bytes());
            ecrire_identifiant(entete, &mut rang, *destination);
            ecrire_identifiant(entete, &mut rang, *source);
            ecrire_varint(
                entete,
                &mut rang,
                u64::try_from(token.len()).expect("une longueur tient dans un u64"),
            );
            ecrire(entete, &mut rang, token);
            ecrire_varint(
                entete,
                &mut rang,
                longueur_annoncee(pose.numero_octets, charge),
            );
        }
        Plan::Handshake {
            destination,
            source,
        } => {
            ecrire(entete, &mut rang, &VERSION_1.to_be_bytes());
            ecrire_identifiant(entete, &mut rang, *destination);
            ecrire_identifiant(entete, &mut rang, *source);
            ecrire_varint(
                entete,
                &mut rang,
                longueur_annoncee(pose.numero_octets, charge),
            );
        }
    }
}

/// Écrit un identifiant précédé de sa longueur (§17.2).
fn ecrire_identifiant(entete: &mut [u8], rang: &mut usize, identifiant: ConnectionId) {
    let longueur =
        u8::try_from(identifiant.len()).expect("§17.2 borne un identifiant à vingt octets");
    ecrire(entete, rang, &[longueur]);
    ecrire(entete, rang, identifiant.as_bytes());
}

/// Écrit un entier de longueur variable (§16).
fn ecrire_varint(entete: &mut [u8], rang: &mut usize, valeur: u64) {
    let ecrits = varints::encode(valeur, &mut entete[*rang..])
        .expect("`disposer` a réservé la place de ce varint");
    *rang = rang.saturating_add(ecrits);
}

/// Recopie ces octets et avance le rang.
fn ecrire(entete: &mut [u8], rang: &mut usize, octets: &[u8]) {
    let fin = rang.saturating_add(octets.len());
    entete[*rang..fin].copy_from_slice(octets);
    *rang = fin;
}

#[cfg(test)]
mod tests;
