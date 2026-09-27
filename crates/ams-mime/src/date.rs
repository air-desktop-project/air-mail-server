//! La date d'un message (RFC 5322 §3.3), écrite depuis un nombre de secondes.
//!
//! # Pourquoi cette crate n'a pas d'horloge, et écrit quand même des dates
//!
//! C1 : lire l'heure est une entrée-sortie, et elle appartient à l'étage 3.
//! L'appelant apporte donc un nombre de secondes depuis l'époque, et c'est tout
//! ce qu'il faut : la conversion en date civile est de l'arithmétique, et se
//! prouve.
//!
//! # LE FUSEAU EST `+0000`, ET CE N'EST PAS UNE PARESSE
//!
//! Écrire une heure locale demanderait une base de fuseaux — un fichier qui
//! change plusieurs fois par an, qu'il faudrait lire, donc une entrée-sortie de
//! plus — et la seule chose qu'elle apporterait est de savoir dans quel bureau
//! se trouvait la machine. La RFC 5322 §3.3 admet `+0000` sans réserve, et un
//! horodatage universel se compare sans rien connaître de personne.

use crate::Error;

/// La longueur d'une date : `Tue, 29 Aug 2026 09:08:31 +0000`.
pub const DATE_MAX: usize = 40;

/// Lit le JOUR d'une date RFC 5322 : le nombre de jours depuis l'époque.
///
/// # ON NE LIT QUE LE JOUR, ET C'EST CE QU'ON DEMANDE
///
/// RFC 9051 §6.4.4 : `SENTBEFORE`, `SENTON` et `SENTSINCE` comparent le champ
/// `Date:` « disregarding time and timezone ». L'heure ne sert donc à rien, et
/// le fuseau non plus — ce qui écarte du même coup toute la zoologie des zones
/// obsolètes de RFC 5322 §4.3 (`EST`, `PDT`, une lettre isolée…), qu'il faudrait
/// sinon interpréter pour un résultat qu'on jetterait.
///
/// # CE QU'ON ACCEPTE
///
/// `[Jour, ]JJ Mois AAAA` — le nom du jour est facultatif (§3.3), le jour tient
/// sur un ou deux chiffres, et l'année sur quatre. Les années à deux chiffres de
/// §4.3 sont refusées : les interpréter demanderait de choisir un siècle, et se
/// tromper de cent ans vaut moins que de ne rien dire.
///
/// Ce qui suit la date — l'heure, le fuseau, un commentaire — est ignoré.
#[must_use]
pub fn read_day(valeur: &[u8]) -> Option<u64> {
    // LE NUMÉRO EST DANS LA TABLE, et non déduit du rang : le déduire
    // demanderait de convertir un `usize` en `u64`, donc d'écrire une garde
    // contre un débordement que douze entrées excluent — et qu'aucun test ne
    // pourrait donc atteindre.
    const MOIS: [(&[u8], u64); 12] = [
        (b"Jan", 1),
        (b"Feb", 2),
        (b"Mar", 3),
        (b"Apr", 4),
        (b"May", 5),
        (b"Jun", 6),
        (b"Jul", 7),
        (b"Aug", 8),
        (b"Sep", 9),
        (b"Oct", 10),
        (b"Nov", 11),
        (b"Dec", 12),
    ];
    let mut mots = mots(valeur);
    let jour = lire_un_nombre(mots.next()?)?;
    let nom = mots.next()?;
    let annee = lire_un_nombre(mots.next()?)?;
    let mois = MOIS
        .iter()
        .find(|(connu, _)| nom.eq_ignore_ascii_case(connu))
        .map(|(_, numero)| *numero)?;
    // UN JOUR HORS DU MOIS N'EST PAS UNE DATE. `31 Feb` se lirait sinon comme
    // le 3 mars, et le message répondrait à une recherche portant sur un jour
    // qu'il ne nomme pas.
    if jour == 0 || jour > jours_du_mois(annee, mois) || !(1970..=9999).contains(&annee) {
        return None;
    }
    // UN NOMBRE DE JOURS, PAS DE SECONDES : c'est un JOUR qu'on compare, et le
    // rendre en secondes obligerait chaque appelant à diviser — donc à savoir
    // que l'heure ne compte pas, alors que c'est justement ce qu'on lui épargne.
    Some(jours_depuis_l_epoque(annee, mois, jour))
}

/// Les mots d'une date, le nom du jour écarté.
fn mots(valeur: &[u8]) -> impl Iterator<Item = &[u8]> {
    // Le nom du jour, s'il est là, se termine par une virgule.
    let reste = valeur.trim_ascii_start();
    let reste = match reste.iter().position(|octet| *octet == b',') {
        Some(rang) => reste.get(rang.saturating_add(1)..).unwrap_or_default(),
        None => reste,
    };
    reste
        .split(|octet| matches!(*octet, b' ' | b'\t' | b'\r' | b'\n'))
        .filter(|mot| !mot.is_empty())
}

/// Ce que dit un champ `Date:` : l'instant, et le fuseau de qui l'a écrit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DateTime {
    /// L'instant, en secondes depuis l'époque — en temps universel.
    pub epoch_seconds: u64,
    /// Le décalage de l'expéditeur, en minutes à l'est de Greenwich.
    pub offset_minutes: i16,
}

impl DateTime {
    /// Le fuseau tel que la RFC 5322 l'écrit : `+0200`, `-0500`.
    #[must_use]
    pub fn zone(&self) -> [u8; 5] {
        let signe = if self.offset_minutes < 0 { b'-' } else { b'+' };
        let minutes = self.offset_minutes.unsigned_abs();
        let chiffre = |valeur: u16| b'0'.wrapping_add(u8::try_from(valeur % 10).unwrap_or(0));
        [
            signe,
            chiffre(minutes / 600),
            chiffre(minutes / 60),
            chiffre((minutes % 60) / 10),
            chiffre(minutes % 60),
        ]
    }
}

/// Lit une date RFC 5322 entière : le jour, l'heure et le fuseau.
///
/// # POURQUOI UNE SECONDE LECTURE, ET NON [`read_day`] ÉLARGI
///
/// `read_day` sert la recherche, qui compare des JOURS et ignore le fuseau
/// (§6.4.4 de RFC 9051) : lui faire lire l'heure la rendrait plus exigeante
/// qu'elle ne doit l'être, et un message sans heure lisible cesserait de
/// répondre à `SENTON`. Celle-ci sert l'affichage, qui veut l'instant exact.
/// Elle part du même jour, lu par le même code : les deux ne peuvent pas
/// diverger sur la date.
///
/// # LE FUSEAU EST EXIGÉ
///
/// §3.3 le rend obligatoire, et sans lui l'heure n'est pas un instant : deviner
/// `+0000` placerait un message écrit à Paris une ou deux heures à côté. Les
/// zones obsolètes de §4.3 se lisent — `UT`, `GMT` et les huit nord-américaines
/// —, et une lettre militaire vaut `-0000` comme §4.3 le demande : elles ont été
/// si souvent écrites de travers que leur sens est perdu.
///
/// Ce qui suit le fuseau — typiquement un commentaire `(CEST)` — est ignoré.
#[must_use]
pub fn read_date_time(valeur: &[u8]) -> Option<DateTime> {
    let jours = read_day(valeur)?;
    let mut suite = mots(valeur).skip(3);
    let (heures, minutes, secondes) = lire_l_heure(suite.next()?)?;
    let decalage = lire_le_fuseau(suite.next()?)?;
    let locale = jours
        .saturating_mul(86_400)
        .saturating_add(heures.saturating_mul(3_600))
        .saturating_add(minutes.saturating_mul(60))
        .saturating_add(secondes);
    // L'HEURE LOCALE MOINS LE DÉCALAGE : `10:00 +0200`, c'est `08:00` en temps
    // universel. Avant l'époque, il n'y a pas de nombre à rendre.
    let ecart = u64::from(decalage.unsigned_abs()).saturating_mul(60);
    let universelle = if decalage < 0 {
        locale.saturating_add(ecart)
    } else {
        locale.checked_sub(ecart)?
    };
    Some(DateTime {
        epoch_seconds: universelle,
        offset_minutes: decalage,
    })
}

/// `hh:mm` ou `hh:mm:ss` — les secondes sont facultatives (§3.3), et la
/// soixantième admise pour une seconde intercalaire.
fn lire_l_heure(mot: &[u8]) -> Option<(u64, u64, u64)> {
    let mut morceaux = mot.split(|octet| *octet == b':');
    let heures = lire_un_nombre(morceaux.next().unwrap_or_default())?;
    let minutes = lire_un_nombre(morceaux.next()?)?;
    let secondes = match morceaux.next() {
        Some(morceau) => lire_un_nombre(morceau)?,
        None => 0,
    };
    if morceaux.next().is_some() || heures > 23 || minutes > 59 || secondes > 60 {
        return None;
    }
    Some((heures, minutes, secondes))
}

/// Le décalage d'un fuseau, en minutes à l'est.
fn lire_le_fuseau(mot: &[u8]) -> Option<i16> {
    // §4.3 : les zones nommées, et la seule dont le sens n'a pas été perdu.
    const NOMMEES: [(&[u8], i16); 10] = [
        (b"UT", 0),
        (b"GMT", 0),
        (b"EST", -300),
        (b"EDT", -240),
        (b"CST", -360),
        (b"CDT", -300),
        (b"MST", -420),
        (b"MDT", -360),
        (b"PST", -480),
        (b"PDT", -420),
    ];
    if let Some((_, decalage)) = NOMMEES
        .iter()
        .find(|(nom, _)| mot.eq_ignore_ascii_case(nom))
    {
        return Some(*decalage);
    }
    match mot {
        // Une lettre militaire : `-0000`, c'est-à-dire « on ne sait pas ».
        [lettre] if lettre.is_ascii_alphabetic() => Some(0),
        [signe @ (b'+' | b'-'), chiffres @ ..] if chiffres.len() == 4 => {
            let heures = lire_un_nombre(chiffres.get(..2).unwrap_or_default())?;
            let minutes = lire_un_nombre(chiffres.get(2..).unwrap_or_default())?;
            if minutes > 59 {
                return None;
            }
            // Quatre chiffres tiennent toujours : 99 × 60 + 59 < 32 767.
            let total = i16::try_from(heures.saturating_mul(60).saturating_add(minutes))
                .unwrap_or(i16::MAX);
            Some(if *signe == b'-' {
                total.saturating_neg()
            } else {
                total
            })
        }
        _ => None,
    }
}

/// Combien de jours ce mois-là porte.
fn jours_du_mois(annee: u64, mois: u64) -> u64 {
    const LONGUEURS: [u64; 12] = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    let ordinaire = LONGUEURS
        .get(usize::try_from(mois.saturating_sub(1)).unwrap_or(0))
        .copied()
        .unwrap_or(31);
    let bissextile =
        annee.is_multiple_of(4) && (!annee.is_multiple_of(100) || annee.is_multiple_of(400));
    match mois == 2 && bissextile {
        true => 29,
        false => ordinaire,
    }
}

/// Lit un nombre décimal, sans signe et sans espace.
fn lire_un_nombre(mot: &[u8]) -> Option<u64> {
    if mot.is_empty() || mot.len() > 4 || !mot.iter().all(u8::is_ascii_digit) {
        return None;
    }
    let mut valeur = 0_u64;
    for octet in mot {
        valeur = valeur
            .saturating_mul(10)
            .saturating_add(u64::from(octet.wrapping_sub(b'0')));
    }
    Some(valeur)
}

/// Combien de jours séparent cette date civile de l'époque.
///
/// L'algorithme est celui de Howard Hinnant, le même que [`civil`] à l'envers.
fn jours_depuis_l_epoque(annee: u64, mois: u64, jour: u64) -> u64 {
    let annee = if mois <= 2 {
        annee.saturating_sub(1)
    } else {
        annee
    };
    let ere = annee / 400;
    let an_de_l_ere = annee.saturating_sub(ere.saturating_mul(400));
    let mois_decale = if mois > 2 {
        mois.saturating_sub(3)
    } else {
        mois.saturating_add(9)
    };
    let jour_de_l_an = (mois_decale.saturating_mul(153).saturating_add(2) / 5)
        .saturating_add(jour.saturating_sub(1));
    let jour_de_l_ere = an_de_l_ere
        .saturating_mul(365)
        .saturating_add(an_de_l_ere / 4)
        .saturating_sub(an_de_l_ere / 100)
        .saturating_add(jour_de_l_an);
    ere.saturating_mul(146_097)
        .saturating_add(jour_de_l_ere)
        .saturating_sub(719_468)
}

/// La longueur d'un horodatage RFC 3339 : `2026-08-29T09:08:31Z`.
pub const RFC3339_MAX: usize = 24;

/// Écrit un horodatage RFC 3339 depuis un nombre de secondes depuis l'époque.
///
/// # POURQUOI ICI, ET NON DANS LA CRATE QUI EN A BESOIN
///
/// §4.1 de RFC 8460 exige cette forme dans un rapport TLSRPT. La conversion en
/// date civile, elle, est déjà écrite ici — et **deux crates qui compteraient
/// les jours différemment finiraient par ne pas dater la même chose de la même
/// façon**. Un seul calendrier dans ce dépôt, et c'est celui-là.
///
/// Le fuseau est `Z` pour la même raison qu'il est `+0000` plus haut : écrire
/// une heure locale demanderait une base de fuseaux, et n'apprendrait que dans
/// quel bureau se trouve la machine.
///
/// # Errors
///
/// [`Error::BufferTooSmall`] si `sortie` fait moins de [`RFC3339_MAX`].
pub fn write_rfc3339(epoch_seconds: u64, sortie: &mut [u8]) -> Result<&[u8], Error> {
    let jours = epoch_seconds / 86_400;
    let dans_le_jour = epoch_seconds % 86_400;
    let (annee, mois, jour) = civil(jours);

    let mut ecrits = nombre(sortie, 0, annee, 4)?;
    ecrits = pousser(sortie, ecrits, b"-")?;
    ecrits = nombre(sortie, ecrits, mois, 2)?;
    ecrits = pousser(sortie, ecrits, b"-")?;
    ecrits = nombre(sortie, ecrits, jour, 2)?;
    ecrits = pousser(sortie, ecrits, b"T")?;
    ecrits = nombre(sortie, ecrits, dans_le_jour / 3_600, 2)?;
    ecrits = pousser(sortie, ecrits, b":")?;
    ecrits = nombre(sortie, ecrits, (dans_le_jour / 60) % 60, 2)?;
    ecrits = pousser(sortie, ecrits, b":")?;
    ecrits = nombre(sortie, ecrits, dans_le_jour % 60, 2)?;
    ecrits = pousser(sortie, ecrits, b"Z")?;
    sortie.get(..ecrits).ok_or(Error::BufferTooSmall)
}

/// Écrit une date RFC 5322 depuis un nombre de secondes depuis l'époque.
///
/// # Errors
///
/// [`Error::BufferTooSmall`] si `sortie` ne suffit pas.
pub fn write_date(epoch_seconds: u64, sortie: &mut [u8]) -> Result<&[u8], Error> {
    const JOURS: [&[u8]; 7] = [b"Thu", b"Fri", b"Sat", b"Sun", b"Mon", b"Tue", b"Wed"];
    const MOIS: [&[u8]; 12] = [
        b"Jan", b"Feb", b"Mar", b"Apr", b"May", b"Jun", b"Jul", b"Aug", b"Sep", b"Oct", b"Nov",
        b"Dec",
    ];

    let jours = epoch_seconds / 86_400;
    let dans_le_jour = epoch_seconds % 86_400;
    let (annee, mois, jour) = civil(jours);

    let mut ecrits = 0_usize;
    // 1970-01-01 était un jeudi, et c'est de là que part la table.
    let semaine = usize::try_from(jours % 7).unwrap_or(0);
    ecrits = pousser(
        sortie,
        ecrits,
        JOURS.get(semaine).copied().unwrap_or(b"Thu"),
    )?;
    ecrits = pousser(sortie, ecrits, b", ")?;
    ecrits = nombre(sortie, ecrits, jour, 2)?;
    ecrits = pousser(sortie, ecrits, b" ")?;
    let rang = usize::try_from(mois.saturating_sub(1)).unwrap_or(0);
    ecrits = pousser(sortie, ecrits, MOIS.get(rang).copied().unwrap_or(b"Jan"))?;
    ecrits = pousser(sortie, ecrits, b" ")?;
    ecrits = nombre(sortie, ecrits, annee, 4)?;
    ecrits = pousser(sortie, ecrits, b" ")?;
    ecrits = nombre(sortie, ecrits, dans_le_jour / 3_600, 2)?;
    ecrits = pousser(sortie, ecrits, b":")?;
    ecrits = nombre(sortie, ecrits, (dans_le_jour / 60) % 60, 2)?;
    ecrits = pousser(sortie, ecrits, b":")?;
    ecrits = nombre(sortie, ecrits, dans_le_jour % 60, 2)?;
    ecrits = pousser(sortie, ecrits, b" +0000")?;
    sortie.get(..ecrits).ok_or(Error::BufferTooSmall)
}

/// La date civile d'un nombre de jours depuis l'époque.
///
/// # L'algorithme est celui de Howard Hinnant, et il est exact
///
/// Il déplace l'origine au 1er mars de l'an 0 — ce qui met le jour
/// bissextile **à la fin** de l'année, où il ne décale plus rien — puis compte
/// par ères de quatre cents ans, la période exacte du calendrier grégorien.
/// Aucune table, aucune boucle, aucun cas particulier : c'est ce qui le rend
/// vérifiable.
///
/// Tout est en arithmétique SATURANTE. Les valeurs sont bornées par
/// construction — un jour de l'ère tient sous 146 097 — mais l'écrire ainsi
/// refuse l'enveloppement silencieux sans ouvrir la moindre branche : une
/// saturation n'est pas un chemin de plus à couvrir, contrairement à un
/// `checked_*` dont personne ne pourrait emprunter le `None`.
fn civil(jours: u64) -> (u64, u64, u64) {
    // Le 1er mars de l'an 0 précède l'époque de 719 468 jours.
    let z = jours.saturating_add(719_468);
    let ere = z / 146_097;
    let jour_de_l_ere = z % 146_097;
    let an_de_l_ere = jour_de_l_ere
        .saturating_sub(jour_de_l_ere / 1_460)
        .saturating_add(jour_de_l_ere / 36_524)
        .saturating_sub(jour_de_l_ere / 146_096)
        / 365;
    let annee = an_de_l_ere.saturating_add(ere.saturating_mul(400));
    let jour_de_l_an = jour_de_l_ere.saturating_sub(
        an_de_l_ere
            .saturating_mul(365)
            .saturating_add(an_de_l_ere / 4)
            .saturating_sub(an_de_l_ere / 100),
    );
    let mois_decale = jour_de_l_an.saturating_mul(5).saturating_add(2) / 153;
    let jour = jour_de_l_an
        .saturating_sub(mois_decale.saturating_mul(153).saturating_add(2) / 5)
        .saturating_add(1);
    // Mars vaut zéro dans ce décalage : janvier et février appartiennent à
    // l'année suivante.
    let (mois, annee) = if mois_decale < 10 {
        (mois_decale.saturating_add(3), annee)
    } else {
        (mois_decale.saturating_sub(9), annee.saturating_add(1))
    };
    (annee, mois, jour)
}

/// Écrit un nombre décimal sur `largeur` chiffres au moins.
fn nombre(sortie: &mut [u8], ecrits: usize, valeur: u64, largeur: usize) -> Result<usize, Error> {
    // Vingt chiffres majorent tout `u64` ; la boucle les parcourt tous, ce qui
    // évite une borne, donc une garde qu'aucun appel ne peut faire céder.
    let mut chiffres = [b'0'; 20];
    let mut reste = valeur;
    let mut significatifs = largeur.max(1);
    for (rang, place) in chiffres.iter_mut().rev().enumerate() {
        *place = b'0'.wrapping_add(u8::try_from(reste % 10).unwrap_or_default());
        reste /= 10;
        if reste != 0 {
            significatifs = significatifs.max(rang.saturating_add(2));
        }
    }
    let debut = chiffres.len().saturating_sub(significatifs);
    pousser(sortie, ecrits, chiffres.get(debut..).unwrap_or_default())
}

/// Recopie `morceau`, et rend le nouveau compte.
fn pousser(sortie: &mut [u8], ecrits: usize, morceau: &[u8]) -> Result<usize, Error> {
    let fin = ecrits.saturating_add(morceau.len());
    let place = sortie.get_mut(ecrits..fin).ok_or(Error::BufferTooSmall)?;
    place.copy_from_slice(morceau);
    Ok(fin)
}

#[cfg(test)]
mod tests;
