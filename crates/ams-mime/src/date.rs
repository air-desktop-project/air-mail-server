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
