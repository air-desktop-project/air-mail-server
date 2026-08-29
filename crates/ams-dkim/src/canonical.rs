//! La canonicalisation (RFC 6376 §3.4) : **la définition exacte de ce qui est
//! signé**.
//!
//! # Pourquoi deux algorithmes, et ce que chacun coûte
//!
//! Une signature couvre des octets. Or un message ne traverse pas internet
//! intact : un relais replie une ligne trop longue, un autre remplace une
//! tabulation par des espaces, un troisième ajoute ou retire une ligne vide à la
//! fin. `simple` ne pardonne rien de tout cela — elle signe les octets tels
//! quels — et `relaxed` pardonne exactement ces trois-là, en normalisant les
//! blancs et le pliage avant de signer.
//!
//! **`relaxed` n'est pas « moins sûr » : elle signe autre chose.** Ce qu'elle
//! laisse changer, elle le laisse changer à quiconque, et c'est un choix qu'on
//! fait en connaissance de cause — pas une tolérance qui traîne.
//!
//! # La canonicalisation n'est pas de la mise en forme
//!
//! Une erreur d'un octet ici ne se voit nulle part : elle rend simplement toutes
//! les signatures invalides, ou — bien pire — en valide qui ne devraient pas
//! l'être. C'est pourquoi les épreuves de ce module sont les **vecteurs de la
//! RFC elle-même** (§3.4.5 et §3.4.6), et pas des exemples inventés ici.

use crate::Error;

/// Comment canonicaliser.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Canon {
    /// Les octets tels quels (§3.4.1, §3.4.3).
    ///
    /// C'est le DÉFAUT de la RFC, et c'est pourquoi il est ici aussi : un
    /// message qui n'écrit pas `c=` est signé ainsi, et se tromper de défaut
    /// ferait échouer toutes ces signatures-là.
    #[default]
    Simple,
    /// Les blancs et le pliage normalisés (§3.4.2, §3.4.4).
    Relaxed,
}

/// Le couple d'algorithmes d'une signature (`c=`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Canonicalization {
    /// Pour les en-têtes.
    pub header: Canon,
    /// Pour le corps.
    pub body: Canon,
}

impl Canonicalization {
    /// Lit un `c=` : `header` ou `header/body`.
    ///
    /// **Le corps absent vaut `simple`, pas la valeur des en-têtes** (§3.5) :
    /// `c=relaxed` veut dire `relaxed/simple`. Le lire autrement ferait
    /// condenser un corps différent de celui que le signataire a condensé.
    ///
    /// # Errors
    ///
    /// [`Error::UnsupportedCanonicalization`] si un des deux noms est inconnu.
    pub fn parse(valeur: &[u8]) -> Result<Self, Error> {
        let (tete, corps) = match valeur.iter().position(|octet| *octet == b'/') {
            Some(rang) => {
                let (avant, apres) = valeur.split_at(rang);
                (avant, apres.get(1..).unwrap_or_default())
            }
            None => (valeur, &b"simple"[..]),
        };
        Ok(Self {
            header: Canon::parse(tete)?,
            body: Canon::parse(corps)?,
        })
    }
}

impl Canon {
    /// Lit un nom d'algorithme.
    ///
    /// # Errors
    ///
    /// [`Error::UnsupportedCanonicalization`] si le nom est inconnu. **On ne se
    /// rabat pas sur `simple`** : un algorithme qu'on ne connaît pas est un
    /// message qu'on ne sait pas vérifier, et le vérifier autrement rendrait un
    /// verdict sur des octets que personne n'a signés.
    pub fn parse(nom: &[u8]) -> Result<Self, Error> {
        // Les noms sont insensibles à la casse : ce sont des `hyphenated-word`
        // de la RFC 6376 §3.5, comparés sans casse comme le reste des étiquettes.
        if nom.eq_ignore_ascii_case(b"simple") {
            return Ok(Self::Simple);
        }
        if nom.eq_ignore_ascii_case(b"relaxed") {
            return Ok(Self::Relaxed);
        }
        Err(Error::UnsupportedCanonicalization)
    }

    /// Le nom, tel qu'il s'écrit dans un `c=`.
    #[must_use]
    pub fn name(self) -> &'static [u8] {
        match self {
            Self::Simple => b"simple",
            Self::Relaxed => b"relaxed",
        }
    }
}

/// Ce qui termine un champ canonicalisé.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Trailer {
    /// Le `CRLF` du champ, comme dans le message.
    Crlf,
    /// Rien.
    ///
    /// **C'est le cas du `DKIM-Signature` lui-même** (§3.7) : il entre dans son
    /// propre condensat sans son `CRLF` final, parce qu'au moment où le
    /// signataire l'a calculé, ce `CRLF` n'était pas encore écrit.
    Aucun,
}

/// Canonicalise un champ d'en-tête, et rend les octets à `sortie`.
///
/// `name` est le nom sans le deux-points ; `value` est la valeur brute, **encore
/// pliée** — c'est-à-dire exactement ce que rend `ams_mime::Field`.
///
/// # Ce que `name` doit être, et pourquoi rien ne le vérifie ici
///
/// Un nom de champ, tel qu'un message en porte : `%d33-57 / %d59-126` (RFC 5322
/// §3.6.8), c'est-à-dire ni blanc, ni deux-points, ni fin de ligne. Ce n'est pas
/// une supposition en l'air — le bloc d'en-tête a été validé avant d'arriver
/// ici, et c'est LUI qui garantit cette forme. Ajouter une garde ici la
/// vérifierait une seconde fois sans que rien ne puisse l'emprunter.
///
/// Ce que la fonction rend est **une entrée de condensat**, jamais un en-tête
/// qu'on émet : un nom absurde donne un condensat absurde, donc une vérification
/// qui échoue. C'est la bonne issue.
pub fn canonicalize_header(
    canon: Canon,
    name: &[u8],
    value: &[u8],
    fin: Trailer,
    sortie: &mut impl FnMut(&[u8]),
) {
    canonicalize_header_parts(canon, name, &[value], fin, sortie);
}

/// Canonicalise un champ dont la valeur est donnée **en morceaux**.
///
/// # Pourquoi des morceaux, alors qu'un champ tient en mémoire
///
/// Le `DKIM-Signature` entre dans son propre condensat **avec la valeur de son
/// `b=` retirée** (§3.7). Ce retrait laisse un trou au milieu de la valeur, et
/// la canonicalisation `relaxed` a une mémoire d'un octet à l'autre — un blanc
/// en attente traverse la coupure. Recoller les deux bouts dans un tampon
/// obligerait à allouer ; les donner tels quels ne coûte rien.
pub fn canonicalize_header_parts(
    canon: Canon,
    name: &[u8],
    parts: &[&[u8]],
    fin: Trailer,
    sortie: &mut impl FnMut(&[u8]),
) {
    match canon {
        // §3.4.1 : rien ne change. Le champ est rendu tel qu'il figure dans le
        // message, deux-points et pliage compris.
        Canon::Simple => {
            sortie(name);
            sortie(b":");
            for morceau in parts {
                sortie(morceau);
            }
        }
        Canon::Relaxed => relaxed_header(name, parts, sortie),
    }
    if fin == Trailer::Crlf {
        sortie(b"\r\n");
    }
}

/// §3.4.2, dans l'ordre où la RFC l'écrit.
fn relaxed_header(name: &[u8], parts: &[&[u8]], sortie: &mut impl FnMut(&[u8])) {
    // 1. Le nom en minuscules, et 5. sans le blanc qui le sépare du
    //    deux-points — « B<SP>:<SP>Y » se canonicalise en « b:Y », et c'est le
    //    vecteur de la RFC qui le dit. `trim_ascii` porte ce retrait dans la
    //    bibliothèque standard plutôt que dans une boucle à nous.
    //
    //    On l'écrit octet par octet : la crate n'alloue pas, et un nom de champ
    //    ne dépasse pas quelques dizaines d'octets.
    for octet in name.trim_ascii() {
        sortie(&[octet.to_ascii_lowercase()]);
    }
    // 5. Le deux-points, lui, reste.
    sortie(b":");

    // 2, 3, 4 : déplier, réduire les suites de blancs à une seule espace, et
    // retirer ceux de la fin. Le pliage disparaît DANS la réduction — un `CRLF`
    // de pliage est toujours suivi d'un blanc, et le tout compte pour un.
    let mut blanc_en_attente = false;
    let mut quelque_chose = false;
    for octet in parts.iter().copied().flatten() {
        if est_blanc_ou_pliage(*octet) {
            // On ne l'écrit pas tout de suite : s'il n'y a plus rien après, il
            // ne s'écrira jamais.
            blanc_en_attente = quelque_chose;
            continue;
        }
        if blanc_en_attente {
            sortie(b" ");
            blanc_en_attente = false;
        }
        sortie(core::slice::from_ref(octet));
        quelque_chose = true;
    }
}

/// Un blanc, ou l'un des deux octets d'un pliage.
///
/// Les traiter ensemble est exactement ce que dit §3.4.2 : « les blancs incluent
/// ceux qui précèdent et suivent une limite de pliage ». Un `CRLF` seul ne peut
/// pas figurer dans une valeur — la grammaire de la RFC 5322 veut qu'il soit
/// suivi d'un blanc — et le confondre avec un blanc ne perd donc rien.
fn est_blanc_ou_pliage(octet: u8) -> bool {
    matches!(octet, b' ' | b'\t' | b'\r' | b'\n')
}

#[cfg(test)]
mod tests;
