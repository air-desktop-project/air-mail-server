//! Les destinations de rapport, `rua=` et `ruf=` (RFC 7489 §6.2).
//!
//! # Ce que dit une destination, et ce qu'elle ne dit pas
//!
//! Une valeur `rua=` est une liste d'URI séparées par des virgules, chacune
//! pouvant porter une taille maximale : `mailto:d@ex.com!10m` demande de ne pas
//! envoyer plus de dix mébioctets d'un coup. La virgule et le point
//! d'exclamation ayant un sens ici, la RFC exige qu'ils soient **encodés en
//! pourcent** partout ailleurs — c'est ce qui permet de découper avant de
//! décoder, et non l'inverse.
//!
//! Ce que la liste ne dit pas, c'est qu'on ait le droit d'y écrire. N'importe
//! qui peut publier `rua=mailto:victime@example.com` : la vérification de cette
//! prétention est un autre problème, et il a son module ([`super::external`]).

use crate::Error;

/// Une destination de rapport, telle qu'elle est écrite.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Uri<'a> {
    /// Le schéma, sans les deux-points — `mailto`, `https`…
    ///
    /// Il se compare **sans égard à la casse** (RFC 3986 §3.1).
    pub scheme: &'a [u8],
    /// Ce qui suit les deux-points, **tel quel** : encore encodé en pourcent.
    ///
    /// Décoder demande un tampon, et cette crate n'alloue pas : voir [`decode`].
    pub target: &'a [u8],
    /// La taille au-delà de laquelle le destinataire ne veut rien recevoir.
    ///
    /// Absente, il n'y a pas de limite déclarée — ce qui ne veut pas dire qu'il
    /// n'y en a pas : c'est à l'émetteur de ne pas être déraisonnable.
    pub max_size: Option<u64>,
}

impl<'a> Uri<'a> {
    /// Est-ce une adresse de courrier ?
    ///
    /// **C'est le seul schéma que la RFC impose de savoir traiter** (§6.2) ; les
    /// autres sont facultatifs, et un receveur qui n'en connaît pas un
    /// l'ignore — il ne rejette pas l'enregistrement pour autant.
    #[must_use]
    pub fn is_mailto(&self) -> bool {
        self.scheme.eq_ignore_ascii_case(b"mailto")
    }

    /// Le domaine à qui le rapport serait remis.
    ///
    /// C'est de LUI qu'on vérifiera qu'il consent à recevoir (§7.1), et c'est
    /// pourquoi on le lit sans rien décoder : un domaine qui a besoin d'être
    /// décodé pour se lire n'est pas un domaine qu'on veut interroger.
    #[must_use]
    pub fn domain(&self) -> Option<&'a [u8]> {
        if !self.is_mailto() {
            return None;
        }
        let rang = self.target.iter().rposition(|octet| *octet == b'@')?;
        // `rposition` a trouvé l'arobase : ce qui suit existe, fût-il vide, et
        // le vide est écarté deux lignes plus bas. Pas de garde à tester ici.
        let domaine = self
            .target
            .get(rang.saturating_add(1)..)
            .unwrap_or_default();
        let bien_forme = !domaine.is_empty()
            && domaine.len() <= 255
            && domaine
                .iter()
                .all(|o| o.is_ascii_alphanumeric() || matches!(*o, b'-' | b'.'));
        bien_forme.then_some(domaine)
    }
}

/// Les destinations d'une valeur `rua=` ou `ruf=`, dans l'ordre.
#[derive(Debug, Clone)]
pub struct Uris<'a> {
    reste: &'a [u8],
    fini: bool,
}

impl<'a> Uris<'a> {
    /// Ouvre la lecture d'une valeur `rua=` ou `ruf=`.
    #[must_use]
    pub fn new(valeur: &'a [u8]) -> Self {
        Self {
            reste: valeur,
            fini: false,
        }
    }
}

impl<'a> Iterator for Uris<'a> {
    type Item = Result<Uri<'a>, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.fini {
            return None;
        }
        let (morceau, suite) = match self.reste.iter().position(|octet| *octet == b',') {
            Some(rang) => {
                let (avant, apres) = self.reste.split_at(rang);
                (avant, apres.get(1..).unwrap_or_default())
            }
            None => {
                self.fini = true;
                (self.reste, &[][..])
            }
        };
        self.reste = suite;
        Some(lire_une(morceau.trim_ascii()))
    }
}

/// Lit une destination, virgules déjà retirées.
fn lire_une(morceau: &[u8]) -> Result<Uri<'_>, Error> {
    // LE POINT D'EXCLAMATION SE CHERCHE EN PREMIER, pas en dernier : la RFC
    // exige qu'il soit encodé partout ailleurs, donc le premier qu'on voit est
    // celui qui sépare. Le chercher en dernier laisserait une URI fautive
    // décider où commence la taille.
    let (uri, taille) = match morceau.iter().position(|octet| *octet == b'!') {
        Some(rang) => {
            let (avant, apres) = morceau.split_at(rang);
            (avant, Some(apres.get(1..).unwrap_or_default()))
        }
        None => (morceau, None),
    };

    let rang = uri
        .iter()
        .position(|octet| *octet == b':')
        .ok_or(Error::MalformedUri)?;
    let (scheme, apres) = uri.split_at(rang);
    let target = apres.get(1..).unwrap_or_default();

    let (&premier, suite) = scheme.split_first().ok_or(Error::MalformedUri)?;
    if !premier.is_ascii_alphabetic() {
        return Err(Error::MalformedUri);
    }
    if !suite
        .iter()
        .all(|o| o.is_ascii_alphanumeric() || matches!(*o, b'+' | b'-' | b'.'))
    {
        return Err(Error::MalformedUri);
    }
    if target.is_empty() {
        return Err(Error::MalformedUri);
    }

    Ok(Uri {
        scheme,
        target,
        max_size: taille.map(lire_une_taille).transpose()?,
    })
}

/// Lit `1*DIGIT [ "k" / "m" / "g" / "t" ]` (§6.2).
fn lire_une_taille(texte: &[u8]) -> Result<u64, Error> {
    let (chiffres, facteur) = match texte.split_last() {
        Some((b'k' | b'K', avant)) => (avant, 1_u64 << 10),
        Some((b'm' | b'M', avant)) => (avant, 1_u64 << 20),
        Some((b'g' | b'G', avant)) => (avant, 1_u64 << 30),
        Some((b't' | b'T', avant)) => (avant, 1_u64 << 40),
        _ => (texte, 1_u64),
    };
    if chiffres.is_empty() {
        return Err(Error::MalformedSize);
    }
    let mut total = 0_u64;
    for octet in chiffres {
        if !octet.is_ascii_digit() {
            return Err(Error::MalformedSize);
        }
        total = total
            .checked_mul(10)
            .and_then(|d| d.checked_add(u64::from(octet.wrapping_sub(b'0'))))
            .ok_or(Error::MalformedSize)?;
    }
    // UNE TAILLE QUI DÉBORDE N'EST PAS UNE GRANDE TAILLE. Repartie de zéro,
    // elle interdirait tout envoi au nom d'un domaine qui n'a rien demandé de
    // tel ; on écarte l'enregistrement plutôt que de le trahir.
    total.checked_mul(facteur).ok_or(Error::MalformedSize)
}

/// Décode les `%XX` d'une destination, dans le tampon offert.
///
/// # Ce qui est refusé, et pourquoi
///
/// Le résultat sera écrit dans un en-tête `To:` et dans un nom de fichier. Un
/// octet de contrôle qui y arriverait — un `CR LF` décodé depuis `%0D%0A` —
/// laisserait celui qui publie l'enregistrement écrire les en-têtes qu'il veut
/// dans le message qu'on lui envoie. **Seul l'ASCII imprimable ressort d'ici.**
///
/// # Errors
///
/// [`Error::MalformedUri`] si un `%` n'est pas suivi de deux chiffres
/// hexadécimaux, [`Error::NotPrintable`] si un octet décodé n'est pas de l'ASCII
/// imprimable, [`Error::BufferTooSmall`] si `out` ne suffit pas.
pub fn decode<'b>(valeur: &[u8], out: &'b mut [u8]) -> Result<&'b [u8], Error> {
    let mut ecrits = 0_usize;
    let mut reste = valeur;
    while let Some((&premier, suite)) = reste.split_first() {
        let (octet, apres) = if premier == b'%' {
            // DEUX PRÉLÈVEMENTS, DEUX FAUTES POSSIBLES : « % » en fin de chaîne
            // et « %2 » en fin de chaîne ne sont pas la même faute d'écriture,
            // et les distinguer coûte moins cher que de prendre deux octets
            // pour ensuite affirmer qu'ils étaient bien deux.
            let (&haut, apres) = suite.split_first().ok_or(Error::MalformedUri)?;
            let (&bas, apres) = apres.split_first().ok_or(Error::MalformedUri)?;
            (
                chiffre(haut)?.wrapping_mul(16).wrapping_add(chiffre(bas)?),
                apres,
            )
        } else {
            (premier, suite)
        };
        if !octet.is_ascii_graphic() && octet != b' ' {
            return Err(Error::NotPrintable);
        }
        *out.get_mut(ecrits).ok_or(Error::BufferTooSmall)? = octet;
        ecrits = ecrits.saturating_add(1);
        reste = apres;
    }
    out.get(..ecrits).ok_or(Error::BufferTooSmall)
}

/// Lit un chiffre hexadécimal.
fn chiffre(octet: u8) -> Result<u8, Error> {
    match octet {
        b'0'..=b'9' => Ok(octet.wrapping_sub(b'0')),
        b'a'..=b'f' => Ok(octet.wrapping_sub(b'a').wrapping_add(10)),
        b'A'..=b'F' => Ok(octet.wrapping_sub(b'A').wrapping_add(10)),
        _ => Err(Error::MalformedUri),
    }
}

#[cfg(test)]
mod tests;
