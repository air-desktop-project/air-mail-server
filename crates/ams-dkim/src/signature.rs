//! Le champ `DKIM-Signature` (RFC 6376 §3.5).

use crate::canonical::Canonicalization;
use crate::tag::{Tags, sans_blancs};
use crate::{Error, Tag};

/// L'algorithme de signature et de condensat (`a=`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    /// RSA et SHA-256 (RFC 6376 §3.3.3).
    RsaSha256,
    /// Ed25519 et SHA-256 (RFC 8463).
    Ed25519Sha256,
}

impl Algorithm {
    /// Lit un `a=`.
    ///
    /// # `rsa-sha1` est REFUSÉ, et ce n'est pas un oubli
    ///
    /// RFC 8301 §3.1 l'interdit aux signataires **comme aux vérificateurs**.
    /// SHA-1 se collisionne pour un coût qu'un particulier peut payer ; accepter
    /// ces signatures reviendrait à valider ce qu'on sait falsifiable — et à le
    /// consigner dans un en-tête que DMARC lira comme un `pass`.
    ///
    /// # Errors
    ///
    /// [`Error::UnsupportedAlgorithm`].
    pub fn parse(valeur: &[u8]) -> Result<Self, Error> {
        if valeur.eq_ignore_ascii_case(b"rsa-sha256") {
            return Ok(Self::RsaSha256);
        }
        if valeur.eq_ignore_ascii_case(b"ed25519-sha256") {
            return Ok(Self::Ed25519Sha256);
        }
        Err(Error::UnsupportedAlgorithm)
    }

    /// Le nom du condensat, tel que l'enregistrement de clé l'écrit dans son
    /// `h=`.
    #[must_use]
    pub fn hash_name(self) -> &'static [u8] {
        match self {
            Self::RsaSha256 | Self::Ed25519Sha256 => b"sha256",
        }
    }
}

/// Un champ `DKIM-Signature` lu et vérifié dans sa cohérence.
///
/// **Rien n'est décodé ici.** `b=` et `bh=` sont rendus tels qu'ils ont été
/// écrits, pliage compris : les décoder demande un tampon que seul l'appelant
/// peut dimensionner, et les comparer demande une clé qu'on n'a pas encore.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Signature<'a> {
    /// `a=` — de quoi vérifier.
    pub algorithm: Algorithm,
    /// `c=` — ce qui est signé, exactement.
    pub canonicalization: Canonicalization,
    /// `d=` — le domaine qui signe.
    pub domain: &'a [u8],
    /// `s=` — le sélecteur, qui nomme la clé dans le DNS.
    pub selector: &'a [u8],
    /// `h=` — la liste des champs signés, telle qu'elle a été écrite.
    pub headers: &'a [u8],
    /// `i=` — l'identité de l'agent signataire, si elle est donnée.
    pub identity: Option<&'a [u8]>,
    /// `l=` — la borne du corps signé. **Voir [`crate::BodyCanon::new`] : c'est
    /// un danger connu.**
    pub body_length: Option<u64>,
    /// `t=` — quand la signature a été posée.
    pub timestamp: Option<u64>,
    /// `x=` — quand elle cesse de valoir.
    pub expiration: Option<u64>,
    /// `b=` — la signature, en base64 encore plié.
    pub signature: &'a [u8],
    /// `bh=` — le condensat du corps, en base64 encore plié.
    pub body_hash: &'a [u8],
}

impl<'a> Signature<'a> {
    /// Lit la valeur d'un champ `DKIM-Signature`.
    ///
    /// # Ce qui est vérifié ici, et pourquoi chacun compte
    ///
    /// La RFC 6376 §6.1.1 veut qu'une signature incohérente échoue **avant**
    /// toute cryptographie. Chacune de ces règles ferme une façon de mentir :
    ///
    /// - `h=` doit nommer `from` : une signature qui ne couvre pas l'auteur ne
    ///   dit rien de l'auteur, et c'est pourtant lui que l'humain lira ;
    /// - `i=` doit être sous `d=` : sans quoi un signataire s'attribuerait
    ///   l'identité d'un domaine qu'il ne détient pas ;
    /// - `x=` doit suivre `t=` : une signature qui expire avant d'être posée
    ///   n'est pas une signature, c'est une erreur d'horloge ou une fabrication.
    ///
    /// # Errors
    ///
    /// Voir [`Error`]. Toutes valent `permfail`.
    pub fn parse(valeur: &'a [u8]) -> Result<Self, Error> {
        let mut version: Option<&[u8]> = None;
        let mut algorithme: Option<Algorithm> = None;
        let mut canonicalisation: Option<Canonicalization> = None;
        let mut domaine: Option<&[u8]> = None;
        let mut selecteur: Option<&[u8]> = None;
        let mut entetes: Option<&[u8]> = None;
        let mut identite: Option<&[u8]> = None;
        let mut longueur: Option<u64> = None;
        let mut horodatage: Option<u64> = None;
        let mut expiration: Option<u64> = None;
        let mut signature: Option<&[u8]> = None;
        let mut condensat: Option<&[u8]> = None;

        for etiquette in Tags::new(valeur) {
            let Tag { name, value } = etiquette?;
            // Les noms d'étiquette sont SENSIBLES À LA CASSE (§3.2) : `D=` n'est
            // pas `d=`, et le traiter comme tel accepterait une signature dont
            // le domaine n'est écrit nulle part.
            match name {
                b"v" => poser(&mut version, value)?,
                b"a" => poser(&mut algorithme, Algorithm::parse(value)?)?,
                // `c=` a un défaut ; l'écrire deux fois reste une faute.
                b"c" => poser(&mut canonicalisation, Canonicalization::parse(value)?)?,
                b"d" => poser(&mut domaine, value)?,
                b"s" => poser(&mut selecteur, value)?,
                b"h" => poser(&mut entetes, value)?,
                b"i" => poser(&mut identite, value)?,
                b"l" => poser(&mut longueur, nombre(value)?)?,
                b"t" => poser(&mut horodatage, nombre(value)?)?,
                b"x" => poser(&mut expiration, nombre(value)?)?,
                b"b" => poser(&mut signature, value)?,
                b"bh" => poser(&mut condensat, value)?,
                b"q" => verifier_la_methode(value)?,
                // §3.2 : les étiquettes inconnues S'IGNORENT. C'est ce qui
                // permet à la RFC d'en ajouter sans casser les vérificateurs —
                // et `z=` en est une, qui ne sert qu'au diagnostic.
                _ => {}
            }
        }

        if version != Some(b"1") {
            return Err(Error::UnsupportedVersion);
        }
        let algorithm = algorithme.ok_or(Error::MissingTag("a"))?;
        let domain = domaine.ok_or(Error::MissingTag("d"))?;
        let selector = selecteur.ok_or(Error::MissingTag("s"))?;
        let headers = entetes.ok_or(Error::MissingTag("h"))?;
        let signature = signature.ok_or(Error::MissingTag("b"))?;
        let body_hash = condensat.ok_or(Error::MissingTag("bh"))?;

        if domain.is_empty() || selector.is_empty() {
            return Err(Error::MalformedDomain);
        }
        if !SignedHeaders::new(headers).any(|nom| nom.eq_ignore_ascii_case(b"from")) {
            return Err(Error::FromNotSigned);
        }
        if let Some(agent) = identite
            && !sous_le_domaine(agent, domain)
        {
            return Err(Error::IdentityOutsideDomain);
        }
        if let (Some(pose), Some(fin)) = (horodatage, expiration)
            && fin <= pose
        {
            return Err(Error::ExpiryBeforeSignature);
        }

        Ok(Self {
            algorithm,
            canonicalization: canonicalisation.unwrap_or_default(),
            domain,
            selector,
            headers,
            identity: identite,
            body_length: longueur,
            timestamp: horodatage,
            expiration,
            signature,
            body_hash,
        })
    }

    /// Les noms de champs signés, dans l'ordre où `h=` les nomme.
    #[must_use]
    pub fn signed_headers(&self) -> SignedHeaders<'a> {
        SignedHeaders::new(self.headers)
    }

    /// Le `b=` sans ses blancs, prêt à décoder.
    ///
    /// # Errors
    ///
    /// [`Error::BufferTooSmall`].
    pub fn signature_base64<'b>(&self, sortie: &'b mut [u8]) -> Result<&'b [u8], Error> {
        sans_blancs(self.signature, sortie)
    }

    /// Le `bh=` sans ses blancs, prêt à décoder.
    ///
    /// # Errors
    ///
    /// [`Error::BufferTooSmall`].
    pub fn body_hash_base64<'b>(&self, sortie: &'b mut [u8]) -> Result<&'b [u8], Error> {
        sans_blancs(self.body_hash, sortie)
    }
}

/// L'étendue de la VALEUR du `b=` dans la valeur brute du champ.
///
/// Rend `(début, fin)` : de l'octet qui suit le `=` jusqu'au `;` qui clôt
/// l'étiquette, ou la fin de la valeur.
///
/// # Pourquoi jusqu'au point-virgule, blancs compris
///
/// Au moment où le signataire a calculé son condensat, `b=` était **vide** :
/// rien entre le `=` et le `;`. C'est cette forme-là qu'il faut reconstituer, et
/// y laisser un pliage ou une espace donnerait un condensat différent du sien.
pub(crate) fn etendue_du_b(valeur: &[u8]) -> Option<(usize, usize)> {
    // `unwrap_or_default` partout : `depart` ne dépasse jamais la longueur,
    // `longueur` ne dépasse jamais le reste, et `rang` est un rang trouvé DANS
    // le morceau. Trois tranches qui ne peuvent pas manquer, et trois gardes
    // qu'aucun message ne pourrait emprunter.
    let mut depart = 0_usize;
    while depart <= valeur.len() {
        let reste = valeur.get(depart..).unwrap_or_default();
        let longueur = reste
            .iter()
            .position(|octet| *octet == b';')
            .unwrap_or(reste.len());
        let morceau = reste.get(..longueur).unwrap_or_default();
        if let Some(rang) = morceau.iter().position(|octet| *octet == b'=')
            && morceau.get(..rang).unwrap_or_default().trim_ascii() == b"b"
        {
            let debut = depart.saturating_add(rang).saturating_add(1);
            return Some((debut, depart.saturating_add(longueur)));
        }
        depart = depart.saturating_add(longueur).saturating_add(1);
    }
    None
}

/// Pose une valeur, ou dit qu'elle l'était déjà.
fn poser<T>(place: &mut Option<T>, valeur: T) -> Result<(), Error> {
    if place.is_some() {
        return Err(Error::DuplicateTag);
    }
    *place = Some(valeur);
    Ok(())
}

/// Lit un entier décimal.
fn nombre(valeur: &[u8]) -> Result<u64, Error> {
    if valeur.is_empty() {
        return Err(Error::MalformedNumber);
    }
    let mut total = 0_u64;
    for octet in valeur {
        let chiffre = u64::from(octet.wrapping_sub(b'0'));
        if !octet.is_ascii_digit() {
            return Err(Error::MalformedNumber);
        }
        // UN DÉBORDEMENT N'EST PAS UNE GRANDE VALEUR. Un `x=` qui déborderait en
        // repartant de zéro ferait expirer une signature valide, ou l'inverse.
        total = total
            .checked_mul(10)
            .and_then(|dizaines| dizaines.checked_add(chiffre))
            .ok_or(Error::MalformedNumber)?;
    }
    Ok(total)
}

/// `q=` nomme-t-il une méthode qu'on sait conduire ?
///
/// RFC 6376 §3.5 : un vérificateur DOIT ignorer une signature dont le `q=` ne
/// nomme que des méthodes qu'il n'implémente pas. On n'en connaît qu'une, et
/// c'est la seule que la RFC définisse.
fn verifier_la_methode(valeur: &[u8]) -> Result<(), Error> {
    let connue = valeur
        .split(|octet| *octet == b':')
        .any(|methode| methode.trim_ascii().eq_ignore_ascii_case(b"dns/txt"));
    if connue {
        return Ok(());
    }
    Err(Error::UnsupportedAlgorithm)
}

/// `agent` est-il sous `domaine` ? (`i=` face à `d=`, §3.5.)
fn sous_le_domaine(agent: &[u8], domaine: &[u8]) -> bool {
    // `i=` s'écrit `[partie-locale]@domaine` ; c'est le domaine qui compte.
    let rang = agent.iter().rposition(|octet| *octet == b'@');
    let Some(rang) = rang else {
        return false;
    };
    let sien = agent.get(rang.saturating_add(1)..).unwrap_or_default();
    if sien.eq_ignore_ascii_case(domaine) {
        return true;
    }
    // `a.example.com` est sous `example.com` ; `badexample.com` ne l'est pas —
    // le point compte, et l'oublier autoriserait qui enregistre un nom qui finit
    // par celui du signataire.
    let reste = sien.len().checked_sub(domaine.len().saturating_add(1));
    let Some(reste) = reste else {
        return false;
    };
    sien.get(reste) == Some(&b'.')
        && sien
            .get(reste.saturating_add(1)..)
            .is_some_and(|queue| queue.eq_ignore_ascii_case(domaine))
}

/// Les noms de champs d'un `h=`.
///
/// Les blancs autour des deux-points sont retirés (§3.5) ; les noms vides —
/// qu'un `h=from::to` produirait — sont **rendus tels quels**, parce que c'est
/// à l'appelant de constater qu'aucun champ ne s'appelle ainsi.
#[derive(Debug, Clone)]
pub struct SignedHeaders<'a> {
    reste: Option<&'a [u8]>,
}

impl<'a> SignedHeaders<'a> {
    fn new(liste: &'a [u8]) -> Self {
        Self { reste: Some(liste) }
    }
}

impl<'a> Iterator for SignedHeaders<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<Self::Item> {
        let reste = self.reste?;
        match reste.iter().position(|octet| *octet == b':') {
            Some(rang) => {
                let (avant, apres) = reste.split_at(rang);
                self.reste = apres.get(1..);
                Some(avant.trim_ascii())
            }
            None => {
                self.reste = None;
                Some(reste.trim_ascii())
            }
        }
    }
}

#[cfg(test)]
mod tests;
