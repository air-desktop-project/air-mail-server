//! La vérification d'une signature (RFC 6376 §6), **sans entrée-sortie**.
//!
//! # Ce que la crate fait, et ce qu'elle laisse à l'appelant
//!
//! Elle condense et elle vérifie. Elle ne va PAS chercher la clé : celle-ci vit
//! dans le DNS, sous `<sélecteur>._domainkey.<domaine>`, et une résolution est
//! une entrée-sortie. L'appelant lit `d=` et `s=` sur la signature, résout, et
//! rend l'enregistrement — c'est le même partage que pour SPF, et c'est ce qui
//! rend ce module couvrable à 100 % sans serveur DNS de test.
//!
//! # L'ordre des opérations n'est pas indifférent
//!
//! **Le condensat du corps se compare AVANT la signature.** C'est gratuit — une
//! comparaison de trente-deux octets — là où vérifier une signature RSA coûte
//! une exponentiation modulaire. Un message dont le corps a changé est ainsi
//! rejeté sans qu'on ait payé la cryptographie, et un pair qui envoie mille
//! messages falsifiés ne fait pas travailler la machine pour autant.
//!
//! # Deux bornes sur les clés, et elles ne sont pas décoratives
//!
//! Une clé RSA de moins de 1024 bits se factorise ; la RFC 8301 §3.2 l'interdit
//! aux signataires, et l'accepter en vérification reviendrait à valider ce qu'on
//! sait falsifiable. Une clé de plus de 4096 bits, elle, ne protège personne de
//! plus mais coûte à *nous* : c'est une zone hostile qui la publierait, pour
//! faire brûler du calcul à qui lui écrit.

extern crate alloc;

use ed25519_dalek::{Signature as EdSignature, VerifyingKey};
use rsa::RsaPublicKey;
use rsa::pkcs1::DecodeRsaPublicKey as _;
use rsa::pkcs1v15::Pkcs1v15Sign;
use rsa::pkcs8::DecodePublicKey as _;
use rsa::traits::{PublicKeyParts as _, SignatureScheme as _};
use sha2::{Digest as _, Sha256};

use crate::base64::decoder_base64;
use crate::body::BodyCanon;
use crate::canonical::{Canon, Trailer, canonicalize_header, canonicalize_header_parts};
use crate::signature::{Algorithm, Signature, etendue_du_b};
use crate::{Error, PublicKeyRecord};

/// La taille d'un condensat SHA-256.
pub const DIGEST_LEN: usize = 32;

/// La plus petite clé RSA qu'on accepte de vérifier, en octets (1024 bits).
const RSA_MIN: usize = 128;

/// La plus grande, en octets (4096 bits).
const RSA_MAX: usize = 512;

/// La taille d'une clé publique Ed25519.
const ED25519_KEY: usize = 32;

/// La taille d'une signature Ed25519.
const ED25519_SIG: usize = 64;

/// Le condensat du corps, calculé en flux.
///
/// Voir [`BodyCanon::new`] pour ce que la borne `l=` autorise — et pour
/// pourquoi c'est un danger connu.
#[derive(Debug, Clone)]
pub struct BodyHasher {
    canon: BodyCanon,
    sha: Sha256,
}

impl BodyHasher {
    /// Ouvre le calcul.
    #[must_use]
    pub fn new(canon: Canon, limite: Option<u64>) -> Self {
        Self {
            canon: BodyCanon::new(canon, limite),
            sha: Sha256::new(),
        }
    }

    /// Donne un morceau du corps.
    pub fn update(&mut self, morceau: &[u8]) {
        let sha = &mut self.sha;
        self.canon.update(morceau, &mut |canonicalise| {
            sha.update(canonicalise);
        });
    }

    /// Termine, et rend le condensat et le nombre d'octets canonicalisés.
    ///
    /// # Le compte sert à faire échouer un corps TROP COURT
    ///
    /// RFC 6376 §6.1.1 : si `l=` annonce plus d'octets que le corps n'en porte,
    /// la vérification échoue. Sans cette comparaison, un pair pourrait faire
    /// signer un long corps et n'en livrer qu'un début.
    #[must_use]
    pub fn finish(mut self) -> ([u8; DIGEST_LEN], u64) {
        let sha = &mut self.sha;
        let ecrits = self.canon.finish(&mut |canonicalise| {
            sha.update(canonicalise);
        });
        (self.sha.finalize().into(), ecrits)
    }
}

/// Le condensat des en-têtes signés.
///
/// Les champs sont donnés **dans l'ordre où `h=` les nomme**, et le
/// `DKIM-Signature` lui-même vient en dernier.
#[derive(Debug, Clone)]
pub struct HeaderHasher {
    canon: Canon,
    sha: Sha256,
}

impl HeaderHasher {
    /// Ouvre le calcul.
    #[must_use]
    pub fn new(canon: Canon) -> Self {
        Self {
            canon,
            sha: Sha256::new(),
        }
    }

    /// Ajoute un champ ordinaire.
    pub fn field(&mut self, name: &[u8], value: &[u8]) {
        let sha = &mut self.sha;
        canonicalize_header(self.canon, name, value, Trailer::Crlf, &mut |octets| {
            sha.update(octets);
        });
    }

    /// Ajoute le champ `DKIM-Signature` lui-même.
    ///
    /// # Deux choses le distinguent, et les deux viennent de §3.7
    ///
    /// La valeur de son `b=` est **retirée** — au moment où le signataire a
    /// calculé ce condensat, elle n'existait pas encore — et le champ entre
    /// **sans son `CRLF` final**, pour la même raison.
    ///
    /// # Errors
    ///
    /// [`Error::MissingTag`] si la valeur ne porte pas de `b=`.
    pub fn signature_field(&mut self, name: &[u8], value: &[u8]) -> Result<(), Error> {
        let (debut, fin) = etendue_du_b(value).ok_or(Error::MissingTag("b"))?;
        let avant = value.get(..debut).unwrap_or_default();
        let apres = value.get(fin..).unwrap_or_default();
        let sha = &mut self.sha;
        canonicalize_header_parts(
            self.canon,
            name,
            &[avant, apres],
            Trailer::Aucun,
            &mut |octets| {
                sha.update(octets);
            },
        );
        Ok(())
    }

    /// Ajoute un champ `DKIM-Signature` **dont le `b=` est déjà vide**.
    ///
    /// C'est le cas du signataire, qui vient de l'écrire ainsi : il n'y a rien à
    /// retirer, et donc aucune raison d'échouer. Le vérificateur, lui, emploie
    /// [`HeaderHasher::signature_field`], qui doit d'abord trouver où le `b=`
    /// s'arrête.
    pub fn written_signature_field(&mut self, name: &[u8], value: &[u8]) {
        let sha = &mut self.sha;
        canonicalize_header(self.canon, name, value, Trailer::Aucun, &mut |octets| {
            sha.update(octets);
        });
    }

    /// Termine, et rend le condensat.
    #[must_use]
    pub fn finish(self) -> [u8; DIGEST_LEN] {
        self.sha.finalize().into()
    }
}

/// Condense les champs que `h=` nomme, **dans l'ordre et depuis le bas**.
///
/// `fields` est appelée autant de fois qu'il le faut : elle doit rendre les
/// champs du message dans l'ordre où ils y figurent, du haut vers le bas. La
/// crate n'alloue pas, et ne peut donc pas les retenir.
///
/// # Depuis le bas, et une seule fois chacun (RFC 6376 §5.4.2)
///
/// La `k`-ième mention d'un nom dans `h=` désigne la `k`-ième instance de ce
/// champ **en partant du bas** du bloc d'en-tête. Ce n'est pas une bizarrerie :
/// un relais qui AJOUTE un champ l'écrit en haut, et cette règle fait qu'un
/// champ ajouté n'est jamais celui qu'on condense.
///
/// # Un nom qu'on ne trouve plus se traite comme ABSENT
///
/// Si `h=` nomme un champ trois fois et que le message n'en porte que deux, la
/// troisième mention ne condense rien — et c'est ce qui ferme l'attaque par
/// AJOUT : un signataire qui nomme `subject` deux fois alors qu'il n'y en a
/// qu'un fait échouer la signature dès qu'un second apparaît.
pub fn hash_signed_headers<'a, F, I>(
    signature: &Signature<'_>,
    hasher: &mut HeaderHasher,
    fields: F,
) where
    F: Fn() -> I,
    I: Iterator<Item = (&'a [u8], &'a [u8])>,
{
    for (rang, nom) in signature.signed_headers().enumerate() {
        // Combien de fois ce nom a-t-il déjà été demandé avant ce rang ?
        let deja = signature
            .signed_headers()
            .take(rang)
            .filter(|autre| autre.eq_ignore_ascii_case(nom))
            .count();
        let combien = fields()
            .filter(|(present, _)| present.eq_ignore_ascii_case(nom))
            .count();
        // La `deja + 1`-ième instance EN PARTANT DU BAS.
        let Some(indice) = combien.checked_sub(deja.saturating_add(1)) else {
            continue;
        };
        // `into_iter` plutôt qu'un `if let` : l'instance existe forcément —
        // `indice` est strictement inférieur au nombre qu'on vient de compter —
        // et une garde qu'aucun message ne pourrait emprunter n'est pas une
        // garde.
        fields()
            .filter(|(present, _)| present.eq_ignore_ascii_case(nom))
            .nth(indice)
            .into_iter()
            .for_each(|(present, valeur)| hasher.field(present, valeur));
    }
}

/// Vérifie une signature contre une clé publique.
///
/// `body` est le condensat rendu par [`BodyHasher::finish`], `headers` celui de
/// [`HeaderHasher::finish`], et `key` la clé **déjà décodée du base64** de `p=`.
///
/// # Errors
///
/// Voir [`Error`]. Toutes valent `permfail` : une signature qui ne se vérifie
/// pas n'est pas une signature.
pub fn verify(
    signature: &Signature<'_>,
    record: &PublicKeyRecord<'_>,
    key: &[u8],
    body: &[u8; DIGEST_LEN],
    headers: &[u8; DIGEST_LEN],
    body_signature: &[u8],
) -> Result<(), Error> {
    // ── Ce que la clé DIT d'elle-même, avant toute cryptographie ────────────
    if !record.matches(signature.algorithm) {
        return Err(Error::UnsupportedKeyType);
    }
    if !record.accepts(signature.algorithm) {
        return Err(Error::UnsupportedAlgorithm);
    }

    // ── Le corps AVANT la signature : c'est le contrôle gratuit ─────────────
    let mut attendu = [0_u8; DIGEST_LEN];
    let ecrit = decoder_base64(signature.body_hash, &mut attendu)?;
    if ecrit != DIGEST_LEN || !constant_eq(&attendu, body) {
        return Err(Error::BodyHashMismatch);
    }

    verifier_la_signature(signature.algorithm, key, headers, body_signature)
}

/// La cryptographie, et rien d'autre.
///
/// # Errors
///
/// [`Error::MalformedKey`], [`Error::KeyTooSmall`], [`Error::KeyTooLarge`] ou
/// [`Error::SignatureMismatch`].
pub fn verifier_la_signature(
    algorithm: Algorithm,
    key: &[u8],
    digest: &[u8; DIGEST_LEN],
    signature: &[u8],
) -> Result<(), Error> {
    match algorithm {
        Algorithm::RsaSha256 => verifier_rsa(key, digest, signature),
        Algorithm::Ed25519Sha256 => verifier_ed25519(key, digest, signature),
    }
}

fn verifier_rsa(key: &[u8], digest: &[u8; DIGEST_LEN], signature: &[u8]) -> Result<(), Error> {
    // RFC 6376 §3.6.1 veut un `SubjectPublicKeyInfo` (RFC 5280). Des zones en
    // publient pourtant sous la forme nue de PKCS#1, et un vérificateur qui les
    // refuserait ferait échouer des signataires par ailleurs corrects.
    let publique = RsaPublicKey::from_public_key_der(key)
        .or_else(|_| RsaPublicKey::from_pkcs1_der(key))
        .map_err(|_| Error::MalformedKey)?;

    let octets = publique.size();
    if octets < RSA_MIN {
        return Err(Error::KeyTooSmall);
    }
    if octets > RSA_MAX {
        return Err(Error::KeyTooLarge);
    }

    Pkcs1v15Sign::new::<Sha256>()
        .verify(&publique, digest, signature)
        .map_err(|_| Error::SignatureMismatch)
}

fn verifier_ed25519(key: &[u8], digest: &[u8; DIGEST_LEN], signature: &[u8]) -> Result<(), Error> {
    // RFC 8463 §3 : le `p=` porte la clé NUE, pas un `SubjectPublicKeyInfo`.
    let octets: &[u8; ED25519_KEY] = key.first_chunk().ok_or(Error::MalformedKey)?;
    if key.len() != ED25519_KEY {
        return Err(Error::MalformedKey);
    }
    let publique = VerifyingKey::from_bytes(octets).map_err(|_| Error::MalformedKey)?;

    let scellee: &[u8; ED25519_SIG] = signature.first_chunk().ok_or(Error::SignatureMismatch)?;
    if signature.len() != ED25519_SIG {
        return Err(Error::SignatureMismatch);
    }

    // `verify_strict` refuse les clés d'ordre faible et les signatures
    // malléables. La variante permissive laisserait DEUX signatures valider le
    // même message, ce dont on n'a aucun usage et qui a déjà servi ailleurs.
    publique
        .verify_strict(digest, &EdSignature::from_bytes(scellee))
        .map_err(|_| Error::SignatureMismatch)
}

/// Compare deux condensats **sans fuir où ils diffèrent**.
///
/// Un condensat de corps n'est pas un secret, et l'écart de temps d'une
/// comparaison ordinaire n'apprendrait rien d'utile ici. On le fait quand même :
/// le jour où quelqu'un réemploiera cette fonction sur autre chose, il ne se
/// demandera pas si elle convient.
fn constant_eq(gauche: &[u8; DIGEST_LEN], droite: &[u8; DIGEST_LEN]) -> bool {
    let mut ecart = 0_u8;
    for (un, autre) in gauche.iter().zip(droite.iter()) {
        ecart |= un ^ autre;
    }
    ecart == 0
}

#[cfg(test)]
mod tests;
