// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Web Push, côté serveur d'application : chiffrer le message (RFC 8291) et
//! s'annoncer au service de push (VAPID, RFC 8292) — **sans entrée-sortie**
//! (C1), et sans allocation.
//!
//! # LE SERVICE DE PUSH NE LIT PAS CE QU'IL PORTE
//!
//! Un message Web Push traverse le service du navigateur — Google, Mozilla,
//! Apple, ou un distributeur UnifiedPush. La RFC 8291 le chiffre pour le
//! navigateur seul : un échange ECDH P-256 entre une clef éphémère du serveur et
//! la clef du navigateur, mêlé au secret d'authentification que le navigateur a
//! tiré, donne la clef AES-128-GCM et le nonce. Le service de push relaie des
//! octets qu'il ne sait pas ouvrir.
//!
//! # L'ALÉA VIENT DE L'APPELANT
//!
//! La clef éphémère et le sel sont TIRÉS par l'appelant et DONNÉS ici. C'est ce
//! qui garde cette crate sans entrée-sortie, et ce qui permet de l'éprouver
//! contre le vecteur de l'annexe A de la RFC 8291, octet pour octet. **Les
//! réemployer d'un message à l'autre serait une faute grave** : le même nonce
//! sous la même clef défait AES-GCM. L'appelant les tire neufs à chaque envoi.
//!
//! # VAPID : QUI FRAPPE À LA PORTE
//!
//! Le jeton VAPID est un JWT ES256 qui dit au service de push quel serveur
//! envoie, et jusqu'à quand. Il est signé par la clef VAPID du serveur, dont la
//! moitié publique a été donnée au navigateur à l'abonnement : un autre serveur
//! ne peut pas écrire à ce navigateur sous notre nom.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

#[cfg(test)]
extern crate std;

use aes_gcm::{AeadInOut, Aes128Gcm, KeyInit};
use hkdf::Hkdf;
use sha2::Sha256;

/// Une clef publique P-256 non compressée.
pub const PUBLIC_KEY_OCTETS: usize = 65;
/// Une clef privée P-256.
pub const PRIVATE_KEY_OCTETS: usize = 32;
/// Le secret d'authentification d'un abonnement (§3.2).
pub const AUTH_OCTETS: usize = 16;
/// Le sel d'un message (§3.4 de RFC 8188).
pub const SALT_OCTETS: usize = 16;
/// La taille d'enregistrement annoncée : un message tient en un seul.
pub const RECORD_SIZE: u32 = 4096;
/// L'en-tête d'un message `aes128gcm` : sel, taille d'enregistrement, longueur
/// de l'identifiant, clef publique éphémère.
pub const HEADER_OCTETS: usize = SALT_OCTETS + 4 + 1 + PUBLIC_KEY_OCTETS;
/// Ce qu'ajoutent au clair le délimiteur de remplissage et l'étiquette GCM.
pub const OVERHEAD_OCTETS: usize = HEADER_OCTETS + 1 + 16;
/// Le plus long clair qu'un message porte : il doit tenir en un enregistrement
/// de [`RECORD_SIZE`], et tout service de push accepte 4 096 octets (§7.2 de
/// RFC 8030).
pub const PLAINTEXT_MAX: usize = RECORD_SIZE as usize - OVERHEAD_OCTETS;

/// Ce qui ne va pas.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// La place ne suffit pas.
    BufferTooSmall,
    /// Une clef privée qui n'en est pas une (zéro, ou au-delà de l'ordre).
    BadPrivateKey,
    /// Une clef publique qui n'est pas un point de la courbe.
    BadPublicKey,
    /// Le clair dépasse [`PLAINTEXT_MAX`].
    TooLong,
    /// Une revendication VAPID hors de la forme admise.
    BadClaim,
    /// Un fichier de clef qui n'est pas une clef `.p8` P-256.
    BadKeyFile,
}

/// Chiffre `clair` pour un navigateur (RFC 8291 §3.4), et écrit le corps du
/// message dans `out` — en-tête compris. Rend ce qu'il occupe.
///
/// `ua_public` et `auth` viennent de l'abonnement ; `ephemere` et `sel` sont
/// tirés NEUFS par l'appelant à chaque message.
///
/// # Errors
///
/// [`Error::BadPublicKey`], [`Error::BadPrivateKey`], [`Error::TooLong`],
/// [`Error::BufferTooSmall`].
pub fn encrypt(
    clair: &[u8],
    ua_public: &[u8; PUBLIC_KEY_OCTETS],
    auth: &[u8; AUTH_OCTETS],
    ephemere: &[u8; PRIVATE_KEY_OCTETS],
    sel: &[u8; SALT_OCTETS],
    out: &mut [u8],
) -> Result<usize, Error> {
    if clair.len() > PLAINTEXT_MAX {
        return Err(Error::TooLong);
    }
    let total = clair.len().saturating_add(OVERHEAD_OCTETS);
    let out = out.get_mut(..total).ok_or(Error::BufferTooSmall)?;
    let navigateur =
        p256::PublicKey::from_sec1_bytes(ua_public).map_err(|_| Error::BadPublicKey)?;
    let secret = p256::SecretKey::from_slice(ephemere).map_err(|_| Error::BadPrivateKey)?;
    let as_public = publique(&secret);

    // §3.3 : le secret ECDH, mêlé au secret d'authentification.
    let partage = p256::ecdh::diffie_hellman(secret.to_nonzero_scalar(), navigateur.as_affine());
    let mut info = [0_u8; 14 + 2 * PUBLIC_KEY_OCTETS];
    let (etiquette, clefs) = info.split_at_mut(14);
    etiquette.copy_from_slice(b"WebPush: info\0");
    let (ua, asp) = clefs.split_at_mut(PUBLIC_KEY_OCTETS);
    ua.copy_from_slice(ua_public);
    asp.copy_from_slice(&as_public);
    let mut ikm = [0_u8; 32];
    // Trente-deux octets sous SHA-256 : l'expansion tient toujours.
    let _ = Hkdf::<Sha256>::new(Some(auth), partage.raw_secret_bytes()).expand(&info, &mut ikm);

    // RFC 8188 §2.2 : la clef de contenu et le nonce, sous le sel.
    let prk = Hkdf::<Sha256>::new(Some(sel), &ikm);
    let mut cek = [0_u8; 16];
    let mut nonce = [0_u8; 12];
    let _ = prk.expand(b"Content-Encoding: aes128gcm\0", &mut cek);
    let _ = prk.expand(b"Content-Encoding: nonce\0", &mut nonce);

    // L'en-tête (§2.1 de RFC 8188) : sel, taille, longueur de l'identifiant,
    // identifiant — la clef publique éphémère.
    let (entete, suite) = out.split_at_mut(HEADER_OCTETS);
    let (s, reste) = entete.split_at_mut(SALT_OCTETS);
    s.copy_from_slice(sel);
    let (rs, reste) = reste.split_at_mut(4);
    rs.copy_from_slice(&RECORD_SIZE.to_be_bytes());
    let (idlen, id) = reste.split_at_mut(1);
    idlen.copy_from_slice(&[65]);
    id.copy_from_slice(&as_public);

    // Le clair, le délimiteur du dernier enregistrement (0x02), puis
    // l'étiquette GCM derrière.
    let (corps, etiquette_gcm) = suite.split_at_mut(clair.len().saturating_add(1));
    let (texte, delimiteur) = corps.split_at_mut(clair.len());
    texte.copy_from_slice(clair);
    delimiteur.copy_from_slice(&[2]);
    let tag = Aes128Gcm::new(&cek.into())
        .encrypt_inout_detached(&nonce.into(), &[], corps.into())
        .unwrap_or_default();
    etiquette_gcm.copy_from_slice(&tag);
    Ok(total)
}

/// La moitié publique d'une clef privée, non compressée.
fn publique(secret: &p256::SecretKey) -> [u8; PUBLIC_KEY_OCTETS] {
    use p256::elliptic_curve::sec1::ToSec1Point as _;
    let point = secret.public_key().to_sec1_point(false);
    let mut octets = [0_u8; PUBLIC_KEY_OCTETS];
    for (place, octet) in octets.iter_mut().zip(point.as_bytes()) {
        *place = *octet;
    }
    octets
}

/// La clef publique VAPID d'une clef privée — ce que le navigateur reçoit
/// comme `applicationServerKey`.
///
/// # Errors
///
/// [`Error::BadPrivateKey`].
pub fn vapid_public_key(cle: &[u8; PRIVATE_KEY_OCTETS]) -> Result<[u8; PUBLIC_KEY_OCTETS], Error> {
    let secret = p256::SecretKey::from_slice(cle).map_err(|_| Error::BadPrivateKey)?;
    Ok(publique(&secret))
}

/// Écrit la valeur du champ `Authorization` (RFC 8292 §3) :
/// `vapid t=<jwt>, k=<clef publique>`, et rend ce qu'elle occupe.
///
/// - `audience` est l'ORIGINE du service de push : `https://` et un hôte ;
/// - `expiration`, en secondes depuis l'époque — au plus vingt-quatre heures
///   devant (§2) ; c'est à l'appelant de la choisir ;
/// - `contact`, un `mailto:` ou une URL `https:` où l'exploitant se joint.
///
/// # UNE FORME ÉTROITE, PLUTÔT QU'UN ÉCHAPPEMENT
///
/// Les trois valeurs vont dans du JSON signé. Plutôt que de les échapper, on
/// n'admet que ce qu'une origine et une adresse portent : ni guillemet, ni
/// barre oblique inversée, ni octet de contrôle, ni rien hors de l'ASCII.
///
/// # Errors
///
/// [`Error::BadClaim`], [`Error::BadPrivateKey`], [`Error::BufferTooSmall`].
pub fn write_vapid(
    audience: &str,
    expiration: u64,
    contact: &str,
    cle: &[u8; PRIVATE_KEY_OCTETS],
    out: &mut [u8],
) -> Result<usize, Error> {
    let propre = |texte: &str| {
        !texte.is_empty()
            && texte.len() <= 255
            && texte
                .bytes()
                .all(|octet| (b' '..=b'~').contains(&octet) && !matches!(octet, b'"' | b'\\'))
    };
    let origine = audience
        .strip_prefix("https://")
        .is_some_and(|hote| !hote.is_empty() && !hote.contains('/'));
    let joignable = contact.starts_with("mailto:") || contact.starts_with("https:");
    if !(propre(audience) && propre(contact) && origine && joignable) {
        return Err(Error::BadClaim);
    }
    let signataire = p256::ecdsa::SigningKey::from_slice(cle).map_err(|_| Error::BadPrivateKey)?;

    // Les revendications en clair, puis encodées. Six cents octets bornent ce
    // que les deux textes de 255 octets au plus et un nombre peuvent faire.
    let mut claims = [0_u8; 600];
    let mut plume = Plume::neuve(&mut claims);
    plume.pousser(br#"{"aud":""#);
    plume.pousser(audience.as_bytes());
    plume.pousser(br#"","exp":"#);
    plume.nombre(expiration);
    plume.pousser(br#","sub":""#);
    plume.pousser(contact.as_bytes());
    plume.pousser(br#""}"#);
    let longueur = plume.ecrits;

    let mut plume = Plume::neuve(out);
    plume.pousser(b"vapid t=");
    signer_un_jwt(
        &mut plume,
        br#"{"typ":"JWT","alg":"ES256"}"#,
        claims.get(..longueur).unwrap_or_default(),
        &signataire,
    );
    plume.pousser(b", k=");
    plume.base64url(&publique(&p256::SecretKey::from(
        signataire.as_nonzero_scalar(),
    )));
    plume.fin()
}

/// Écrit un JWT ES256 : en-tête et revendications en base64url, puis la
/// signature (§3.4 de RFC 7518 : `r` et `s`, trente-deux octets chacun).
fn signer_un_jwt(
    plume: &mut Plume<'_>,
    entete: &[u8],
    revendications: &[u8],
    signataire: &p256::ecdsa::SigningKey,
) {
    use p256::ecdsa::signature::Signer as _;
    let debut = plume.ecrits;
    plume.base64url(entete);
    plume.pousser(b".");
    plume.base64url(revendications);
    let signe = plume.ecrits;
    let signature: p256::ecdsa::Signature =
        signataire.sign(plume.out.get(debut..signe).unwrap_or_default());
    plume.pousser(b".");
    plume.base64url(&signature.to_bytes());
}

/// Écrit la valeur du champ `authorization` d'APNs : `bearer <jwt>`, le jeton
/// de fournisseur qu'Apple exige (« token-based connection »).
///
/// `identifiant` est le Key ID de la clef `.p8`, `equipe` le Team ID du compte
/// de développeur, `emis` l'instant d'émission en secondes. Apple refuse un
/// jeton de plus d'une heure, et un jeton renouvelé plus souvent que toutes les
/// vingt minutes : c'est à l'appelant de le garder entre deux.
///
/// # Errors
///
/// [`Error::BadClaim`] si un identifiant n'est pas fait d'une à trente-deux
/// lettres et chiffres ASCII ; [`Error::BadPrivateKey`] ;
/// [`Error::BufferTooSmall`].
pub fn write_apns_token(
    identifiant: &str,
    equipe: &str,
    emis: u64,
    cle: &[u8; PRIVATE_KEY_OCTETS],
    out: &mut [u8],
) -> Result<usize, Error> {
    let propre = |texte: &str| {
        (1..=32).contains(&texte.len()) && texte.bytes().all(|octet| octet.is_ascii_alphanumeric())
    };
    if !(propre(identifiant) && propre(equipe)) {
        return Err(Error::BadClaim);
    }
    let signataire = p256::ecdsa::SigningKey::from_slice(cle).map_err(|_| Error::BadPrivateKey)?;
    let mut entete = [0_u8; 96];
    let mut plume = Plume::neuve(&mut entete);
    plume.pousser(br#"{"alg":"ES256","kid":""#);
    plume.pousser(identifiant.as_bytes());
    plume.pousser(br#""}"#);
    let longueur_entete = plume.ecrits;
    let mut claims = [0_u8; 96];
    let mut plume = Plume::neuve(&mut claims);
    plume.pousser(br#"{"iss":""#);
    plume.pousser(equipe.as_bytes());
    plume.pousser(br#"","iat":"#);
    plume.nombre(emis);
    plume.pousser(b"}");
    let longueur_claims = plume.ecrits;

    let mut plume = Plume::neuve(out);
    plume.pousser(b"bearer ");
    signer_un_jwt(
        &mut plume,
        entete.get(..longueur_entete).unwrap_or_default(),
        claims.get(..longueur_claims).unwrap_or_default(),
        &signataire,
    );
    plume.fin()
}

/// Lit une clef d'authentification APNs — le fichier `.p8` qu'Apple livre : une
/// `PRIVATE KEY` PKCS#8 (RFC 5958) en PEM, sur la courbe P-256.
///
/// # UNE LECTURE ÉTROITE
///
/// Seule la forme qu'Apple écrit passe : la version zéro, l'algorithme
/// `id-ecPublicKey` sur `prime256v1`, et une `ECPrivateKey` (RFC 5915) de
/// version un qui porte trente-deux octets. Rien d'autre n'est deviné.
///
/// # Errors
///
/// [`Error::BadKeyFile`] pour tout ce qui n'a pas cette forme ;
/// [`Error::BadPrivateKey`] si les trente-deux octets ne sont pas un scalaire.
pub fn decode_p8(pem: &[u8]) -> Result<[u8; PRIVATE_KEY_OCTETS], Error> {
    const DEBUT: &[u8] = b"-----BEGIN PRIVATE KEY-----";
    const FIN: &[u8] = b"-----END PRIVATE KEY-----";
    let apres = pem
        .windows(DEBUT.len())
        .position(|fenetre| fenetre == DEBUT)
        .and_then(|rang| pem.get(rang.saturating_add(DEBUT.len())..))
        .ok_or(Error::BadKeyFile)?;
    let corps = apres
        .windows(FIN.len())
        .position(|fenetre| fenetre == FIN)
        .and_then(|rang| apres.get(..rang))
        .ok_or(Error::BadKeyFile)?;
    let mut der = [0_u8; 256];
    let longueur = base64_standard(corps, &mut der)?;
    let der = der.get(..longueur).unwrap_or_default();

    // PrivateKeyInfo ::= SEQUENCE { version, algorithm, privateKey OCTET STRING }
    let (info, reste) = element(der, 0x30)?;
    if !reste.is_empty() {
        return Err(Error::BadKeyFile);
    }
    let (version, info) = element(info, 0x02)?;
    let (algorithme, info) = element(info, 0x30)?;
    let (cle_privee, _) = element(info, 0x04)?;
    // id-ecPublicKey (1.2.840.10045.2.1), prime256v1 (1.2.840.10045.3.1.7).
    const ALGORITHME: &[u8] = &[
        0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce,
        0x3d, 0x03, 0x01, 0x07,
    ];
    if version != [0] || algorithme != ALGORITHME {
        return Err(Error::BadKeyFile);
    }
    // ECPrivateKey ::= SEQUENCE { version 1, privateKey OCTET STRING, … }
    let (ec, _) = element(cle_privee, 0x30)?;
    let (version, ec) = element(ec, 0x02)?;
    let (scalaire, _) = element(ec, 0x04)?;
    let scalaire: [u8; PRIVATE_KEY_OCTETS] = scalaire.try_into().map_err(|_| Error::BadKeyFile)?;
    if version != [1] {
        return Err(Error::BadKeyFile);
    }
    p256::SecretKey::from_slice(&scalaire).map_err(|_| Error::BadPrivateKey)?;
    Ok(scalaire)
}

/// Un élément DER de cette étiquette : son contenu, et ce qui le suit.
fn element(der: &[u8], etiquette: u8) -> Result<(&[u8], &[u8]), Error> {
    let (&lue, reste) = der.split_first().ok_or(Error::BadKeyFile)?;
    let (&premier, reste) = reste.split_first().ok_or(Error::BadKeyFile)?;
    let (longueur, reste) = match premier {
        0..=0x7f => (usize::from(premier), reste),
        0x81 => {
            let (&un, reste) = reste.split_first().ok_or(Error::BadKeyFile)?;
            (usize::from(un), reste)
        }
        0x82 => {
            let (deux, reste) = reste.split_at_checked(2).ok_or(Error::BadKeyFile)?;
            let valeur = deux.iter().fold(0_usize, |acc, octet| {
                acc.saturating_mul(256).saturating_add(usize::from(*octet))
            });
            (valeur, reste)
        }
        _ => return Err(Error::BadKeyFile),
    };
    if lue != etiquette {
        return Err(Error::BadKeyFile);
    }
    reste.split_at_checked(longueur).ok_or(Error::BadKeyFile)
}

/// Décode du base64 STANDARD (§4 de RFC 4648), blancs ignorés, remplissage
/// admis à la fin seulement.
fn base64_standard(texte: &[u8], out: &mut [u8]) -> Result<usize, Error> {
    let valeur = |octet: u8| -> Option<u32> {
        let rang = match octet {
            b'A'..=b'Z' => octet.wrapping_sub(b'A'),
            b'a'..=b'z' => octet.wrapping_sub(b'a').wrapping_add(26),
            b'0'..=b'9' => octet.wrapping_sub(b'0').wrapping_add(52),
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        };
        Some(u32::from(rang))
    };
    let mut plume = Plume::neuve(out);
    let mut accumulateur = 0_u32;
    let mut bits = 0_u32;
    let mut fini = false;
    for octet in texte
        .iter()
        .copied()
        .filter(|octet| !octet.is_ascii_whitespace())
    {
        if octet == b'=' {
            fini = true;
            continue;
        }
        // Rien ne suit le remplissage.
        let six = valeur(octet).filter(|_| !fini).ok_or(Error::BadKeyFile)?;
        accumulateur = (accumulateur << 6 | six) & 0x00ff_ffff;
        bits = bits.saturating_add(6);
        if bits >= 8 {
            bits = bits.saturating_sub(8);
            plume.pousser(&[u8::try_from((accumulateur >> bits) & 0xff).unwrap_or(0)]);
        }
    }
    plume.fin().map_err(|_| Error::BadKeyFile)
}

/// Écrit `octets` en base64url sans remplissage (§5 de RFC 4648), et rend ce
/// que cela occupe.
///
/// # Errors
///
/// [`Error::BufferTooSmall`].
pub fn encode_base64url(octets: &[u8], out: &mut [u8]) -> Result<usize, Error> {
    let mut plume = Plume::neuve(out);
    plume.base64url(octets);
    plume.fin()
}

/// De quoi écrire dans un tampon fixe.
///
/// **L'ERREUR EST COLLANTE** : au premier débordement, plus rien ne s'écrit, et
/// [`Plume::fin`] le dit. Une écriture à moitié faite ne sort jamais.
struct Plume<'a> {
    out: &'a mut [u8],
    ecrits: usize,
    entier: bool,
}

impl<'a> Plume<'a> {
    fn neuve(out: &'a mut [u8]) -> Self {
        Self {
            out,
            ecrits: 0,
            entier: true,
        }
    }

    fn pousser(&mut self, octets: &[u8]) {
        let fin = self.ecrits.saturating_add(octets.len());
        match self.out.get_mut(self.ecrits..fin).filter(|_| self.entier) {
            Some(place) => {
                place.copy_from_slice(octets);
                self.ecrits = fin;
            }
            None => self.entier = false,
        }
    }

    /// Ce qui a été écrit, si tout a tenu.
    fn fin(self) -> Result<usize, Error> {
        match self.entier {
            true => Ok(self.ecrits),
            false => Err(Error::BufferTooSmall),
        }
    }

    /// Un nombre décimal.
    fn nombre(&mut self, valeur: u64) {
        let mut chiffres = [0_u8; 20];
        let mut reste = valeur;
        let mut debut = chiffres.len();
        loop {
            debut = debut.saturating_sub(1);
            // Vingt places bornent tout `u64` : la place existe toujours.
            chiffres.get_mut(debut).into_iter().for_each(|place| {
                *place = b'0'.wrapping_add(u8::try_from(reste % 10).unwrap_or(0))
            });
            reste /= 10;
            if reste == 0 {
                break;
            }
        }
        self.pousser(chiffres.get(debut..).unwrap_or_default());
    }

    /// Des octets en base64url, sans remplissage.
    fn base64url(&mut self, octets: &[u8]) {
        const ALPHABET: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let signe = |six: u32| {
            ALPHABET
                .get(usize::try_from(six & 63).unwrap_or(0))
                .copied()
                .unwrap_or(b'A')
        };
        for groupe in octets.chunks(3) {
            let a = u32::from(groupe.first().copied().unwrap_or(0));
            let b = u32::from(groupe.get(1).copied().unwrap_or(0));
            let c = u32::from(groupe.get(2).copied().unwrap_or(0));
            let bloc = (a << 16) | (b << 8) | c;
            let tous = [
                signe(bloc >> 18),
                signe(bloc >> 12),
                signe(bloc >> 6),
                signe(bloc),
            ];
            // Un octet en donne deux signes, deux en donnent trois.
            let utiles = groupe.len().saturating_add(1);
            self.pousser(tous.get(..utiles).unwrap_or_default());
        }
    }
}

#[cfg(test)]
mod tests;
