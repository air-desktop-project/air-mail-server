//! La signature à l'émission (RFC 6376 §5), **sans entrée-sortie**.
//!
//! # Signer, c'est écrire exactement ce que le vérificateur relira
//!
//! Un signataire et un vérificateur qui divergent d'un octet ne se le disent
//! jamais : les signatures échouent, et personne ne sait pourquoi. C'est
//! pourquoi ce module ne compose pas son propre condensat — **il écrit le champ,
//! le relit avec [`Signature::parse`], et le donne à condenser au même code que
//! la vérification**. Ce qui est signé ici est, par construction, ce que
//! [`crate::verify`] vérifiera.
//!
//! # Ce que ce module n'écrit PAS, et pourquoi
//!
//! **`l=`.** La borne de corps laisse ajouter ce qu'on veut après les `n`
//! premiers octets sans invalider la signature (RFC 6376 §8.2). Un message signé
//! avec `l=` peut donc arriver avec une pièce jointe que son auteur n'a jamais
//! écrite. La crate sait la LIRE — d'autres l'écrivent — mais elle n'en écrit
//! pas.
//!
//! **L'heure.** `t=` et `x=` viennent de l'appelant : cette crate n'a pas
//! d'horloge, et C1 dit pourquoi. Une machine à états qui consulterait l'heure
//! ne serait plus éprouvable à volonté.
//!
//! # Ce qu'il refuse d'écrire
//!
//! Une signature qui ne couvre pas `from`. La relecture par
//! [`Signature::parse`] la refuse, et cette relecture n'est pas une politesse :
//! elle est le seul endroit où l'on vérifie que ce qu'on vient d'écrire est ce
//! qu'on croit avoir écrit.

extern crate alloc;

use alloc::boxed::Box;
use alloc::vec::Vec;

use ed25519_dalek::Signer as _;
use rsa::RsaPrivateKey;
use rsa::pkcs1::DecodeRsaPrivateKey as _;
use rsa::pkcs1v15::Pkcs1v15Sign;
use rsa::pkcs8::DecodePrivateKey as _;
use rsa::pkcs8::EncodePublicKey as _;
use rsa::rand_core::TryCryptoRng;
use rsa::traits::SignatureScheme as _;
use sha2::Sha256;

use crate::base64::{condensat_en_base64, encoder_base64};
use crate::canonical::Canonicalization;
use crate::signature::Algorithm;
use crate::tag::est_valchar;
use crate::verify::{DIGEST_LEN, HeaderHasher, hash_signed_headers};
use crate::{Error, Signature};

/// Un tampon qui suffit toujours à un champ `DKIM-Signature`.
///
/// La signature d'une clé de 4096 bits fait 512 octets, soit 684 en base64 ; le
/// reste — domaine, sélecteur, liste des champs — tient largement dans ce qui
/// reste. Deux kibioctets majorent tout cela.
pub const SIGNATURE_FIELD_MAX: usize = 2048;

/// Le nom du champ, tel qu'il s'écrit.
const NOM: &[u8] = b"DKIM-Signature";

/// La longueur au-delà de laquelle on plie (RFC 5322 §2.1.1 : 78 recommandés).
const LIGNE_SOUHAITEE: usize = 78;

/// La longueur qu'une ligne ne peut pas dépasser.
const LIGNE_MAX: usize = 998;

/// Une clé privée, et de quoi signer avec.
///
/// # Elle n'est jamais affichée
///
/// Pas de `Debug` : une clé privée qui apparaît dans une trace n'est plus une
/// clé privée, et c'est le genre de fuite qu'on ne remarque qu'après.
pub enum SigningKey {
    /// RSA (RFC 6376 §3.3.3).
    Rsa(Box<RsaPrivateKey>),
    /// Ed25519 (RFC 8463).
    Ed25519(Box<ed25519_dalek::SigningKey>),
}

impl SigningKey {
    /// Lit une clé privée au format PEM, telle qu'un administrateur en écrit.
    ///
    /// # C'EST L'ÉTIQUETTE QUI DIT LE FORMAT, ET NON UNE DEVINETTE
    ///
    /// `BEGIN PRIVATE KEY` est du PKCS#8, `BEGIN RSA PRIVATE KEY` du PKCS#1.
    /// Essayer l'un puis l'autre marcherait aussi, et masquerait une clé
    /// abîmée derrière un second essai qui échoue pour une autre raison. On
    /// lit ce que le fichier DÉCLARE être.
    ///
    /// # Errors
    ///
    /// [`Error::MalformedKey`] si le PEM ne se lit pas, si son étiquette est
    /// inconnue, ou si ce qu'il porte n'est pas une clé.
    pub fn from_pem(pem: &[u8]) -> Result<Self, Error> {
        let (etiquette, corps) = bornes_pem(pem).ok_or(Error::MalformedKey)?;
        // LA TAILLE VIENT DU FICHIER : elle sert à BORNER, jamais à réserver
        // (C3). Une RSA de 8 192 bits tient dans quatre kibioctets de DER.
        let mut der = [0_u8; CLE_DER_MAX];
        let ecrits = crate::base64::decoder_base64(corps, &mut der)?;
        let der = der.get(..ecrits).unwrap_or_default();
        if etiquette == b"RSA PRIVATE KEY" {
            return RsaPrivateKey::from_pkcs1_der(der)
                .map(|cle| Self::Rsa(Box::new(cle)))
                .map_err(|_| Error::MalformedKey);
        }
        if etiquette != b"PRIVATE KEY" {
            return Err(Error::MalformedKey);
        }
        // Une clé Ed25519 en PKCS#8 v1 tient en quarante-huit octets, dont un
        // préfixe qui ne varie pas : le reconnaître exactement vaut mieux que
        // de lire un OID à la main pour s'en assurer.
        if let Some(graine) = der
            .strip_prefix(&ED25519_PKCS8)
            .and_then(|reste| <[u8; 32]>::try_from(reste).ok())
        {
            return Ok(Self::ed25519_from_seed(&graine));
        }
        Self::rsa_from_pkcs8_der(der)
    }

    /// Lit une clé RSA au format PKCS#8 (`BEGIN PRIVATE KEY`), en DER.
    ///
    /// # Errors
    ///
    /// [`Error::MalformedKey`] si le DER n'est pas une clé RSA lisible.
    pub fn rsa_from_pkcs8_der(der: &[u8]) -> Result<Self, Error> {
        RsaPrivateKey::from_pkcs8_der(der)
            .map(|cle| Self::Rsa(Box::new(cle)))
            .map_err(|_| Error::MalformedKey)
    }

    /// Lit une clé Ed25519 depuis sa **graine** de 32 octets.
    #[must_use]
    pub fn ed25519_from_seed(graine: &[u8; 32]) -> Self {
        Self::Ed25519(Box::new(ed25519_dalek::SigningKey::from_bytes(graine)))
    }

    /// L'enregistrement TXT à publier pour cette clé (RFC 6376 §3.6.1).
    ///
    /// Rend `v=DKIM1; k=…; p=…`, prêt à coller dans une zone.
    ///
    /// # POURQUOI CE SERVEUR LE COMPOSE, ET NE LAISSE PAS LE FAIRE
    ///
    /// Il disait à son exploitant OÙ publier — `<sélecteur>._domainkey.<domaine>`
    /// — et pas QUOI. Il fallait donc dériver la clé publique à la main :
    /// `openssl pkey -pubout`, retirer l'en-tête PEM, recoller les lignes,
    /// préfixer les étiquettes. Quatre étapes, quatre occasions de se tromper.
    ///
    /// **Et une erreur y est PIRE que l'absence de signature** : un
    /// enregistrement faux fait échouer TOUTES nos signatures, ce qui se lit
    /// dans les rapports DMARC du domaine comme un échec d'authentification.
    /// Ce serveur détient la seule information qui rend l'étape sûre ; la garder
    /// serait faire porter le risque à celui qui n'a pas les moyens de le
    /// réduire.
    ///
    /// # LES DEUX TYPES DE CLÉ NE SE PUBLIENT PAS PAREIL
    ///
    /// §3.6.1 veut un `SubjectPublicKeyInfo` pour RSA — la clé et son type,
    /// encodés en DER. §3 de RFC 8463 veut au contraire la clé **NUE** pour
    /// Ed25519, trente-deux octets et rien d'autre. Publier l'une à la façon de
    /// l'autre donne un enregistrement qu'aucun vérificateur ne lira.
    ///
    /// Le lecteur de ce dépôt connaît déjà cette différence ; l'écrivain la
    /// connaît désormais aussi, et les deux sont côte à côte.
    ///
    /// # CETTE COMPOSITION NE PEUT PAS ÉCHOUER
    ///
    /// Une clé privée que `from_pem` a acceptée porte une partie publique qui
    /// s'encode, et le tampon de base64 est dimensionné par construction — quatre
    /// tiers suffisent, on en prend quatre. Rendre un `Result` ouvrirait deux
    /// branches que rien ne pourrait emprunter, chez nous comme chez l'appelant.
    #[must_use]
    pub fn public_record(&self) -> Vec<u8> {
        let (genre, brut): (&[u8], Vec<u8>) = match self {
            Self::Rsa(privee) => {
                let publique = rsa::RsaPublicKey::from(privee.as_ref());
                let der = publique
                    .to_public_key_der()
                    .expect("une clé privée lisible a une partie publique encodable");
                (b"rsa", der.as_bytes().to_vec())
            }
            // **LA CLÉ NUE, ET NON UN `SubjectPublicKeyInfo`** (RFC 8463 §3).
            Self::Ed25519(privee) => (b"ed25519", privee.verifying_key().to_bytes().to_vec()),
        };
        // Un enregistrement DNS ne se plie pas : `largeur` à zéro n'insère aucun
        // repli, et c'est ce qu'il faut ici — le pliage de RFC 5322 vit dans un
        // en-tête de message, pas dans une zone.
        let mut place = alloc::vec![0_u8; brut.len().saturating_mul(4).saturating_add(64)];
        let encodee = encoder_base64(&brut, 0, &mut place)
            .expect("quatre fois la longueur majore quatre tiers")
            .to_vec();

        let mut record = Vec::with_capacity(encodee.len().saturating_add(32));
        record.extend_from_slice(b"v=DKIM1; k=");
        record.extend_from_slice(genre);
        record.extend_from_slice(b"; p=");
        record.extend_from_slice(&encodee);
        record
    }

    /// L'algorithme que cette clé impose.
    #[must_use]
    pub fn algorithm(&self) -> Algorithm {
        match self {
            Self::Rsa(_) => Algorithm::RsaSha256,
            Self::Ed25519(_) => Algorithm::Ed25519Sha256,
        }
    }

    /// Signe un condensat.
    ///
    /// # RSA sans aveuglement, et ce que cela coûte
    ///
    /// L'aveuglement protège la clé contre les attaques par mesure du temps ou
    /// par faute. Il demande de l'aléa, que cette crate n'a pas — C1 — et c'est
    /// pourquoi [`SigningKey::sign_with`] existe : **un serveur qui signe le
    /// courrier d'autrui doit l'employer**. Celle-ci reste, parce qu'Ed25519 n'a
    /// besoin de rien et qu'une signature déterministe est ce qu'une épreuve
    /// peut comparer.
    ///
    /// # Errors
    ///
    /// [`Error::SignatureMismatch`] si la clé refuse de signer.
    pub fn sign(&self, digest: &[u8; DIGEST_LEN]) -> Result<Vec<u8>, Error> {
        match self {
            Self::Rsa(cle) => Pkcs1v15Sign::new::<Sha256>()
                .sign(None::<&mut Jamais>, cle, digest)
                .map_err(|_| Error::SignatureMismatch),
            Self::Ed25519(cle) => Ok(cle.sign(digest).to_bytes().to_vec()),
        }
    }

    /// Signe un condensat, **avec aveuglement** quand la clé est RSA.
    ///
    /// L'aléa vient de l'appelant : c'est lui qui en a une source, et cette
    /// crate n'en aura jamais.
    ///
    /// # Errors
    ///
    /// [`Error::SignatureMismatch`] si la clé refuse de signer.
    pub fn sign_with<R>(&self, digest: &[u8; DIGEST_LEN], alea: &mut R) -> Result<Vec<u8>, Error>
    where
        R: TryCryptoRng + ?Sized,
    {
        match self {
            Self::Rsa(cle) => Pkcs1v15Sign::new::<Sha256>()
                .sign(Some(alea), cle, digest)
                .map_err(|_| Error::SignatureMismatch),
            Self::Ed25519(cle) => Ok(cle.sign(digest).to_bytes().to_vec()),
        }
    }
}

/// Ce qu'une clé privée occupe au plus, en DER.
///
/// **Aucune RFC ne le borne.** Une RSA de 8 192 bits en occupe un peu moins de
/// quatre ; le double laisse de la place sans en offrir à qui écrirait un
/// fichier immense.
const CLE_DER_MAX: usize = 8 * 1024;

/// Le préfixe d'une clé Ed25519 en PKCS#8 v1 (RFC 8410 §7).
///
/// `SEQUENCE { INTEGER 0, SEQUENCE { OID 1.3.101.112 }, OCTET STRING { OCTET
/// STRING (32) } }` : les seize octets ne varient pas, les trente-deux suivants
/// sont la graine.
const ED25519_PKCS8: [u8; 16] = [
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
];

/// L'étiquette et le corps d'un bloc PEM.
fn bornes_pem(pem: &[u8]) -> Option<(&[u8], &[u8])> {
    const OUVERTURE: &[u8] = b"-----BEGIN ";
    const TIRETS: &[u8] = b"-----";
    // TROIS REFUS, ET TROIS SEULEMENT : pas d'ouverture, pas de fin
    // d'étiquette, pas de fermeture. Tout le reste se découpe à des rangs que
    // la recherche vient de rendre, donc sans refus possible — un `?` de plus
    // serait une garde qu'aucun fichier ne pourrait faire céder.
    let debut = trouver(pem, OUVERTURE)?.saturating_add(OUVERTURE.len());
    let reste = pem.get(debut..).unwrap_or_default();
    let fin_etiquette = trouver(reste, TIRETS)?;
    let etiquette = reste.get(..fin_etiquette).unwrap_or_default();
    let corps = reste
        .get(fin_etiquette.saturating_add(TIRETS.len())..)
        .unwrap_or_default();
    let fin_corps = trouver(corps, b"-----END ")?;
    Some((etiquette, corps.get(..fin_corps).unwrap_or_default()))
}

/// Le rang où `aiguille` commence dans `botte`.
fn trouver(botte: &[u8], aiguille: &[u8]) -> Option<usize> {
    botte
        .windows(aiguille.len())
        .position(|fenetre| fenetre == aiguille)
}

/// Un aléa qui n'existe pas, et qu'on ne demande jamais.
///
/// `Option<&mut R>` veut un type même quand la valeur est `None` : celui-ci en
/// est un, et ses méthodes ne sont appelées par personne — c'est précisément ce
/// que `None` veut dire.
struct Jamais;

/// L'erreur qu'un aléa inexistant rendrait s'il était appelé.
#[derive(Debug)]
struct PasDAlea;

impl core::fmt::Display for PasDAlea {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("cette crate n'a pas de source d'aléa")
    }
}

impl core::error::Error for PasDAlea {}

impl rsa::rand_core::TryRng for Jamais {
    type Error = PasDAlea;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        Err(PasDAlea)
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        Err(PasDAlea)
    }

    fn try_fill_bytes(&mut self, _dst: &mut [u8]) -> Result<(), Self::Error> {
        Err(PasDAlea)
    }
}

impl TryCryptoRng for Jamais {}

/// Ce qu'une signature doit dire.
#[derive(Debug, Clone, Copy)]
pub struct Signer<'a> {
    /// `d=` — le domaine qui signe.
    pub domain: &'a [u8],
    /// `s=` — le sélecteur, qui nomme la clé dans le DNS.
    pub selector: &'a [u8],
    /// `c=` — ce qui sera signé, exactement.
    pub canonicalization: Canonicalization,
    /// `h=` — les noms des champs à couvrir, **dans l'ordre**.
    ///
    /// `from` doit en faire partie : sans lui, la signature ne dit rien de
    /// l'auteur, et la relecture refuse d'écrire un champ pareil.
    pub headers: &'a [&'a [u8]],
    /// `t=` — quand la signature est posée. L'appelant a l'horloge.
    pub timestamp: Option<u64>,
    /// `x=` — quand elle cesse de valoir.
    pub expiration: Option<u64>,
    /// `i=` — l'identité de l'agent signataire, si on veut la dire.
    pub identity: Option<&'a [u8]>,
}

impl Signer<'_> {
    /// Écrit le champ `DKIM-Signature`, `CRLF` final compris.
    ///
    /// `body` est le condensat rendu par [`crate::BodyHasher::finish`] sur le
    /// corps du message, canonicalisé comme [`Signer::canonicalization`] le dit.
    /// `fields` porte les champs du message, **du haut vers le bas**, sous la
    /// forme `(nom, valeur brute)` — exactement ce que rend `ams_mime::Field`.
    ///
    /// # Une tranche, et pas une fermeture
    ///
    /// Le vérificateur, lui, prend une fermeture : il ne peut pas retenir les
    /// champs, et doit les reparcourir. Le signataire, lui, les a déjà — c'est
    /// LUI qui compose le message. Une tranche suffit donc, et elle évite à
    /// cette fonction d'être générique : une fonction générique est recopiée
    /// une fois par appelant, et chaque copie porte ses propres chemins
    /// d'erreur, dont aucun appelant n'emprunte la totalité.
    ///
    /// # Errors
    ///
    /// [`Error::BufferTooSmall`] si `out` ne suffit pas ; [`Error::FromNotSigned`]
    /// si `h=` ne nomme pas `from` ; les autres erreurs de lecture si ce qu'on
    /// vient d'écrire ne se relit pas.
    pub fn sign<'b>(
        &self,
        key: &SigningKey,
        body: &[u8; DIGEST_LEN],
        fields: &[(&[u8], &[u8])],
        out: &'b mut [u8],
    ) -> Result<&'b [u8], Error> {
        self.composer_et_sceller(key.algorithm(), body, fields, out, |condensat| {
            key.sign(condensat)
        })
    }

    /// La même chose, **avec aveuglement** quand la clé est RSA.
    ///
    /// # C'EST CELLE-CI QU'UN SERVEUR EMPLOIE
    ///
    /// L'aveuglement protège la clé contre les attaques par mesure du temps et
    /// par faute. Un serveur qui signe à la demande — et le nôtre signe ce
    /// qu'il émet — donne à qui l'observe autant de mesures qu'il veut.
    /// [`Signer::sign`] reste, parce qu'Ed25519 n'a besoin de rien et qu'une
    /// signature déterministe est ce qu'une épreuve peut comparer.
    ///
    /// # Errors
    ///
    /// Les mêmes que [`Signer::sign`].
    pub fn sign_with<'b, R>(
        &self,
        key: &SigningKey,
        body: &[u8; DIGEST_LEN],
        fields: &[(&[u8], &[u8])],
        alea: &mut R,
        out: &'b mut [u8],
    ) -> Result<&'b [u8], Error>
    where
        R: TryCryptoRng + ?Sized,
    {
        self.composer_et_sceller(key.algorithm(), body, fields, out, |condensat| {
            key.sign_with(condensat, alea)
        })
    }

    /// Compose le champ, le relit, et le scelle avec ce que `sceller` rend.
    fn composer_et_sceller<'b>(
        &self,
        algorithme: Algorithm,
        body: &[u8; DIGEST_LEN],
        fields: &[(&[u8], &[u8])],
        out: &'b mut [u8],
        sceller: impl FnOnce(&[u8; DIGEST_LEN]) -> Result<Vec<u8>, Error>,
    ) -> Result<&'b [u8], Error> {
        // ── 0. CE QU'ON NOUS DONNE DOIT POUVOIR S'ÉCRIRE ────────────────────
        //
        // Un `d=` qui porterait un `CRLF` terminerait l'en-tête et en ouvrirait
        // un autre : c'est l'injection d'en-tête, et elle se ferme ici. Le
        // fuzzing l'a trouvée en donnant au signataire un domaine fait de deux
        // points et de sauts de ligne.
        for valeur in [self.domain, self.selector]
            .into_iter()
            .chain(self.identity)
        {
            if valeur.is_empty() || !valeur.iter().copied().all(est_valchar) {
                return Err(Error::MalformedTagValue);
            }
        }
        // Les noms de champ, eux, suivent `ftext` (RFC 5322 §3.6.8) : ni blanc,
        // ni deux-points — celui-ci les sépare.
        for nom in self.headers {
            if nom.is_empty() || !nom.iter().all(|octet| est_ftext(*octet)) {
                return Err(Error::MalformedTagValue);
            }
        }

        // ── 1. Le champ, `b=` VIDE et en dernier ────────────────────────────
        //
        // En dernier, parce que ce qui vient après lui n'est pas condensé : la
        // signature s'y ajoutera sans rien déplacer.
        let jusqu_au_b = self.composer(algorithme, body, out)?;

        // ── 2. On RELIT ce qu'on vient d'écrire ─────────────────────────────
        //
        // Ce n'est pas une politesse : c'est le seul endroit où l'on vérifie que
        // le champ écrit est celui qu'on croit avoir écrit — et c'est la
        // relecture qui refuse une signature qui ne couvre pas `from`.
        let scellee = {
            // `unwrap_or_default` partout : `jusqu_au_b` est ce qu'on VIENT
            // d'écrire, et le nom du champ suivi de son deux-points est ce qu'on
            // a écrit en premier. Trois tranches qui ne peuvent pas manquer.
            let champ = out.get(..jusqu_au_b).unwrap_or_default();
            let valeur = champ.get(NOM.len().saturating_add(1)..).unwrap_or_default();
            let signature = Signature::parse(valeur)?;

            let mut condensat = HeaderHasher::new(self.canonicalization.header);
            hash_signed_headers(&signature, &mut condensat, || fields.iter().copied());
            // Le `b=` qu'on vient d'écrire est DÉJÀ vide : il n'y a rien à en
            // retirer, et donc aucune raison que cette écriture-là échoue.
            condensat.written_signature_field(NOM, valeur);
            sceller(&condensat.finish())?
        };

        // ── 3. La signature, pliée, puis la fin de ligne ────────────────────
        let reste = out.get_mut(jusqu_au_b..).unwrap_or_default();
        let ecrits = encoder_base64(&scellee, 64, reste)?.len();
        let fin = jusqu_au_b.saturating_add(ecrits);
        let queue = out
            .get_mut(fin..fin.saturating_add(2))
            .ok_or(Error::BufferTooSmall)?;
        queue.copy_from_slice(b"\r\n");
        out.get(..fin.saturating_add(2))
            .ok_or(Error::BufferTooSmall)
    }

    /// Écrit le champ jusqu'au `b=` inclus, et rend où il s'arrête.
    fn composer(
        &self,
        algorithme: Algorithm,
        body: &[u8; DIGEST_LEN],
        out: &mut [u8],
    ) -> Result<usize, Error> {
        let condensat = condensat_en_base64(body);
        let algorithme: &[u8] = match algorithme {
            Algorithm::RsaSha256 => b"rsa-sha256",
            Algorithm::Ed25519Sha256 => b"ed25519-sha256",
        };

        let mut plume = Plume::neuve(out);
        plume.pousser(NOM)?;
        plume.pousser(b":")?;
        plume.etiquette(b"v=", b"1")?;
        plume.etiquette(b"a=", algorithme)?;
        // `c=` s'écrit TOUJOURS, même quand c'est le défaut : le lire sur le
        // champ vaut mieux que le déduire d'une absence.
        plume.plier_si_besoin(20)?;
        plume.pousser(b"c=")?;
        plume.pousser(self.canonicalization.header.name())?;
        plume.pousser(b"/")?;
        plume.pousser(self.canonicalization.body.name())?;
        plume.pousser(b";")?;
        plume.etiquette(b"d=", self.domain)?;
        plume.etiquette(b"s=", self.selector)?;
        if let Some(pose) = self.timestamp {
            let mut chiffres = [0_u8; 20];
            plume.etiquette(b"t=", decimal(pose, &mut chiffres))?;
        }
        if let Some(fin) = self.expiration {
            let mut chiffres = [0_u8; 20];
            plume.etiquette(b"x=", decimal(fin, &mut chiffres))?;
        }
        if let Some(agent) = self.identity {
            plume.etiquette(b"i=", agent)?;
        }

        // `h=` : les noms, séparés par des deux-points, pliés au besoin.
        plume.plier_si_besoin(2)?;
        plume.pousser(b"h=")?;
        for (rang, nom) in self.headers.iter().enumerate() {
            if rang > 0 {
                plume.pousser(b":")?;
            }
            plume.pousser(nom)?;
        }
        plume.pousser(b";")?;

        plume.etiquette(b"bh=", &condensat)?;
        plume.plier_si_besoin(2)?;
        plume.pousser(b"b=")?;
        Ok(plume.fini())
    }
}

/// Un octet de nom de champ (RFC 5322 §3.6.8, `ftext`).
fn est_ftext(octet: u8) -> bool {
    (33..=126).contains(&octet) && octet != b':'
}

/// De quoi écrire un champ plié, sans jamais dépasser une ligne.
struct Plume<'a> {
    out: &'a mut [u8],
    ecrits: usize,
    ligne: usize,
}

impl<'a> Plume<'a> {
    fn neuve(out: &'a mut [u8]) -> Self {
        Self {
            out,
            ecrits: 0,
            ligne: 0,
        }
    }

    fn pousser(&mut self, morceau: &[u8]) -> Result<(), Error> {
        let fin = self.ecrits.saturating_add(morceau.len());
        let place = self
            .out
            .get_mut(self.ecrits..fin)
            .ok_or(Error::BufferTooSmall)?;
        place.copy_from_slice(morceau);
        self.ecrits = fin;
        // LA BORNE DES 998 EST VÉRIFIÉE, PAS SUPPOSÉE. Un en-tête plus long
        // qu'une ligne se fait couper en aval, là où personne ne décide — et un
        // champ coupé n'est plus le champ qu'on a signé.
        if self.ecrits.saturating_sub(self.ligne) > LIGNE_MAX {
            return Err(Error::BufferTooSmall);
        }
        Ok(())
    }

    /// Plie si ce qui vient ne tient pas sur la ligne recommandée.
    fn plier_si_besoin(&mut self, longueur: usize) -> Result<(), Error> {
        let courante = self.ecrits.saturating_sub(self.ligne);
        if courante.saturating_add(longueur) > LIGNE_SOUHAITEE {
            self.pousser(b"\r\n")?;
            self.ligne = self.ecrits;
            return self.pousser(b" ");
        }
        self.pousser(b" ")
    }

    /// Une étiquette entière : `nom=valeur;`, pliée si elle ne tient plus.
    fn etiquette(&mut self, nom: &[u8], valeur: &[u8]) -> Result<(), Error> {
        self.plier_si_besoin(nom.len().saturating_add(valeur.len()).saturating_add(1))?;
        self.pousser(nom)?;
        self.pousser(valeur)?;
        self.pousser(b";")
    }

    fn fini(self) -> usize {
        self.ecrits
    }
}

/// Écrit un entier en décimal.
fn decimal(valeur: u64, tampon: &mut [u8; 20]) -> &[u8] {
    let mut reste = valeur;
    let mut rang = tampon.len();
    loop {
        rang = rang.saturating_sub(1);
        let chiffre = u8::try_from(reste % 10).unwrap_or(0);
        // `rang` part de la longueur du tampon et décroît AVANT d'être employé :
        // l'indexation est totale, et le dire ainsi évite une garde qu'aucun
        // nombre ne pourrait emprunter.
        tampon[rang] = b'0'.saturating_add(chiffre);
        reste /= 10;
        if reste == 0 || rang == 0 {
            break;
        }
    }
    tampon.get(rang..).unwrap_or_default()
}

#[cfg(test)]
mod tests;
