// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Ce qu'une session retient entre les deux allers-retours de SCRAM.
//!
//! # POURQUOI CE MODULE EST SI PETIT, ET CE QU'IL NE FAIT PAS
//!
//! La session **encadre**, elle ne calcule pas. SCRAM tient en deux échanges :
//! le pair envoie son `client-first`, le serveur répond un `server-first`, le
//! pair envoie son `client-final`, le serveur conclut. Entre les deux, il faut
//! se souvenir de DEUX choses — le `client-first-bare` et le `server-first` —
//! parce que le `AuthMessage` de §3 est leur concaténation avec le
//! `client-final` amputé de sa preuve.
//!
//! Tout le reste — le sel, les itérations, PBKDF2, la comparaison — appartient
//! à la politique, qui seule a le magasin et la clé de scellement. Ce module ne
//! sait même pas si un compte existe.
//!
//! # POURQUOI DES TAMPONS FIXES, ET CES TAILLES-LÀ
//!
//! C3 : pas d'allocation. Une session vit par connexion, et un pair non
//! authentifié ne doit pas pouvoir en faire grossir une. Les deux messages ont
//! une forme connue — un nom de compte, deux nonces, un sel en base64, un
//! nombre — et [`BARE_MAX`] comme [`FIRST_MAX`] les couvrent largement. Ce qui
//! déborde est REFUSÉ, jamais tronqué : un `AuthMessage` amputé ne
//! correspondrait à rien, et le pair verrait « mot de passe faux » là où il
//! faudrait lire « votre nom de compte est trop long ».

/// Le serveur et le client SCRAM que les bancs des deux sessions jouent.
///
/// Il vit ICI, et non dans le module d'essais de l'une des deux : SMTP et IMAP
/// conduisent le MÊME échange, et deux politiques d'essai feraient deux fois la
/// même arithmétique.
#[cfg(test)]
pub(crate) mod banc;

/// Le `n=` d'un `client-first-bare`, **encore échappé**.
///
/// La session ne déséchappe pas : `=2C` et `=3D` ne peuvent apparaître que dans
/// un nom qui porte une virgule ou un égal, et `check_login` refuse déjà le
/// premier. Ce qui sort d'ici va à `canonical_login`, qui compare à des noms de
/// comptes — lesquels n'en portent pas davantage.
///
/// **LES DEUX SESSIONS LE LISENT** : SMTP et IMAP tirent le nom du même
/// endroit, et deux copies de cette lecture finiraient par ne plus désigner la
/// même boîte.
pub fn nom_du_bare(bare: &[u8]) -> &[u8] {
    let apres = bare
        .get(..2)
        .filter(|debut| *debut == b"n=")
        .and_then(|_| bare.get(2..))
        .unwrap_or_default();
    match apres.iter().position(|octet| *octet == b',') {
        Some(rang) => apres.get(..rang).unwrap_or_default(),
        None => apres,
    }
}

/// Ce qu'un `client-first-bare` peut occuper.
///
/// `n=<compte>,r=<nonce>` : un nom de compte est borné à soixante-quatre octets
/// par `check_login`, un nonce de client tient en quelques dizaines. Le double
/// laisse la place aux extensions que §5 permet et qu'on ignore.
pub const BARE_MAX: usize = 256;

/// Ce qu'un `server-first` peut occuper.
///
/// `r=<les deux nonces>,s=<sel en base64>,i=<nombre>` : les deux nonces, vingt-
/// quatre octets de sel encodés, et cinq chiffres.
pub const FIRST_MAX: usize = 256;

/// Cet en-tête GS2 va-t-il avec le mécanisme choisi ? (§6 de RFC 5802.)
///
/// # LES QUATRE CAS, ET CELUI QUI COMPTE
///
/// - `-PLUS` avec `p=` : c'est l'échange attendu, le `c=` sera vérifié ;
/// - `-PLUS` sans `p=` : le client a choisi de lier puis ne lie pas. Refus ;
/// - sans `-PLUS` avec `p=` : il lie sur un mécanisme qui ne lie pas, et le
///   `c=` qu'il calculera ne correspondra à rien d'attendu. Refus ;
/// - **sans `-PLUS` avec `y,,`, ALORS QU'ON A ANNONCÉ `-PLUS`** : c'est LA
///   rétrogradation que §6 fait détecter. `y` veut dire « je sais lier,
///   mais tu ne sais pas » ; si l'on sait, c'est qu'un tiers a retiré
///   l'annonce du fil entre nous. Refus, et c'est tout l'intérêt de `y`.
///
/// Le dernier cas — `n,,` ou `y,,` sur un canal qui ne se lie pas — est
/// celui d'un client honnête, et passe.
#[must_use]
pub fn entete_recevable(plus: bool, gs2: ams_sasl::Gs2, canal_liable: bool) -> bool {
    match (plus, gs2) {
        (true, ams_sasl::Gs2::Liee) | (false, ams_sasl::Gs2::SansLiaison) => true,
        (true, _) | (false, ams_sasl::Gs2::Liee) => false,
        (false, ams_sasl::Gs2::LiaisonRefusee) => !canal_liable,
    }
}

/// Le `c=` du `client-final` porte-t-il ce qu'il doit ? (§6.)
///
/// **LA COMPARAISON EST À TEMPS CONSTANT**, parce qu'un des deux côtés
/// contient les octets de l'exportateur : une comparaison qui s'arrête au
/// premier octet différent les livrerait un par un à qui sait mesurer.
#[must_use]
pub fn liaison_verifiee(
    etat: &EtatScram,
    liaison: Option<[u8; ams_sasl::LIAISON_OCTETS]>,
    client_final: &[u8],
) -> bool {
    // Un `c=` légitime fait au plus quarante-huit octets — l'en-tête le
    // plus long, et les trente-deux de la liaison. Ce qui déborde ne peut
    // pas correspondre, et se refuse donc au décodage.
    let mut lue = [0_u8; ENTETE_MAX + ams_sasl::LIAISON_OCTETS];
    let Ok(lu) = ams_sasl::parse_client_final(client_final, &mut lue) else {
        return false;
    };
    let (place, fin) = etat.liaison_attendue(&liaison.unwrap_or_default());
    ams_sasl::egales(lu.channel_binding, place.get(..fin).unwrap_or_default())
}

/// Ce qu'un en-tête GS2 peut occuper.
///
/// §5.1 n'en permet que trois formes, et la plus longue — `p=tls-exporter,,` —
/// fait seize octets. Trente-deux laissent la place sans rien promettre.
pub const ENTETE_MAX: usize = 32;

/// Les trois choses qu'il faut avoir gardées pour conclure.
#[derive(Debug, Clone, Copy)]
pub struct EtatScram {
    /// L'en-tête GS2, TEL QUE LE PAIR L'A ÉCRIT.
    ///
    /// **IL SE COMPARE, OCTET POUR OCTET, À CE QUE LE `c=` PORTE** (§6) : le
    /// pair y renvoie son propre en-tête, et un tiers qui aurait retiré
    /// `-PLUS` de l'annonce laisserait les deux se contredire. Le recomposer
    /// ici plutôt que le retenir reviendrait à comparer ce qu'on croit avoir
    /// lu à ce qu'on croit avoir lu.
    entete: [u8; ENTETE_MAX],
    entete_len: usize,
    /// Le pair a-t-il lié le canal (`p=`) ?
    liee: bool,
    bare: [u8; BARE_MAX],
    bare_len: usize,
    first: [u8; FIRST_MAX],
    first_len: usize,
}

impl EtatScram {
    /// Retient ce qu'il faut, ou refuse si cela ne tient pas.
    ///
    /// **REFUSER PLUTÔT QUE TRONQUER** : un `AuthMessage` amputé donnerait une
    /// preuve fausse, et le pair lirait « mot de passe invalide » pour un nom
    /// de compte trop long. Le refus, lui, se diagnostique.
    #[must_use]
    pub fn neuf(entete: &[u8], liee: bool, bare: &[u8], first: &[u8]) -> Option<Self> {
        if entete.len() > ENTETE_MAX || bare.len() > BARE_MAX || first.len() > FIRST_MAX {
            return None;
        }
        let mut etat = Self {
            entete: [0; ENTETE_MAX],
            entete_len: entete.len(),
            liee,
            bare: [0; BARE_MAX],
            bare_len: bare.len(),
            first: [0; FIRST_MAX],
            first_len: first.len(),
        };
        etat.entete
            .get_mut(..entete.len())
            .unwrap_or_default()
            .copy_from_slice(entete);
        etat.bare
            .get_mut(..bare.len())
            .unwrap_or_default()
            .copy_from_slice(bare);
        etat.first
            .get_mut(..first.len())
            .unwrap_or_default()
            .copy_from_slice(first);
        Some(etat)
    }

    /// L'en-tête GS2 retenu.
    #[must_use]
    pub fn entete(&self) -> &[u8] {
        self.entete.get(..self.entete_len).unwrap_or_default()
    }

    /// Le pair a-t-il lié le canal ?
    #[must_use]
    pub const fn liee(&self) -> bool {
        self.liee
    }

    /// Ce que le `c=` du `client-final` DOIT porter (§6), et sa longueur.
    ///
    /// L'en-tête GS2 tel quel, suivi des octets de liaison si le pair a lié.
    ///
    /// # POURQUOI UN TABLEAU PLUTÔT QU'UN TAMPON DONNÉ
    ///
    /// **AUCUN ÉTAT NE PEUT FAIRE DÉBORDER CELUI-CI** : l'en-tête est borné à
    /// [`ENTETE_MAX`] par [`EtatScram::neuf`], la liaison fait exactement
    /// `LIAISON_OCTETS`, et le tableau porte la somme des deux. Un tampon
    /// fourni par l'appelant aurait ouvert un « et s'il est trop court » que
    /// rien ne peut atteindre — et C2 compte ces branches-là comme découvertes
    /// pour toujours.
    #[must_use]
    pub fn liaison_attendue(
        &self,
        liaison: &[u8; ams_sasl::LIAISON_OCTETS],
    ) -> ([u8; ENTETE_MAX + ams_sasl::LIAISON_OCTETS], usize) {
        let mut place = [0_u8; ENTETE_MAX + ams_sasl::LIAISON_OCTETS];
        place
            .get_mut(..self.entete_len)
            .unwrap_or_default()
            .copy_from_slice(self.entete());
        if !self.liee {
            return (place, self.entete_len);
        }
        let fin = self.entete_len.saturating_add(ams_sasl::LIAISON_OCTETS);
        place
            .get_mut(self.entete_len..fin)
            .unwrap_or_default()
            .copy_from_slice(liaison);
        (place, fin)
    }

    /// Le `client-first-bare` retenu.
    #[must_use]
    pub fn bare(&self) -> &[u8] {
        self.bare.get(..self.bare_len).unwrap_or_default()
    }

    /// Le `server-first` retenu.
    #[must_use]
    pub fn first(&self) -> &[u8] {
        self.first.get(..self.first_len).unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::{BARE_MAX, ENTETE_MAX, EtatScram, FIRST_MAX};

    #[test]
    fn ce_qui_est_retenu_se_relit_tel_quel() {
        let etat = EtatScram::neuf(b"n,,", false, b"n=jean,r=abc", b"r=abcdef,s=c2Vs,i=32768")
            .expect("tient");
        assert_eq!(etat.entete(), b"n,,");
        assert!(!etat.liee());
        assert_eq!(etat.bare(), b"n=jean,r=abc");
        assert_eq!(etat.first(), b"r=abcdef,s=c2Vs,i=32768");
    }

    #[test]
    fn le_vide_se_retient_aussi() {
        // Une politique peut rendre un `server-first` vide si elle refuse : la
        // session doit savoir le porter sans broncher.
        let etat = EtatScram::neuf(b"", false, b"", b"").expect("tient");
        assert_eq!(etat.bare(), b"");
        assert_eq!(etat.first(), b"");
        assert_eq!(etat.entete(), b"");
    }

    #[test]
    fn ce_qui_deborde_est_refuse_et_non_tronque() {
        let trop_long = [b'a'; BARE_MAX + 1];
        assert!(EtatScram::neuf(b"n,,", false, &trop_long, b"r=x").is_none());
        let trop_long = [b'a'; FIRST_MAX + 1];
        assert!(EtatScram::neuf(b"n,,", false, b"n=jean,r=abc", &trop_long).is_none());
        let trop_long = [b'a'; ENTETE_MAX + 1];
        assert!(EtatScram::neuf(&trop_long, false, b"n=jean,r=abc", b"r=x").is_none());
        // Et la limite EXACTE tient, elle : c'est une borne, pas un interdit.
        let juste = [b'a'; BARE_MAX];
        assert!(EtatScram::neuf(b"n,,", false, &juste, b"r=x").is_some());
        let juste = [b'a'; FIRST_MAX];
        assert!(EtatScram::neuf(b"n,,", false, b"n=jean,r=abc", &juste).is_some());
        let juste = [b'a'; ENTETE_MAX];
        assert!(EtatScram::neuf(&juste, false, b"n=jean,r=abc", b"r=x").is_some());
    }

    #[test]
    fn la_liaison_attendue_est_l_entete_puis_les_octets_du_canal() {
        // **SANS LIAISON, LE `c=` NE PORTE QUE L'EN-TÊTE** : c'est §6, et c'est
        // ce qui rend `biws` (le base64 de `n,,`) si familier dans les traces.
        let sans = EtatScram::neuf(b"n,,", false, b"n=jean,r=abc", b"r=abc").expect("tient");
        let (place, fin) = sans.liaison_attendue(&[7; 32]);
        assert_eq!(
            place.get(..fin),
            Some(&b"n,,"[..]),
            "une liaison a été ajoutée là où le pair n'a pas lié"
        );

        // Avec liaison, les trente-deux octets suivent l'en-tête.
        let avec =
            EtatScram::neuf(b"p=tls-exporter,,", true, b"n=jean,r=abc", b"r=abc").expect("tient");
        let mut attendu = std::vec::Vec::from(&b"p=tls-exporter,,"[..]);
        attendu.extend_from_slice(&[7; 32]);
        let (place, fin) = avec.liaison_attendue(&[7; 32]);
        assert_eq!(place.get(..fin), Some(attendu.as_slice()));

        // **L'EN-TÊTE LE PLUS LONG TIENT AVEC SA LIAISON**, et c'est la borne
        // qui rend cette fonction infaillible.
        let long = [b'a'; ENTETE_MAX];
        let plein = EtatScram::neuf(&long, true, b"n=jean,r=abc", b"r=abc").expect("tient");
        let (_, fin) = plein.liaison_attendue(&[7; 32]);
        assert_eq!(fin, ENTETE_MAX + ams_sasl::LIAISON_OCTETS);
    }

    #[test]
    fn l_etat_se_copie_et_se_debogue() {
        let etat =
            EtatScram::neuf(b"n,,", false, b"n=jean,r=abc", b"r=abc,s=c2Vs,i=4096").expect("tient");
        let copie = etat;
        assert_eq!(copie.bare(), etat.bare());
        assert!(!std::format!("{etat:?}").is_empty());
    }
}
