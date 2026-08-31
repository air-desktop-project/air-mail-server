// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Ce que la couture entre `rustls` et notre disposition de paquet doit rendre.
//!
//! # LA PROPRIÉTÉ QUI COMPTE EST CROISÉE
//!
//! Un aller-retour de `rustls` avec lui-même ne dirait rien : c'est ce qu'il
//! fait déjà. Ce qu'on éprouve ici, c'est que **`seal_packet` avec les clés de
//! `rustls` produit exactement ce que `open_packet` avec NOS clés relit**, et
//! réciproquement. Les deux sources doivent être interchangeables, sans quoi
//! l'espace `Initial` et l'espace `Handshake` d'une même connexion ne
//! s'entendraient pas.

use ams_proto_quic::{ConnectionId, LongKind};
use ams_quic::{PacketKind, Plan, Protection, open_packet, seal_packet};
use ams_quic_crypto::{Keys, Reason, Role, Secret};

use super::Clefs;

/// L'identifiant de destination de l'annexe A.1 de RFC 9001.
const DCID: [u8; 8] = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];

/// Nos clés `Initial`, dérivées comme §5.2 le veut.
fn nos_clefs(role: Role) -> Keys {
    Secret::initial(&DCID, role)
        .expect("dérivable")
        .keys()
        .expect("dérivables")
}

/// Les MÊMES clés, mais passées par les objets de `rustls`.
///
/// **C'EST `rustls` QUI LES DÉRIVE, ET NON NOUS QUI LES LUI DONNONS.**
/// `AeadKey` ne se construit, hors de `rustls`, qu'à partir de trente-deux
/// octets — AES-128 en veut seize. On passe donc par `Keys::initial`, qui
/// applique §5.2 de RFC 9001 au même identifiant de destination.
///
/// C'est ce qui rend la comparaison forte : les deux chemins partent du même
/// identifiant en clair, et rien d'autre ne circule entre eux.
fn celles_de_rustls(role: Role) -> Clefs {
    let fournisseur = ams_tls::provider_quic();
    let suite = fournisseur
        .cipher_suites
        .iter()
        .filter_map(rustls::SupportedCipherSuite::tls13)
        .find(|suite| suite.common.suite == rustls::CipherSuite::TLS13_AES_128_GCM_SHA256)
        .expect("AES-128-GCM est la suite obligatoire de QUIC (§5.1)");
    let quic = suite.quic.expect("le fournisseur QUIC en porte un");
    let cote = match role {
        Role::Client => rustls::Side::Client,
        Role::Server => rustls::Side::Server,
    };
    // `local` chiffre ce que CE côté-là émet — c'est exactement ce que
    // `Secret::initial(&DCID, role)` dérive.
    let clefs = rustls::quic::Keys::initial(rustls::quic::Version::V1, suite, quic, &DCID, cote);
    Clefs::new(clefs.local.packet, clefs.local.header)
}

/// Un identifiant de connexion à partir de ces octets.
fn identifiant(octets: &[u8]) -> ConnectionId {
    ConnectionId::new(octets).expect("vingt octets au plus")
}

/// **CE QUE `rustls` SCELLE, NOTRE LECTURE L'OUVRE** — et réciproquement.
#[test]
fn les_deux_sources_de_clefs_sont_interchangeables() {
    let notres = nos_clefs(Role::Server);
    let siennes = celles_de_rustls(Role::Server);
    let charge = b"des trames, assez longues pour porter un echantillon";

    for (quoi, plan) in [
        (
            "Initial",
            Plan::Initial {
                destination: identifiant(&DCID),
                source: identifiant(&[1, 2, 3, 4]),
                token: &[],
            },
        ),
        (
            "Handshake",
            Plan::Handshake {
                destination: identifiant(&DCID),
                source: identifiant(&[1, 2, 3, 4]),
            },
        ),
        (
            "1-RTT",
            Plan::OneRtt {
                destination: identifiant(&DCID),
                key_phase: true,
            },
        ),
    ] {
        // Scellé par `rustls`, ouvert par nous.
        let mut par_rustls = std::vec![0_u8; 1500];
        let ecrit =
            seal_packet(&mut par_rustls, &siennes, &plan, 5, None, charge).expect("scellable");
        let mut par_nous = std::vec![0_u8; 1500];
        let aussi = seal_packet(&mut par_nous, &notres, &plan, 5, None, charge).expect("scellable");

        // **LES OCTETS SONT LES MÊMES, PAS SEULEMENT ÉQUIVALENTS.** Deux
        // chemins qui ne produiraient pas le même paquet seraient deux
        // implémentations, et l'une des deux serait fausse un jour.
        assert_eq!(ecrit, aussi, "{quoi}");
        assert_eq!(par_rustls, par_nous, "{quoi} : les octets diffèrent");

        // Et l'ouverture croisée retrouve la charge, dans les deux sens.
        for (par_qui, clefs) in [
            ("nos clés", &notres as &dyn Protection),
            ("celles de rustls", &siennes),
        ] {
            let mut datagramme = par_rustls.get(..ecrit).expect("écrit").to_vec();
            let ouvert = open_packet(&mut datagramme, clefs, None, DCID.len()).expect("lisible");
            assert_eq!(ouvert.number, 5, "{quoi} / {par_qui}");
            assert_eq!(ouvert.total, ecrit, "{quoi} / {par_qui}");
            assert_eq!(
                datagramme.get(ouvert.payload_at..ouvert.payload_at + ouvert.payload_len),
                Some(&charge[..]),
                "{quoi} / {par_qui}"
            );
            let attendu = match quoi {
                "Initial" => PacketKind::Long(LongKind::Initial),
                "Handshake" => PacketKind::Long(LongKind::Handshake),
                _ => PacketKind::Short,
            };
            assert_eq!(ouvert.kind, attendu, "{quoi} / {par_qui}");
        }
    }
}

/// **LE DÉMASQUAGE NE TOUCHE QUE LA LONGUEUR ANNONCÉE** (§5.4.1).
///
/// L'interface de `rustls` démasque le premier octet ET les octets de numéro
/// qu'on lui donne, en un seul appel. Lui en donner quatre en démasquerait
/// quatre — alors que le numéro peut n'en faire qu'un, et que **les trois de
/// trop appartiennent à la charge chiffrée**. Les toucher la rendrait
/// indéchiffrable.
///
/// On le constate sur des numéros de toutes les longueurs : si le démasquage
/// débordait, l'ouverture échouerait.
#[test]
fn le_demasquage_ne_touche_que_la_longueur_annoncee() {
    let siennes = celles_de_rustls(Role::Server);
    let plan = Plan::Handshake {
        destination: identifiant(&DCID),
        source: identifiant(&[7]),
    };
    // Des numéros qui s'écrivent sur un, deux, trois et quatre octets (§17.1).
    for numero in [0_u64, 200, 60_000, 20_000_000, 3_000_000_000] {
        let mut tampon = std::vec![0_u8; 1500];
        let ecrit = seal_packet(&mut tampon, &siennes, &plan, numero, None, b"une charge")
            .expect("scellable");
        let mut datagramme = tampon.get(..ecrit).expect("écrit").to_vec();
        let plus_grand = numero.checked_sub(1);
        let ouvert = open_packet(&mut datagramme, &siennes, plus_grand, DCID.len())
            .unwrap_or_else(|issue| panic!("{numero} : {issue:?}"));
        assert_eq!(ouvert.number, numero);
        assert_eq!(
            datagramme.get(ouvert.payload_at..ouvert.payload_at + ouvert.payload_len),
            Some(&b"une charge"[..]),
            "{numero} : la charge a été abîmée par le démasquage"
        );
    }
}

/// **UN PAQUET ABÎMÉ NE S'OUVRE PAS**, quelle que soit la source des clés.
#[test]
fn un_paquet_abime_ne_s_ouvre_pas() {
    let siennes = celles_de_rustls(Role::Server);
    let plan = Plan::OneRtt {
        destination: identifiant(&DCID),
        key_phase: false,
    };
    let mut tampon = std::vec![0_u8; 1500];
    let ecrit =
        seal_packet(&mut tampon, &siennes, &plan, 1, None, b"une charge").expect("scellable");
    let paquet = tampon.get(..ecrit).expect("écrit").to_vec();

    for rang in 0..paquet.len() {
        let mut abime = paquet.clone();
        abime[rang] ^= 0x01;
        let relu = open_packet(&mut abime, &siennes, None, DCID.len());
        let intact = relu.is_ok_and(|ouvert| {
            ouvert.number == 1
                && abime.get(ouvert.payload_at..ouvert.payload_at + ouvert.payload_len)
                    == Some(&b"une charge"[..])
        });
        assert!(!intact, "l'octet {rang} n'est pas authentifié");
    }
}

/// **UN PAQUET TROP COURT POUR PORTER UN ÉCHANTILLON SE REFUSE** (§5.4.2).
///
/// « An endpoint MUST discard packets that are not long enough to contain a
/// complete sample. »
#[test]
fn un_paquet_sans_echantillon_se_refuse() {
    let siennes = celles_de_rustls(Role::Server);
    for taille in [0_usize, 1, 10, 19] {
        let mut court = std::vec![0_u8; taille];
        assert_eq!(
            siennes
                .protect(&mut court, 1, 1)
                .expect_err("pas d'échantillon")
                .reason(),
            Reason::TooShortToSample,
            "{taille} octets"
        );
        assert_eq!(
            siennes
                .unprotect(&mut court, 1)
                .expect_err("pas d'échantillon")
                .reason(),
            Reason::TooShortToSample,
            "{taille} octets"
        );
    }
}

/// **UN TAMPON SANS PLACE POUR LE TAG SE REFUSE**, plutôt que de sceller à
/// moitié.
#[test]
fn un_tampon_sans_place_pour_le_tag_se_refuse() {
    let siennes = celles_de_rustls(Role::Server);
    assert_eq!(siennes.tag_len(), 16);
    let mut juste = [0_u8; 20];
    assert_eq!(
        siennes
            .seal(0, b"entete", &mut juste, 8)
            .expect_err("huit de clair et seize de tag ne tiennent pas dans vingt")
            .reason(),
        Reason::BufferTooSmall
    );
    // Vingt-quatre suffisent : huit et seize.
    let mut assez = [0_u8; 24];
    assert_eq!(
        siennes
            .seal(0, b"entete", &mut assez, 8)
            .expect("scellable"),
        24
    );
}

/// **UNE CHARGE QUI NE S'AUTHENTIFIE PAS SE REFUSE.**
#[test]
fn une_charge_qui_ne_s_authentifie_pas_se_refuse() {
    let siennes = celles_de_rustls(Role::Server);
    let mut tampon = [0_u8; 32];
    siennes
        .seal(3, b"entete", &mut tampon, 16)
        .expect("scellable");
    tampon[0] ^= 0x01;
    assert_eq!(
        siennes
            .open(3, b"entete", &mut tampon)
            .expect_err("abîmée")
            .reason(),
        Reason::NotAuthentic
    );
    // Et un autre en-tête non plus : il sert de données associées (§5.3).
    let mut autre = [0_u8; 32];
    siennes
        .seal(3, b"entete", &mut autre, 16)
        .expect("scellable");
    assert_eq!(
        siennes
            .open(3, b"autre", &mut autre)
            .expect_err("l'en-tête ne correspond pas")
            .reason(),
        Reason::NotAuthentic
    );
}

/// Rien de secret ne s'imprime.
#[test]
fn rien_de_secret_ne_s_imprime() {
    let siennes = celles_de_rustls(Role::Server);
    let dit = std::format!("{siennes:?}");
    assert!(dit.contains("Clefs"), "{dit}");
    assert!(!dit.contains("key"), "des clés dans un Debug : {dit}");
}

/// **UNE CHARGE PLUS GRANDE QU'UN DATAGRAMME SE REFUSE**, y compris par ce
/// chemin-ci.
///
/// `ams-quic-crypto` borne ce qu'il chiffre à ce qu'un datagramme UDP peut
/// porter, et le pont vers `rustls` hérite de cette borne : ce sont NOS clés
/// qui travaillent en dessous.
#[test]
fn une_charge_plus_grande_qu_un_datagramme_se_refuse() {
    let siennes = celles_de_rustls(Role::Server);
    let borne = ams_quic_crypto::PACKET_OCTETS_MAX;
    let mut trop = std::vec![0_u8; borne + 1 + 16];
    assert_eq!(
        siennes
            .seal(0, b"entete", &mut trop, borne + 1)
            .expect_err("plus qu'un datagramme ne porte")
            .reason(),
        Reason::NotAuthentic
    );
    // La borne elle-même passe.
    let mut pile = std::vec![0_u8; borne + 16];
    assert_eq!(
        siennes
            .seal(0, b"entete", &mut pile, borne)
            .expect("la borne tient"),
        borne + 16
    );
}

/// **LE TRAIT PASSE PAR LES DEUX IMPLÉMENTATIONS, ET ELLES S'ACCORDENT.**
///
/// `tag_len` est la seule méthode qu'un appelant peut lire sans rien chiffrer :
/// si les deux sources n'annonçaient pas la même taille, la disposition d'un
/// paquet différerait selon l'espace — et un datagramme coalisé serait illisible
/// à partir de son second paquet.
#[test]
fn les_deux_implementations_annoncent_le_meme_tag() {
    let notres = nos_clefs(Role::Server);
    let siennes = celles_de_rustls(Role::Server);
    assert_eq!(Protection::tag_len(&notres), 16);
    assert_eq!(siennes.tag_len(), 16);
    assert_eq!(Protection::tag_len(&notres), siennes.tag_len());
}

/// **UN NUMÉRO PLUS LONG QUE QUATRE OCTETS SE REFUSE** (§17.1).
///
/// « When present in long or short packet headers, they are encoded in 1 to 4
/// bytes. » Masquer au-delà toucherait la charge chiffrée.
#[test]
fn un_numero_trop_long_se_refuse() {
    let siennes = celles_de_rustls(Role::Server);
    let mut paquet = std::vec![0_u8; 64];
    assert_eq!(
        siennes
            .protect(&mut paquet, 1, 5)
            .expect_err("§17.1 borne à quatre")
            .reason(),
        Reason::TooShortToSample
    );
    // Quatre passent.
    assert!(siennes.protect(&mut paquet, 1, 4).is_ok());
}

/// Une protection d'en-tête qui refuse tout, pour éprouver ce qu'on en fait.
///
/// # POURQUOI CE FAUX EXISTE
///
/// `Clefs::new` est publique : elle accepte n'importe quelle implémentation des
/// traits de `rustls`, pas seulement la nôtre. **Les refus de la nôtre sont
/// inatteignables** — l'échantillon est vérifié avant, et §17.1 borne le numéro.
/// Ceux d'une autre ne le sont pas, et le code qui les remonte doit être éprouvé
/// plutôt que supposé.
/// `tout` : elle refuse dès le premier octet. Sinon, elle ne refuse QUE quand
/// il y a un numéro à démasquer — ce qui éprouve le SECOND appel de
/// [`super::Clefs::unprotect`], que le premier masquerait sinon.
#[derive(Debug)]
struct Bougonne {
    tout: bool,
}

impl Bougonne {
    /// Refuse-t-elle cet appel-ci ?
    fn refuse(&self, numero: &[u8]) -> Result<(), rustls::Error> {
        match self.tout || !numero.is_empty() {
            true => Err(rustls::Error::DecryptError),
            false => Ok(()),
        }
    }
}

impl rustls::quic::HeaderProtectionKey for Bougonne {
    fn encrypt_in_place(
        &self,
        _sample: &[u8],
        _first: &mut u8,
        packet_number: &mut [u8],
    ) -> Result<(), rustls::Error> {
        self.refuse(packet_number)
    }

    fn decrypt_in_place(
        &self,
        _sample: &[u8],
        _first: &mut u8,
        packet_number: &mut [u8],
    ) -> Result<(), rustls::Error> {
        self.refuse(packet_number)
    }

    fn sample_len(&self) -> usize {
        16
    }
}

/// **CE QU'UNE PROTECTION D'EN-TÊTE REFUSE REMONTE, ET NE PANIQUE PAS.**
///
/// Les deux appels de [`super::Clefs::unprotect`] sont éprouvés séparément : une
/// implémentation qui refuserait seulement le second — celui qui démasque le
/// numéro — passerait le premier, et un refus avalé là laisserait un numéro à
/// moitié démasqué.
#[test]
fn ce_qu_une_protection_refuse_remonte() {
    let vraies = celles_de_rustls(Role::Server);
    let fournisseur = ams_tls::provider_quic();
    let suite = fournisseur
        .cipher_suites
        .iter()
        .filter_map(rustls::SupportedCipherSuite::tls13)
        .find(|suite| suite.common.suite == rustls::CipherSuite::TLS13_AES_128_GCM_SHA256)
        .expect("AES-128-GCM");
    let quic = suite.quic.expect("le fournisseur QUIC en porte un");

    for tout in [true, false] {
        // On garde une vraie clé de paquet, et l'on remplace la protection
        // d'en-tête par celle qui refuse.
        let clefs = rustls::quic::Keys::initial(
            rustls::quic::Version::V1,
            suite,
            quic,
            &DCID,
            rustls::Side::Server,
        );
        let bougonnes = Clefs::new(clefs.local.packet, std::boxed::Box::new(Bougonne { tout }));

        let mut paquet = std::vec![0_u8; 64];
        assert_eq!(
            bougonnes
                .protect(&mut paquet, 1, 1)
                .expect_err("elle refuse")
                .reason(),
            Reason::TooShortToSample,
            "tout = {tout}"
        );
        assert_eq!(
            bougonnes
                .unprotect(&mut paquet, 1)
                .expect_err("elle refuse")
                .reason(),
            Reason::TooShortToSample,
            "tout = {tout}"
        );
    }

    // La vraie, elle, accepte les mêmes octets.
    let mut paquet = std::vec![0_u8; 64];
    assert!(vraies.protect(&mut paquet, 1, 1).is_ok());
}
