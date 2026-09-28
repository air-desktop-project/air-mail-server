// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Juger l'attestation de clef d'un appareil à l'enrôlement : Android
//! (0.2.39) et App Attest d'Apple (0.2.43).
//!
//! La vérification elle-même vit dans `ams-attest`, sans entrée-sortie. Ce
//! module tient ce qui vient de la configuration — le mode, le paquet, les
//! empreintes, les racines — et décide de ce qu'une absence veut dire.
//!
//! # LE DÉFI EST CE QUE LE SERVEUR A DÉJÀ SCELLÉ
//!
//! Une attestation fraîche porte un défi que le serveur a émis. Il n'y en a
//! pas de nouveau à émettre : l'enrôlement présente une INVITATION, et un
//! appairage un DÉFI D'APPAIRAGE — l'une et l'autre scellés, datés, et à usage
//! unique. Le défi d'attestation est le SHA-256 de ce texte, tel qu'écrit :
//! l'application le calcule avant de créer sa clef
//! (`setAttestationChallenge`), et une attestation produite pour une autre
//! invitation ne vaut pas pour celle-ci.
//!
//! # APP ATTEST : LE DÉFI LIE AUSSI LA CLEF D'APPAREIL
//!
//! La clef qu'App Attest atteste n'est pas la clef d'appareil : elle ne sait
//! signer que des assertions. L'application iOS passe donc à `attestKey` le
//! `clientDataHash` = SHA-256(défi ‖ 0x00 ‖ clef d'appareil, 65 octets) : une
//! attestation obtenue pour une autre clef d'appareil — ou une autre
//! invitation — ne vaut pas pour celle-ci. L'octet nul sépare le texte de la
//! clef, que le texte ne peut contenir.
//!
//! # UN SEUL CHAMP, DEUX PLATEFORMES
//!
//! L'attestation arrive dans le même champ. Décodée, une chaîne Android est
//! une `SEQUENCE` DER (`0x30`) ; un objet App Attest, une table CBOR
//! (`0xA0` à `0xBF`). Rien d'autre ne se lit.

use std::string::String;
use std::sync::{Arc, PoisonError, RwLock};
use std::vec::Vec;

use ams_config::{AttestationMode, Attested};

/// Ce qu'une chaîne d'attestation peut peser, décodée.
///
/// Une chaîne réelle fait quatre à six kilo-octets ; seize laissent de la marge
/// sans laisser un inconnu faire lire ce qu'il veut.
const CHAINE_OCTETS_MAX: usize = 16 * 1024;

/// Pourquoi un enrôlement se refuse — pour le journal du serveur.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refus {
    /// Le serveur l'exige, et l'appareil n'en présente pas.
    Absente,
    /// Aucune liste de révocation n'est encore chargée : on ne croit pas une
    /// clef dont on ne sait pas si Google l'a révoquée.
    SansListe,
    /// La liste est plus vieille que l'âge admis (0.2.42) : elle ne dit plus
    /// ce que Google a révoqué depuis.
    ListePerimee,
    /// Elle n'est pas du base64url, pèse trop, ou n'est d'aucune plateforme.
    Illisible,
    /// Elle est d'une plateforme dont le serveur ne juge pas l'attestation,
    /// et il en exige une.
    NonJugee,
    /// La politique la refuse — et dit pourquoi.
    Refusee(ams_attest::Refusal),
}

impl Refus {
    /// Ce que le journal en dit.
    #[must_use]
    pub const fn dire(self) -> &'static str {
        match self {
            Self::Absente => "aucune attestation, et le serveur l'exige",
            Self::SansListe => "aucune liste de révocation n'est encore chargée",
            Self::ListePerimee => "la liste de révocation est trop vieille",
            Self::Illisible => "attestation illisible",
            Self::NonJugee => {
                "attestation d'une plateforme que le serveur ne juge pas, et il en exige une"
            }
            Self::Refusee(raison) => raison.describe(),
        }
    }
}

/// Le juge : ce que la configuration exige d'une attestation.
#[derive(Debug, Clone)]
pub struct Juge {
    /// Le mode Android.
    mode: AttestationMode,
    paquet: Vec<u8>,
    signataires: Vec<[u8; 32]>,
    /// Les racines admises : celles de Google, puis celles de la
    /// configuration.
    racines: Vec<Vec<u8>>,
    /// La liste de révocation, partagée avec ce qui la relit.
    liste: Arc<Liste>,
    /// L'âge, en secondes, au-delà duquel la liste ne se croit plus.
    age_max: u64,
    /// Les racines en plus, lues de la configuration : elles valent pour les
    /// deux plateformes.
    en_plus: Vec<Vec<u8>>,
    /// App Attest.
    apple: Apple,
}

/// Ce que la configuration exige d'App Attest.
#[derive(Debug, Clone)]
struct Apple {
    mode: AttestationMode,
    /// `TeamID.bundleID`.
    application: Vec<u8>,
    environnement: ams_attest::AppleEnvironment,
    /// La racine d'Apple, puis celles de la configuration.
    racines: Vec<Vec<u8>>,
}

impl Apple {
    fn eteint() -> Self {
        Self {
            mode: AttestationMode::Off,
            application: Vec::new(),
            environnement: ams_attest::AppleEnvironment::Production,
            racines: Vec::new(),
        }
    }
}

/// La liste de révocation courante — les numéros de série que Google nomme,
/// triés.
///
/// **ELLE SE REMPLACE ENTIÈRE, ET NE SE VIDE JAMAIS** : une relecture qui
/// échoue laisse l'ancienne en vigueur. Seule une liste lue en entier en
/// remplace une autre — voir `ams_attest::read_status_list`.
#[derive(Debug, Default)]
pub struct Liste {
    courante: RwLock<Option<Courante>>,
}

/// Une liste, et la date de ce qu'elle dit.
#[derive(Debug, Clone)]
pub struct Courante {
    /// Les numéros de série, triés.
    pub series: Arc<Vec<u128>>,
    /// Quand elle a été publiée — la relecture chez Google, ou la dernière
    /// modification du fichier —, en secondes depuis l'époque.
    pub date: u64,
}

impl Liste {
    /// Pose une liste neuve, datée. Rend combien de clefs elle nomme.
    pub fn poser(&self, mut series: Vec<u128>, date: u64) -> usize {
        series.sort_unstable();
        series.dedup();
        let combien = series.len();
        *self
            .courante
            .write()
            .unwrap_or_else(PoisonError::into_inner) = Some(Courante {
            series: Arc::new(series),
            date,
        });
        combien
    }

    /// La liste courante, s'il y en a une.
    #[must_use]
    pub fn courante(&self) -> Option<Courante> {
        self.courante
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

/// Lit une liste de révocation publiée par Google.
///
/// # Errors
///
/// Une liste qui n'a pas la forme publiée : elle se refuse entière.
pub fn lire_la_liste(json: &[u8]) -> Result<Vec<u128>, ams_attest::Refusal> {
    let mut series = Vec::new();
    ams_attest::read_status_list(json, &mut |serie| series.push(serie))?;
    Ok(series)
}

impl Juge {
    /// Un juge qui ne lit aucune attestation.
    #[must_use]
    pub fn eteint() -> Self {
        Self {
            mode: AttestationMode::Off,
            paquet: Vec::new(),
            signataires: Vec::new(),
            racines: Vec::new(),
            liste: Arc::new(Liste::default()),
            age_max: 0,
            en_plus: Vec::new(),
            apple: Apple::eteint(),
        }
    }

    /// La liste de révocation de ce juge, à tenir à jour.
    #[must_use]
    pub fn liste(&self) -> Arc<Liste> {
        Arc::clone(&self.liste)
    }

    /// Le juge que cette configuration décrit. `pem_des_racines` est le
    /// contenu du fichier de racines en plus, déjà lu, ou `None`.
    ///
    /// # Errors
    ///
    /// Un fichier de racines qui ne contient aucune clef lisible, ou un mode
    /// qui juge sans paquet ni empreinte.
    pub fn new(
        mode: AttestationMode,
        paquet: &str,
        signataires: &[[u8; 32]],
        pem_des_racines: Option<&[u8]>,
        age_max_jours: u16,
    ) -> Result<Self, String> {
        if mode != AttestationMode::Off && (paquet.is_empty() || signataires.is_empty()) {
            return Err(String::from(
                "l'attestation Android est jugée sans paquet ni empreinte de signature : \
                 n'importe quelle application passerait",
            ));
        }
        let mut racines: Vec<Vec<u8>> = ams_attest::GOOGLE_ROOTS
            .iter()
            .map(|racine| racine.to_vec())
            .collect();
        let mut en_plus = Vec::new();
        if let Some(pem) = pem_des_racines {
            let lues = clefs_publiques(pem);
            if lues.is_empty() {
                return Err(String::from(
                    "le fichier de racines Android ne contient aucune clef publique lisible \
                     (`-----BEGIN PUBLIC KEY-----`)",
                ));
            }
            racines.extend(lues.iter().cloned());
            en_plus = lues;
        }
        Ok(Self {
            mode,
            paquet: paquet.as_bytes().to_vec(),
            signataires: signataires.to_vec(),
            racines,
            liste: Arc::new(Liste::default()),
            age_max: u64::from(age_max_jours).saturating_mul(86_400),
            en_plus,
            apple: Apple::eteint(),
        })
    }

    /// Ce juge, qui juge aussi App Attest (0.2.43) — sous la racine d'Apple et
    /// les racines en plus de [`Self::new`].
    ///
    /// # Errors
    ///
    /// Un mode qui juge sans identifiant d'application.
    pub fn avec_apple(
        mut self,
        mode: AttestationMode,
        application: &str,
        developpement: bool,
    ) -> Result<Self, String> {
        if mode != AttestationMode::Off && application.is_empty() {
            return Err(String::from(
                "App Attest est jugée sans identifiant d'application : n'importe quelle \
                 application passerait",
            ));
        }
        let mut racines: Vec<Vec<u8>> = ams_attest::APPLE_ROOTS
            .iter()
            .map(|racine| racine.to_vec())
            .collect();
        racines.extend(self.en_plus.iter().cloned());
        self.apple = Apple {
            mode,
            application: application.as_bytes().to_vec(),
            environnement: if developpement {
                ams_attest::AppleEnvironment::Development
            } else {
                ams_attest::AppleEnvironment::Production
            },
            racines,
        };
        Ok(self)
    }

    /// Le mode Android.
    #[must_use]
    pub const fn mode(&self) -> AttestationMode {
        self.mode
    }

    /// Le mode d'App Attest.
    #[must_use]
    pub const fn mode_apple(&self) -> AttestationMode {
        self.apple.mode
    }

    /// Combien de racines sont admises pour App Attest.
    #[must_use]
    pub fn racines_apple(&self) -> usize {
        self.apple.racines.len()
    }

    /// Combien de racines sont admises.
    #[must_use]
    pub fn racines(&self) -> usize {
        self.racines.len()
    }

    /// Juge l'attestation qu'un appareil présente avec sa clef.
    ///
    /// - `defi` : le texte scellé dont est tiré le défi — l'invitation, ou le
    ///   défi d'appairage ;
    /// - `attestation` : la chaîne Android ou l'objet App Attest, en
    ///   base64url, ou rien.
    ///
    /// Rend ce que l'attestation a établi, ou `None` quand il n'y en a pas et
    /// qu'aucun mode ne l'exige — ou quand le mode de sa plateforme n'en lit
    /// aucune.
    ///
    /// # Errors
    ///
    /// Le [`Refus`], pour le journal.
    pub fn juger(
        &self,
        cle: &[u8; ams_attest::DEVICE_KEY_OCTETS],
        defi: &str,
        attestation: Option<&str>,
        maintenant: i64,
    ) -> Result<Option<Attested>, Refus> {
        let exigee =
            self.mode == AttestationMode::Require || self.apple.mode == AttestationMode::Require;
        let lue = self.mode != AttestationMode::Off || self.apple.mode != AttestationMode::Off;
        let encodee = match (lue, attestation) {
            (false, _) => return Ok(None),
            (true, None) if exigee => return Err(Refus::Absente),
            (true, None) => return Ok(None),
            (true, Some(encodee)) => encodee,
        };
        let mut place = std::vec![0_u8; CHAINE_OCTETS_MAX];
        let decodee = ams_api::decode_base64url(encodee.as_bytes(), &mut place)
            .map_err(|_| Refus::Illisible)?;
        let (mode, attestee) = match decodee.first() {
            Some(0x30) => (
                self.mode,
                self.juger_android(decodee, cle, defi, maintenant),
            ),
            Some(0xA0..=0xBF) => (
                self.apple.mode,
                self.juger_apple(decodee, cle, defi, maintenant),
            ),
            _ => return Err(Refus::Illisible),
        };
        // **UNE PLATEFORME ÉTEINTE NE LIT PAS SON ATTESTATION** — mais si l'un
        // des modes l'exige, ne rien lire ne peut pas valoir preuve.
        if mode == AttestationMode::Off {
            return if exigee {
                Err(Refus::NonJugee)
            } else {
                Ok(None)
            };
        }
        attestee.map(Some)
    }

    fn juger_android(
        &self,
        chaine: &[u8],
        cle: &[u8; ams_attest::DEVICE_KEY_OCTETS],
        defi: &str,
        maintenant: i64,
    ) -> Result<Attested, Refus> {
        if self.mode == AttestationMode::Off {
            return Err(Refus::NonJugee);
        }
        let courante = self.liste.courante().ok_or(Refus::SansListe)?;
        // **UNE LISTE TROP VIEILLE NE SE CROIT PLUS** (0.2.42) : elle ne dit
        // rien de ce que Google a révoqué depuis. Refuser, c'est retarder un
        // enrôlement ; croire, ce serait accepter une clef d'usine qui a fui.
        let age = u64::try_from(maintenant)
            .unwrap_or(0)
            .saturating_sub(courante.date);
        if age > self.age_max {
            return Err(Refus::ListePerimee);
        }
        let revoquees = courante.series;
        let racines: Vec<&[u8]> = self.racines.iter().map(Vec::as_slice).collect();
        let politique = ams_attest::Policy {
            roots: &racines,
            package: &self.paquet,
            signers: &self.signataires,
            revoked: &revoquees,
        };
        let condensat = ams_sasl::sha256(defi.as_bytes());
        let verdict = ams_attest::verify(chaine, cle, &condensat, &politique, maintenant)
            .map_err(Refus::Refusee)?;
        Ok(match verdict.level {
            ams_attest::SecurityLevel::TrustedEnvironment => Attested::Tee,
            ams_attest::SecurityLevel::StrongBox => Attested::StrongBox,
        })
    }

    fn juger_apple(
        &self,
        objet: &[u8],
        cle: &[u8; ams_attest::DEVICE_KEY_OCTETS],
        defi: &str,
        maintenant: i64,
    ) -> Result<Attested, Refus> {
        if self.apple.mode == AttestationMode::Off {
            return Err(Refus::NonJugee);
        }
        let racines: Vec<&[u8]> = self.apple.racines.iter().map(Vec::as_slice).collect();
        let politique = ams_attest::ApplePolicy {
            roots: &racines,
            app_id: &self.apple.application,
            environment: self.apple.environnement,
        };
        let condensat = donnees_client(defi, cle);
        ams_attest::verify_app_attest(objet, &condensat, &politique, maintenant)
            .map_err(Refus::Refusee)?;
        Ok(Attested::AppAttest)
    }
}

/// Le `clientDataHash` qu'une application iOS passe à `attestKey` :
/// SHA-256(défi ‖ 0x00 ‖ clef d'appareil).
#[must_use]
pub fn donnees_client(defi: &str, cle: &[u8; ams_attest::DEVICE_KEY_OCTETS]) -> [u8; 32] {
    let mut tout = Vec::with_capacity(defi.len().saturating_add(1).saturating_add(cle.len()));
    tout.extend_from_slice(defi.as_bytes());
    tout.push(0);
    tout.extend_from_slice(cle);
    ams_sasl::sha256(&tout)
}

/// Les clefs publiques d'un fichier PEM (`-----BEGIN PUBLIC KEY-----`), en
/// `SubjectPublicKeyInfo` DER. Ce qui ne se lit pas s'ignore : l'appelant
/// refuse un fichier dont RIEN ne se lit.
fn clefs_publiques(pem: &[u8]) -> Vec<Vec<u8>> {
    const DEBUT: &[u8] = b"-----BEGIN PUBLIC KEY-----";
    const FIN: &[u8] = b"-----END PUBLIC KEY-----";
    let mut clefs = Vec::new();
    let mut reste = pem;
    while let Some(debut) = reste.windows(DEBUT.len()).position(|f| f == DEBUT) {
        let apres = reste
            .get(debut.saturating_add(DEBUT.len())..)
            .unwrap_or_default();
        let Some(fin) = apres.windows(FIN.len()).position(|f| f == FIN) else {
            break;
        };
        let corps = apres.get(..fin).unwrap_or_default();
        // Le base64 de PEM est l'alphabet standard ; on le récrit dans celui
        // d'URL, que sait lire `ams-api`, sans remplissage ni blancs.
        let url: Vec<u8> = corps
            .iter()
            .filter(|octet| !octet.is_ascii_whitespace() && **octet != b'=')
            .map(|octet| match octet {
                b'+' => b'-',
                b'/' => b'_',
                autre => *autre,
            })
            .collect();
        let mut der = std::vec![0_u8; url.len()];
        if let Ok(lue) = ams_api::decode_base64url(&url, &mut der) {
            clefs.push(lue.to_vec());
        }
        reste = apres
            .get(fin.saturating_add(FIN.len())..)
            .unwrap_or_default();
    }
    clefs
}

#[cfg(test)]
mod tests;
