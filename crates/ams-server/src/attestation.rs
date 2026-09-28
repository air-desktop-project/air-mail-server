// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Juger l'attestation de clef d'un appareil Android à l'enrôlement (0.2.39).
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

use std::string::String;
use std::sync::{Arc, PoisonError, RwLock};
use std::vec::Vec;

use ams_config::{AndroidAttestation, Attested};

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
    /// Elle n'est pas du base64url, ou pèse trop.
    Illisible,
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
            Self::Refusee(raison) => raison.describe(),
        }
    }
}

/// Le juge : ce que la configuration exige d'une attestation.
#[derive(Debug, Clone)]
pub struct Juge {
    mode: AndroidAttestation,
    paquet: Vec<u8>,
    signataires: Vec<[u8; 32]>,
    /// Les racines admises : celles de Google, puis celles de la
    /// configuration.
    racines: Vec<Vec<u8>>,
    /// La liste de révocation, partagée avec ce qui la relit.
    liste: Arc<Liste>,
    /// L'âge, en secondes, au-delà duquel la liste ne se croit plus.
    age_max: u64,
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
            mode: AndroidAttestation::Off,
            paquet: Vec::new(),
            signataires: Vec::new(),
            racines: Vec::new(),
            liste: Arc::new(Liste::default()),
            age_max: 0,
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
        mode: AndroidAttestation,
        paquet: &str,
        signataires: &[[u8; 32]],
        pem_des_racines: Option<&[u8]>,
        age_max_jours: u16,
    ) -> Result<Self, String> {
        if mode != AndroidAttestation::Off && (paquet.is_empty() || signataires.is_empty()) {
            return Err(String::from(
                "l'attestation Android est jugée sans paquet ni empreinte de signature : \
                 n'importe quelle application passerait",
            ));
        }
        let mut racines: Vec<Vec<u8>> = ams_attest::GOOGLE_ROOTS
            .iter()
            .map(|racine| racine.to_vec())
            .collect();
        if let Some(pem) = pem_des_racines {
            let lues = clefs_publiques(pem);
            if lues.is_empty() {
                return Err(String::from(
                    "le fichier de racines Android ne contient aucune clef publique lisible \
                     (`-----BEGIN PUBLIC KEY-----`)",
                ));
            }
            racines.extend(lues);
        }
        Ok(Self {
            mode,
            paquet: paquet.as_bytes().to_vec(),
            signataires: signataires.to_vec(),
            racines,
            liste: Arc::new(Liste::default()),
            age_max: u64::from(age_max_jours).saturating_mul(86_400),
        })
    }

    /// Le mode.
    #[must_use]
    pub const fn mode(&self) -> AndroidAttestation {
        self.mode
    }

    /// Combien de racines sont admises.
    #[must_use]
    pub fn racines(&self) -> usize {
        self.racines.len()
    }

    /// Juge l'attestation qu'un appareil présente avec sa clef.
    ///
    /// - `defi` : le texte scellé dont le SHA-256 est le défi — l'invitation,
    ///   ou le défi d'appairage ;
    /// - `attestation` : la chaîne en base64url, ou rien.
    ///
    /// Rend ce que l'attestation a établi, ou `None` quand il n'y en a pas et
    /// que le mode le permet — ou quand le mode n'en lit aucune.
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
        let encodee = match (self.mode, attestation) {
            (AndroidAttestation::Off, _) | (AndroidAttestation::Verify, None) => return Ok(None),
            (AndroidAttestation::Require, None) => return Err(Refus::Absente),
            (_, Some(encodee)) => encodee,
        };
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
        let mut place = std::vec![0_u8; CHAINE_OCTETS_MAX];
        let chaine = ams_api::decode_base64url(encodee.as_bytes(), &mut place)
            .map_err(|_| Refus::Illisible)?;
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
        Ok(Some(match verdict.level {
            ams_attest::SecurityLevel::TrustedEnvironment => Attested::Tee,
            ams_attest::SecurityLevel::StrongBox => Attested::StrongBox,
        }))
    }
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
