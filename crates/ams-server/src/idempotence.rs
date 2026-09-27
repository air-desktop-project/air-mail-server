// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! `Idempotency-Key` : rejouer une soumission sans la doubler.
//!
//! # LE CAS QUI COMPTE
//!
//! Un téléphone soumet un message ; le serveur l'envoie ; la réponse se perd
//! dans un tunnel. Le client ne sait pas si le message est parti, et réessaie.
//! Sans clé, il part deux fois. Avec une clé — la même aux deux essais —, le
//! serveur reconnaît la requête et rend la PREMIÈRE réponse, sans rien refaire.
//!
//! C'est le brouillon IETF `httpapi-idempotency-key-header` : la même clé et la
//! même requête rendent la même réponse ; la même clé pour une autre requête
//! rend `422` ; la même clé pendant que la première est en cours, `409`.
//!
//! # SUR LE DISQUE, ET NON EN MÉMOIRE
//!
//! Un redémarrage du serveur entre la réponse perdue et le nouvel essai est
//! exactement le moment où il ne faut pas oublier. Chaque clé est un fichier —
//! nommé par le SHA-256 de la clé, jamais par la clé elle-même —, sous
//! `<racine>/<compte>/`. La racine est celle des brouillons, sous un nom qui
//! commence par un point : leur balayage ne la prend pas pour un compte.
//!
//! Le fichier dit, sur sa première ligne, `EN-COURS <empreinte>` ou
//! `FAIT <empreinte> <statut> <type>` ; la réponse suit. Il vit
//! [`DUREE_S`] secondes ; un `EN-COURS` qui date de plus de [`EN_COURS_S`]
//! secondes est celui d'une requête morte en chemin, et ne bloque plus rien.

use std::path::{Path, PathBuf};

/// Combien de temps une réponse se rejoue : un jour.
pub const DUREE_S: u64 = 24 * 3600;

/// Au-delà, une requête « en cours » est tenue pour morte.
pub const EN_COURS_S: u64 = 300;

/// La plus longue clé admise.
pub const CLE_MAX: usize = 255;

/// Ce qu'une clé présentée donne.
#[derive(Debug, PartialEq, Eq)]
pub enum Debut {
    /// Jamais vue : la requête s'exécute, et [`Idempotence::finir`] retiendra
    /// sa réponse.
    Neuve,
    /// Déjà servie, pour la même requête : la réponse à rendre telle quelle.
    Rejouer {
        /// Son code d'état.
        status: u16,
        /// Son type de média.
        media: String,
        /// Son corps.
        corps: Vec<u8>,
    },
    /// Déjà servie, pour une AUTRE requête.
    AutreRequete,
    /// La requête qui la porte est en cours.
    EnCours,
}

/// Le registre des clés, sous une racine.
#[derive(Debug)]
pub struct Idempotence {
    racine: PathBuf,
}

/// La clé, lue dans son champ : une chaîne structurée `"…"` (§3.3.3 de
/// RFC 8941) d'ASCII imprimable, sans guillemet ni barre oblique inverse
/// dedans — rien à déséchapper, donc une seule écriture pour une clé.
#[must_use]
pub fn cle_du_champ(champ: &[u8]) -> Option<&[u8]> {
    let dedans = champ.strip_prefix(b"\"")?.strip_suffix(b"\"")?;
    let admis = |octet: &u8| (0x20..=0x7E).contains(octet) && !matches!(*octet, b'"' | b'\\');
    (!dedans.is_empty() && dedans.len() <= CLE_MAX && dedans.iter().all(admis)).then_some(dedans)
}

/// L'empreinte d'une requête : ce qui distingue « la même requête » d'une
/// autre. Le verbe et la ressource, puis le corps.
#[must_use]
pub fn empreinte(requete: &str, corps: &[u8]) -> String {
    let mut tout = Vec::with_capacity(requete.len().saturating_add(corps.len()).saturating_add(1));
    tout.extend_from_slice(requete.as_bytes());
    tout.push(0);
    tout.extend_from_slice(corps);
    hexa(&ams_sasl::sha256(&tout))
}

fn hexa(octets: &[u8]) -> String {
    octets.iter().map(|octet| format!("{octet:02x}")).collect()
}

impl Idempotence {
    /// Le registre sous `racine`.
    #[must_use]
    pub fn new(racine: PathBuf) -> Self {
        Self { racine }
    }

    /// Le fichier d'une clé, pour un compte — ou `None` pour un compte qui ne
    /// se nomme pas.
    fn fichier(&self, compte: &str, cle: &[u8]) -> Option<PathBuf> {
        (!compte.is_empty() && !compte.starts_with('.') && !compte.contains('/'))
            .then(|| self.racine.join(compte).join(hexa(&ams_sasl::sha256(cle))))
    }

    /// Présente une clé pour une requête d'empreinte `empreinte`.
    ///
    /// Une clé neuve est aussitôt marquée EN COURS — par une création
    /// exclusive, si bien que deux requêtes simultanées ne passent pas toutes
    /// les deux.
    ///
    /// # Errors
    ///
    /// L'erreur du système, si le registre ne s'écrit pas.
    pub fn commencer(
        &self,
        compte: &str,
        cle: &[u8],
        empreinte: &str,
        maintenant: u64,
    ) -> std::io::Result<Debut> {
        let Some(fichier) = self.fichier(compte, cle) else {
            return Err(std::io::Error::from(std::io::ErrorKind::InvalidInput));
        };
        if let Some(parent) = fichier.parent() {
            use std::os::unix::fs::DirBuilderExt as _;
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(parent)?;
        }
        // Deux essais : le second suit le retrait d'une entrée périmée.
        for _ in 0..2 {
            match poser_en_cours(&fichier, empreinte) {
                Ok(()) => return Ok(Debut::Neuve),
                Err(erreur) if erreur.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(erreur) => return Err(erreur),
            }
            let Some(lu) = lire(&fichier, maintenant) else {
                // Périmée, illisible ou disparue entre-temps : on la retire et
                // l'on recommence.
                let _ = std::fs::remove_file(&fichier);
                continue;
            };
            return Ok(match lu {
                Lu::EnCours { empreinte: vue } if vue == empreinte => Debut::EnCours,
                Lu::Fait {
                    empreinte: vue,
                    status,
                    media,
                    corps,
                } if vue == empreinte => Debut::Rejouer {
                    status,
                    media,
                    corps,
                },
                _ => Debut::AutreRequete,
            });
        }
        Ok(Debut::EnCours)
    }

    /// Retient la réponse d'une requête commencée.
    ///
    /// # Errors
    ///
    /// L'erreur du système : la réponse part quand même, elle ne se rejouera
    /// seulement pas.
    pub fn finir(
        &self,
        compte: &str,
        cle: &[u8],
        empreinte: &str,
        status: u16,
        media: &str,
        corps: &[u8],
    ) -> std::io::Result<()> {
        let Some(fichier) = self.fichier(compte, cle) else {
            return Err(std::io::Error::from(std::io::ErrorKind::InvalidInput));
        };
        let mut contenu = format!("FAIT {empreinte} {status} {media}\n").into_bytes();
        contenu.extend_from_slice(corps);
        ams_fichier::poser(&fichier, &contenu)
    }

    /// Oublie une requête commencée qui a échoué de NOTRE fait : le client
    /// doit pouvoir réessayer sous la même clé.
    pub fn abandonner(&self, compte: &str, cle: &[u8]) {
        if let Some(fichier) = self.fichier(compte, cle) {
            let _ = std::fs::remove_file(fichier);
        }
    }

    /// Retire les entrées périmées de tous les comptes — au démarrage.
    pub fn balayer(&self, maintenant: u64) {
        let Ok(comptes) = std::fs::read_dir(&self.racine) else {
            return;
        };
        for compte in comptes.flatten() {
            let Ok(entrees) = std::fs::read_dir(compte.path()) else {
                continue;
            };
            for entree in entrees.flatten() {
                if lire(&entree.path(), maintenant).is_none() {
                    let _ = std::fs::remove_file(entree.path());
                }
            }
        }
    }
}

/// Ce qu'une entrée dit.
enum Lu {
    EnCours {
        empreinte: String,
    },
    Fait {
        empreinte: String,
        status: u16,
        media: String,
        corps: Vec<u8>,
    },
}

/// Crée l'entrée EN COURS, exclusivement.
fn poser_en_cours(fichier: &Path, empreinte: &str) -> std::io::Result<()> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    let mut sortie = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(fichier)?;
    sortie.write_all(format!("EN-COURS {empreinte}\n").as_bytes())?;
    sortie.sync_all()
}

/// Lit une entrée — `None` si elle est périmée ou illisible.
fn lire(fichier: &Path, maintenant: u64) -> Option<Lu> {
    let contenu = std::fs::read(fichier).ok()?;
    let age = maintenant.saturating_sub(
        std::fs::metadata(fichier)
            .ok()?
            .modified()
            .ok()?
            .duration_since(std::time::UNIX_EPOCH)
            .ok()?
            .as_secs(),
    );
    let fin = contenu.iter().position(|octet| *octet == b'\n')?;
    let (tete, corps) = contenu.split_at(fin);
    let tete = core::str::from_utf8(tete).ok()?;
    let mut mots = tete.split(' ');
    match (mots.next()?, mots.next()?) {
        ("EN-COURS", empreinte) if age <= EN_COURS_S => Some(Lu::EnCours {
            empreinte: empreinte.to_owned(),
        }),
        ("FAIT", empreinte) if age <= DUREE_S => Some(Lu::Fait {
            empreinte: empreinte.to_owned(),
            status: mots.next()?.parse().ok()?,
            media: mots.next()?.to_owned(),
            corps: corps.get(1..).unwrap_or_default().to_vec(),
        }),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::{Debut, Idempotence, cle_du_champ, empreinte};

    struct Atelier(std::path::PathBuf);

    impl Drop for Atelier {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn atelier(nom: &str) -> Atelier {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        let chemin = std::env::temp_dir().join(format!(
            "ams-idempotence-{nom}-{unique}-{:?}",
            std::thread::current().id()
        ));
        std::fs::create_dir_all(&chemin).expect("créable");
        Atelier(chemin)
    }

    fn maintenant() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs())
    }

    #[test]
    fn une_cle_se_lit_comme_une_chaine_structuree() {
        assert_eq!(
            cle_du_champ(b"\"8e03978e-40d5\""),
            Some(&b"8e03978e-40d5"[..])
        );
        for mauvais in [
            &b"8e03978e"[..],
            b"\"\"",
            b"\"a\"b\"",
            b"\"a\\b\"",
            b"\"a\x01\"",
            b"\"",
        ] {
            assert_eq!(cle_du_champ(mauvais), None, "{mauvais:?}");
        }
        let longue = format!("\"{}\"", "a".repeat(256));
        assert_eq!(cle_du_champ(longue.as_bytes()), None);
    }

    /// **LA MÊME CLÉ ET LA MÊME REQUÊTE REJOUENT ; UNE AUTRE REQUÊTE SE
    /// REFUSE ; PENDANT, C'EST « EN COURS ».**
    #[test]
    fn une_cle_se_rejoue_et_ne_se_detourne_pas() {
        let atelier = atelier("rejeu");
        let registre = Idempotence::new(atelier.0.clone());
        let premiere = empreinte("POST Submissions", b"message");
        let t = maintenant();
        assert_eq!(
            registre.commencer("marie", b"k1", &premiere, t).ok(),
            Some(Debut::Neuve)
        );
        assert_eq!(
            registre.commencer("marie", b"k1", &premiere, t).ok(),
            Some(Debut::EnCours)
        );
        registre
            .finir(
                "marie",
                b"k1",
                &premiere,
                200,
                "application/json",
                b"{\"delivered\":1}",
            )
            .expect("retenue");
        assert_eq!(
            registre.commencer("marie", b"k1", &premiere, t).ok(),
            Some(Debut::Rejouer {
                status: 200,
                media: String::from("application/json"),
                corps: b"{\"delivered\":1}".to_vec()
            })
        );
        let autre = empreinte("POST Submissions", b"un autre message");
        assert_eq!(
            registre.commencer("marie", b"k1", &autre, t).ok(),
            Some(Debut::AutreRequete)
        );
        // Une clé est au compte : la même chez un autre est neuve.
        assert_eq!(
            registre.commencer("paul", b"k1", &premiere, t).ok(),
            Some(Debut::Neuve)
        );
        // Abandonnée, elle redevient neuve.
        registre.abandonner("paul", b"k1");
        assert_eq!(
            registre.commencer("paul", b"k1", &premiere, t).ok(),
            Some(Debut::Neuve)
        );
        // Un compte qui ne se nomme pas n'a pas de registre.
        assert!(registre.commencer(".x", b"k1", &premiere, t).is_err());
        assert!(registre.finir("", b"k1", &premiere, 200, "x", b"").is_err());
        registre.abandonner("a/b", b"k1");
    }

    /// **UNE ENTRÉE PÉRIMÉE NE BLOQUE RIEN**, et le balayage la retire.
    #[test]
    fn une_entree_perimee_ne_bloque_rien() {
        let atelier = atelier("peremption");
        let registre = Idempotence::new(atelier.0.clone());
        let premiere = empreinte("POST Submissions", b"m");
        let t = maintenant();
        assert_eq!(
            registre.commencer("marie", b"k", &premiere, t).ok(),
            Some(Debut::Neuve)
        );
        // Six minutes plus tard, la requête « en cours » est morte.
        assert_eq!(
            registre
                .commencer("marie", b"k", &premiere, t + super::EN_COURS_S + 60)
                .ok(),
            Some(Debut::Neuve)
        );
        registre
            .finir("marie", b"k", &premiere, 200, "x", b"y")
            .expect("retenue");
        let demain = t + super::DUREE_S + 60;
        assert_eq!(
            registre.commencer("marie", b"k", &premiere, demain).ok(),
            Some(Debut::Neuve)
        );
        registre.balayer(demain + super::DUREE_S + 60);
        assert_eq!(
            std::fs::read_dir(atelier.0.join("marie"))
                .expect("lisible")
                .count(),
            0,
            "le balayage retire ce qui a expiré"
        );
        // Une entrée illisible est une entrée qu'on retire.
        std::fs::write(atelier.0.join("marie").join("illisible"), b"rien").expect("écrite");
        registre.balayer(t);
        assert!(!atelier.0.join("marie").join("illisible").exists());
        Idempotence::new(atelier.0.join("absente")).balayer(t);
    }
}
