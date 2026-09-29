// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Le registre de réception, sur le disque (0.2.44) — voir
//! `docs/registre-de-reception.md` et `ams_config::registre`.
//!
//! # UN FICHIER PAR JOUR UTC, SCELLÉ ET CHAÎNÉ
//!
//! `AAAA-MM-JJ.amsr`, ouvert au premier enregistrement du jour par un entête
//! qui cite le condensat du fichier précédent, et fermé — au premier passage
//! après minuit — par un sceau qui porte celui de tout ce qui le précède. Le
//! fichier scellé passe en lecture seule.
//!
//! # CHAQUE ENREGISTREMENT EST SUR LE DISQUE QUAND `ecrire` REND LA MAIN
//!
//! `sync_data` après chaque trame : un message n'est accepté qu'une fois son
//! constat écrit, et « écrit » veut dire « survit à une coupure ». C'est plus
//! lent qu'un tampon ; la sécurité passe avant la vitesse.
//!
//! # UN ARRÊT BRUTAL NE CASSE PAS LA CHAÎNE
//!
//! Au démarrage, le dernier fichier est relu : une trame coupée par une
//! coupure est retirée — le sceau dira combien d'octets —, et un fichier d'un
//! jour passé que personne n'a scellé l'est à ce moment-là.
//!
//! # RIEN NE SE SUPPRIME
//!
//! Le serveur n'efface ni ne réécrit jamais un fichier scellé.

use std::fs::{File, OpenOptions};
use std::io::Write as _;
use std::os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, PoisonError};

use ams_config::registre::{self, Enregistrement, Entete, Sceau};
use sha2::Digest as _;

/// L'extension des fichiers du registre.
const EXTENSION: &str = "amsr";

/// Le fichier du jour, ouvert en ajout.
struct Courant {
    jour: String,
    chemin: PathBuf,
    fichier: File,
    /// Le condensat de tout ce qui est écrit — ce que le sceau portera.
    hacheur: sha2::Sha256,
    /// Les enregistrements écrits, entête compris.
    enregistrements: u64,
    /// Les octets d'une trame coupée retirés à la reprise.
    tronques: u64,
}

struct Etat {
    courant: Option<Courant>,
    /// Le SHA-256 du dernier fichier scellé : ce que le suivant citera.
    precedent: Option<[u8; 32]>,
}

/// Le registre de réception.
pub struct Registre {
    repertoire: PathBuf,
    etat: Mutex<Etat>,
}

impl core::fmt::Debug for Registre {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Registre")
            .field("repertoire", &self.repertoire)
            .finish_non_exhaustive()
    }
}

fn maintenant_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |ecoule| {
            u64::try_from(ecoule.as_millis()).unwrap_or(u64::MAX)
        })
}

fn invalide(texte: String) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, texte)
}

/// Les fichiers du registre, par jour croissant.
fn fichiers(repertoire: &Path) -> std::io::Result<Vec<PathBuf>> {
    let mut trouves: Vec<PathBuf> = std::fs::read_dir(repertoire)?
        .filter_map(Result::ok)
        .map(|entree| entree.path())
        .filter(|chemin| chemin.extension().is_some_and(|ext| ext == EXTENSION))
        .collect();
    trouves.sort();
    Ok(trouves)
}

impl Registre {
    /// Ouvre le registre : crée le répertoire (`0700`), relit le dernier
    /// fichier, retire une trame coupée, scelle un jour passé resté ouvert.
    ///
    /// # Errors
    ///
    /// Un répertoire qu'on ne peut pas créer ou lire, un dernier fichier qu'on
    /// ne peut pas relire ou qui ne commence pas par un entête : **le serveur
    /// refuse alors de démarrer** plutôt que d'écrire à la suite d'une chaîne
    /// qu'il ne sait pas prolonger.
    pub fn ouvrir(repertoire: PathBuf) -> std::io::Result<Self> {
        Self::ouvrir_a(repertoire, maintenant_ms())
    }

    /// [`Registre::ouvrir`], à cet instant.
    fn ouvrir_a(repertoire: PathBuf, quand: u64) -> std::io::Result<Self> {
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&repertoire)?;
        std::fs::set_permissions(&repertoire, std::fs::Permissions::from_mode(0o700))?;
        let mut etat = Etat {
            courant: None,
            precedent: None,
        };
        if let Some(dernier) = fichiers(&repertoire)?.pop() {
            let octets = std::fs::read(&dernier)?;
            let (entieres, combien) = registre::trames_entieres(&octets);
            let garde = octets.get(..entieres).unwrap_or_default();
            let bilan = registre::verifier(garde)
                .map_err(|faute| invalide(format!("{} : {faute}", dernier.display())))?;
            let tronques = u64::try_from(octets.len().saturating_sub(entieres)).unwrap_or(0);
            if bilan.sceau.is_some() {
                etat.precedent = Some(bilan.condensat);
            } else {
                if tronques > 0 {
                    // **LA TRAME COUPÉE SE RETIRE**, et le sceau le dira : on ne
                    // prolonge pas une chaîne après des octets qu'aucun lecteur
                    // ne relirait.
                    OpenOptions::new()
                        .write(true)
                        .open(&dernier)?
                        .set_len(u64::try_from(entieres).unwrap_or(u64::MAX))?;
                    eprintln!(
                        "air-mail-server : registre — {} : trame coupée retirée ({tronques} octet(s)), \
                         sans doute un arrêt brutal",
                        dernier.display()
                    );
                }
                let mut hacheur = sha2::Sha256::new();
                hacheur.update(garde);
                let courant = Courant {
                    jour: bilan.entete.jour.clone(),
                    fichier: OpenOptions::new().append(true).open(&dernier)?,
                    chemin: dernier,
                    hacheur,
                    enregistrements: combien,
                    tronques,
                };
                etat.courant = Some(courant);
            }
        }
        let registre = Self {
            repertoire,
            etat: Mutex::new(etat),
        };
        // Un jour passé resté ouvert se scelle tout de suite.
        registre.tenir_a(quand)?;
        Ok(registre)
    }

    /// Scelle le fichier courant s'il n'est plus celui du jour — à appeler
    /// régulièrement, pour qu'un jour sans courrier se scelle quand même à
    /// minuit.
    ///
    /// # Errors
    ///
    /// Une écriture qui échoue.
    pub fn tenir(&self) -> std::io::Result<()> {
        self.tenir_a(maintenant_ms())
    }

    /// [`Registre::tenir`], à cet instant.
    fn tenir_a(&self, quand: u64) -> std::io::Result<()> {
        let jour = registre::jour_utc(quand);
        let mut etat = self.etat.lock().unwrap_or_else(PoisonError::into_inner);
        if etat
            .courant
            .as_ref()
            .is_some_and(|courant| courant.jour != jour)
        {
            sceller(&mut etat, quand)?;
        }
        Ok(())
    }

    /// Écrit un enregistrement, et ne rend la main qu'une fois qu'il est sur
    /// le disque.
    ///
    /// # Errors
    ///
    /// Une écriture ou une synchronisation qui échoue — le disque plein en
    /// tête. **L'appelant refuse alors le message** (`451`).
    pub fn ecrire(&self, quoi: &Enregistrement) -> std::io::Result<()> {
        self.ecrire_a(quoi, maintenant_ms())
    }

    /// [`Registre::ecrire`], à cet instant.
    fn ecrire_a(&self, quoi: &Enregistrement, quand: u64) -> std::io::Result<()> {
        let trame = registre::trame(quoi).map_err(|faute| invalide(faute.to_string()))?;
        let jour = registre::jour_utc(quand);
        let mut etat = self.etat.lock().unwrap_or_else(PoisonError::into_inner);
        if etat
            .courant
            .as_ref()
            .is_some_and(|courant| courant.jour != jour)
        {
            sceller(&mut etat, quand)?;
        }
        if etat.courant.is_none() {
            let courant = self.ouvrir_le_jour(&jour, etat.precedent, quand)?;
            etat.courant = Some(courant);
        }
        let Some(courant) = etat.courant.as_mut() else {
            return Err(invalide(String::from("aucun fichier ouvert")));
        };
        ajouter(courant, &trame)
    }

    /// Ouvre le fichier d'un jour, et y écrit son entête.
    fn ouvrir_le_jour(
        &self,
        jour: &str,
        precedent: Option<[u8; 32]>,
        quand: u64,
    ) -> std::io::Result<Courant> {
        let chemin = self.repertoire.join(format!("{jour}.{EXTENSION}"));
        // **`create_new`** : un fichier du jour qui existerait déjà — scellé,
        // donc — ne se rouvre pas pour y écrire à la suite.
        let fichier = OpenOptions::new()
            .append(true)
            .create_new(true)
            .mode(0o600)
            .open(&chemin)?;
        let mut courant = Courant {
            jour: String::from(jour),
            chemin,
            fichier,
            hacheur: sha2::Sha256::new(),
            enregistrements: 0,
            tronques: 0,
        };
        let entete = registre::trame(&Enregistrement::Entete(Entete {
            format: registre::FORMAT,
            jour: String::from(jour),
            precedent,
            version: String::from(env!("CARGO_PKG_VERSION")),
            ouvert: quand,
        }))
        .map_err(|faute| invalide(faute.to_string()))?;
        ajouter(&mut courant, &entete)?;
        // Le répertoire aussi : un fichier créé dont l'entrée se perd à la
        // coupure n'a jamais existé.
        File::open(&self.repertoire)?.sync_all()?;
        Ok(courant)
    }
}

/// Ajoute une trame au fichier courant, et la synchronise.
fn ajouter(courant: &mut Courant, trame: &[u8]) -> std::io::Result<()> {
    courant.fichier.write_all(trame)?;
    courant.fichier.sync_data()?;
    courant.hacheur.update(trame);
    courant.enregistrements = courant.enregistrements.saturating_add(1);
    Ok(())
}

/// Scelle le fichier courant : le sceau, la synchronisation, la lecture seule.
fn sceller(etat: &mut Etat, quand: u64) -> std::io::Result<()> {
    let Some(mut courant) = etat.courant.take() else {
        return Ok(());
    };
    let condensat: [u8; 32] = courant.hacheur.clone().finalize().into();
    let sceau = registre::trame(&Enregistrement::Sceau(Sceau {
        enregistrements: courant.enregistrements,
        condensat,
        scelle: quand,
        tronques: courant.tronques,
    }))
    .map_err(|faute| invalide(faute.to_string()))?;
    courant.fichier.write_all(&sceau)?;
    courant.fichier.sync_all()?;
    courant.hacheur.update(&sceau);
    std::fs::set_permissions(&courant.chemin, std::fs::Permissions::from_mode(0o400))?;
    etat.precedent = Some(courant.hacheur.finalize().into());
    Ok(())
}

#[cfg(test)]
mod tests;
