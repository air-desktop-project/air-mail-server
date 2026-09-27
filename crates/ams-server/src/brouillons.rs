// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Les brouillons de l'API : **le corps d'abord, les pièces jointes ensuite.**
//!
//! # LA DÉCISION, ET CE QU'ELLE DEMANDE
//!
//! Décision de l'exploitant (2026-09-27) : un message avec pièces jointes ne
//! se soumet pas d'un seul tenant. Le client donne d'abord son corps — texte,
//! HTML —, dans la borne d'un message ; puis chaque pièce jointe, déclarée
//! avec son nom, son type et sa taille, arrive **par morceaux**, chacun dans sa
//! requête, chacun écrit sur disque. Au dernier morceau, la pièce est
//! rassemblée en un seul fichier. Le message entier ne se compose qu'à
//! l'envoi, en lisant le disque : aucune pièce jointe n'est jamais entière en
//! mémoire.
//!
//! # SUR LE DISQUE
//!
//! ```text
//! <racine>/<compte>/<id>/corps.eml          le corps, tel que reçu
//!                       /pj-<n>.meta        « taille \t type \t nom »
//!                       /pj-<n>.<a>-<b>     un morceau : les octets a à b inclus
//!                       /pj-<n>.bin         la pièce rassemblée
//! ```
//!
//! **L'expiration se lit sur `corps.eml`**, qui ne se réécrit jamais : un
//! brouillon vit [`DUREE_S`] secondes après sa création, puis disparaît au
//! premier passage — sans horloge ni tâche de fond de plus.
//!
//! # UN MORCEAU RENVOYÉ REMPLACE LE SIEN
//!
//! C'est ce qui rend la reprise possible : un téléphone dont le réseau coupe au
//! milieu d'un morceau ne sait pas s'il est arrivé, et le renvoie. Même portée,
//! même place — le second remplace le premier. Une portée qui en CHEVAUCHE une
//! autre sans l'égaler, en revanche, se refuse : deux versions d'un même octet
//! ne se départagent pas.

use std::path::{Path, PathBuf};

/// Combien de temps un brouillon vit : un jour.
pub const DUREE_S: u64 = 24 * 3600;

/// Combien de pièces jointes un brouillon porte au plus.
pub const PIECES_MAX: u64 = 32;

/// Le nom du corps dans le répertoire d'un brouillon.
const CORPS: &str = "corps.eml";

/// Pourquoi un geste sur un brouillon n'a pas eu lieu.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Faute {
    /// Le brouillon, ou la pièce, n'existe pas — ou a expiré.
    Introuvable,
    /// Ce qu'on demande est mal formé : une portée qui ne tombe pas juste, une
    /// taille qui ne correspond pas.
    Refus,
    /// Le message composé dépasserait la taille d'un message.
    TropGros,
    /// L'état l'empêche : trop de pièces, un morceau qui en chevauche un autre,
    /// une pièce déjà complète, un envoi dont une pièce manque.
    Conflit,
    /// Le disque n'a pas suivi.
    Disque,
}

impl From<std::io::Error> for Faute {
    fn from(_: std::io::Error) -> Self {
        Self::Disque
    }
}

/// Une pièce jointe, telle que le disque la dit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Piece {
    /// Son numéro dans le brouillon, à partir de un.
    pub numero: u64,
    /// Son nom de fichier.
    pub nom: String,
    /// Son type, `type/sous-type`.
    pub media: String,
    /// Sa taille entière.
    pub taille: u64,
    /// Les portées reçues, triées, bornes comprises.
    pub recu: Vec<(u64, u64)>,
}

impl Piece {
    /// Est-elle entière ?
    #[must_use]
    pub fn complete(&self) -> bool {
        self.recu.as_slice() == [(0, self.taille.saturating_sub(1))]
    }
}

/// Le corps d'un brouillon, et ses pièces entières avec leur fichier.
pub type APrendre = (Vec<u8>, Vec<(Piece, PathBuf)>);

/// Les brouillons, sous une racine.
#[derive(Debug)]
pub struct Brouillons {
    racine: PathBuf,
    /// La taille qu'un message composé ne doit pas dépasser.
    message_max: u64,
}

impl Brouillons {
    /// Les brouillons sous `racine`, bornés par la taille d'un message.
    #[must_use]
    pub fn new(racine: PathBuf, message_max: u64) -> Self {
        Self {
            racine,
            message_max,
        }
    }

    /// Le répertoire d'un compte. **Le nom vient d'un jeton vérifié** ; on
    /// refuse quand même ce qui deviendrait une traversée.
    fn du_compte(&self, compte: &str) -> Option<PathBuf> {
        (!compte.is_empty() && !compte.starts_with('.') && !compte.contains('/'))
            .then(|| self.racine.join(compte))
    }

    /// Le répertoire d'un brouillon : trente-deux chiffres hexadécimaux, et
    /// rien d'autre ne désigne un brouillon.
    fn du_brouillon(&self, compte: &str, id: &str) -> Option<PathBuf> {
        if id.len() != 32 || !id.bytes().all(|octet| octet.is_ascii_hexdigit()) {
            return None;
        }
        Some(self.du_compte(compte)?.join(id))
    }

    /// Le répertoire d'un brouillon qui existe et vit encore — ou `None`, en
    /// retirant au passage celui qui a expiré.
    fn vivant(&self, compte: &str, id: &str, maintenant: u64) -> Result<PathBuf, Faute> {
        let chemin = self.du_brouillon(compte, id).ok_or(Faute::Introuvable)?;
        let Some(expire) = expiration(&chemin) else {
            return Err(Faute::Introuvable);
        };
        if expire <= maintenant {
            let _ = std::fs::remove_dir_all(&chemin);
            return Err(Faute::Introuvable);
        }
        Ok(chemin)
    }

    /// Crée un brouillon à partir de son corps, et rend son identifiant et
    /// son expiration. Balaie au passage les brouillons expirés du compte.
    ///
    /// # Errors
    ///
    /// [`Faute::Refus`] pour un compte qui ne se nomme pas, [`Faute::Disque`].
    pub fn creer(
        &self,
        compte: &str,
        corps: &[u8],
        maintenant: u64,
        alea: [u8; 16],
    ) -> Result<(String, u64), Faute> {
        let repertoire = self.du_compte(compte).ok_or(Faute::Refus)?;
        self.balayer(compte, maintenant);
        let id: String = alea.iter().map(|octet| format!("{octet:02x}")).collect();
        let chemin = repertoire.join(&id);
        {
            use std::os::unix::fs::DirBuilderExt as _;
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(&chemin)?;
        }
        ams_fichier::poser(&chemin.join(CORPS), corps)?;
        Ok((id, expiration(&chemin).ok_or(Faute::Disque)?))
    }

    /// Retire les brouillons expirés d'un compte.
    pub fn balayer(&self, compte: &str, maintenant: u64) {
        let Some(repertoire) = self.du_compte(compte) else {
            return;
        };
        let Ok(entrees) = std::fs::read_dir(repertoire) else {
            return;
        };
        for entree in entrees.flatten() {
            if expiration(&entree.path()).is_none_or(|expire| expire <= maintenant) {
                let _ = std::fs::remove_dir_all(entree.path());
            }
        }
    }

    /// Retire les brouillons expirés de tous les comptes — au démarrage.
    pub fn balayer_tout(&self, maintenant: u64) {
        let Ok(comptes) = std::fs::read_dir(&self.racine) else {
            return;
        };
        for compte in comptes.flatten() {
            if let Some(nom) = compte.file_name().to_str() {
                self.balayer(nom, maintenant);
            }
        }
    }

    /// L'expiration d'un brouillon et ses pièces.
    ///
    /// # Errors
    ///
    /// [`Faute::Introuvable`].
    pub fn etat(
        &self,
        compte: &str,
        id: &str,
        maintenant: u64,
    ) -> Result<(u64, Vec<Piece>), Faute> {
        let chemin = self.vivant(compte, id, maintenant)?;
        let expire = expiration(&chemin).ok_or(Faute::Introuvable)?;
        Ok((expire, pieces(&chemin)))
    }

    /// Abandonne un brouillon.
    ///
    /// # Errors
    ///
    /// [`Faute::Introuvable`], [`Faute::Disque`].
    pub fn supprimer(&self, compte: &str, id: &str, maintenant: u64) -> Result<(), Faute> {
        let chemin = self.vivant(compte, id, maintenant)?;
        std::fs::remove_dir_all(chemin)?;
        Ok(())
    }

    /// Déclare une pièce jointe, et rend son état — vide.
    ///
    /// # LA TAILLE SE JUGE ICI, AVANT LE PREMIER OCTET
    ///
    /// Le message composé porte le corps, et chaque pièce en base64 — quatre
    /// tiers de sa taille, plus ses fins de ligne. Le refuser au dernier
    /// morceau ferait envoyer des mégaoctets pour rien.
    ///
    /// # Errors
    ///
    /// [`Faute::Introuvable`], [`Faute::Conflit`] au-delà de [`PIECES_MAX`],
    /// [`Faute::TropGros`], [`Faute::Disque`].
    pub fn declarer(
        &self,
        compte: &str,
        id: &str,
        nom: &str,
        media: &str,
        taille: u64,
        maintenant: u64,
    ) -> Result<Piece, Faute> {
        let chemin = self.vivant(compte, id, maintenant)?;
        let _verrou = ams_fichier::verrouiller(&chemin.join(CORPS))?;
        let deja = pieces(&chemin);
        let numero = deja
            .iter()
            .map(|piece| piece.numero)
            .max()
            .unwrap_or(0)
            .saturating_add(1);
        if numero > PIECES_MAX {
            return Err(Faute::Conflit);
        }
        let corps = std::fs::metadata(chemin.join(CORPS))?.len();
        let total = deja
            .iter()
            .map(|piece| piece.taille)
            .chain(core::iter::once(taille))
            .fold(corps, |somme, octets| somme.saturating_add(encode(octets)));
        if total > self.message_max {
            return Err(Faute::TropGros);
        }
        let meta = format!("{taille}\t{media}\t{nom}");
        ams_fichier::poser(&chemin.join(format!("pj-{numero}.meta")), meta.as_bytes())?;
        Ok(Piece {
            numero,
            nom: nom.to_owned(),
            media: media.to_owned(),
            taille,
            recu: Vec::new(),
        })
    }

    /// Pose un morceau d'une pièce jointe, et rend l'état de la pièce.
    ///
    /// Quand les morceaux couvrent la pièce de bout en bout, elle est
    /// RASSEMBLÉE en un seul fichier, et les morceaux s'en vont.
    ///
    /// # Errors
    ///
    /// [`Faute::Introuvable`] ; [`Faute::Refus`] si la taille annoncée n'est
    /// pas celle de la pièce, ou si les octets ne font pas la portée ;
    /// [`Faute::Conflit`] pour une pièce déjà entière ou un morceau qui en
    /// chevauche un autre sans l'égaler ; [`Faute::Disque`].
    #[allow(clippy::too_many_arguments)]
    pub fn poser(
        &self,
        compte: &str,
        id: &str,
        numero: u64,
        (premier, dernier, total): (u64, u64, u64),
        octets: &[u8],
        maintenant: u64,
    ) -> Result<Piece, Faute> {
        let chemin = self.vivant(compte, id, maintenant)?;
        let _verrou = ams_fichier::verrouiller(&chemin.join(CORPS))?;
        let piece = pieces(&chemin)
            .into_iter()
            .find(|piece| piece.numero == numero)
            .ok_or(Faute::Introuvable)?;
        let longueur = dernier.saturating_sub(premier).saturating_add(1);
        if total != piece.taille || u64::try_from(octets.len()).ok() != Some(longueur) {
            return Err(Faute::Refus);
        }
        if piece.complete() {
            return Err(Faute::Conflit);
        }
        if piece
            .recu
            .iter()
            .any(|&(a, b)| (a, b) != (premier, dernier) && a <= dernier && premier <= b)
        {
            return Err(Faute::Conflit);
        }
        ams_fichier::poser(
            &chemin.join(format!("pj-{numero}.{premier}-{dernier}")),
            octets,
        )?;
        let apres = pieces(&chemin)
            .into_iter()
            .find(|piece| piece.numero == numero)
            .ok_or(Faute::Disque)?;
        if couvre(&apres.recu, apres.taille) {
            rassembler(&chemin, &apres)?;
            return Ok(Piece {
                recu: vec![(0, apres.taille.saturating_sub(1))],
                ..apres
            });
        }
        Ok(apres)
    }

    /// Retire une pièce jointe, entière ou en morceaux.
    ///
    /// # Errors
    ///
    /// [`Faute::Introuvable`], [`Faute::Disque`].
    pub fn retirer(
        &self,
        compte: &str,
        id: &str,
        numero: u64,
        maintenant: u64,
    ) -> Result<(), Faute> {
        let chemin = self.vivant(compte, id, maintenant)?;
        let _verrou = ams_fichier::verrouiller(&chemin.join(CORPS))?;
        if !pieces(&chemin).iter().any(|piece| piece.numero == numero) {
            return Err(Faute::Introuvable);
        }
        let prefixe = format!("pj-{numero}.");
        for entree in std::fs::read_dir(&chemin)?.flatten() {
            if entree.file_name().to_string_lossy().starts_with(&prefixe) {
                std::fs::remove_file(entree.path())?;
            }
        }
        Ok(())
    }

    /// Le corps et les pièces ENTIÈRES d'un brouillon, prêtes à composer.
    ///
    /// # Errors
    ///
    /// [`Faute::Introuvable`] ; [`Faute::Conflit`] si une pièce n'est pas
    /// entière — on n'envoie pas un fichier auquel il manque des octets.
    pub fn a_composer(&self, compte: &str, id: &str, maintenant: u64) -> Result<APrendre, Faute> {
        let chemin = self.vivant(compte, id, maintenant)?;
        let corps = std::fs::read(chemin.join(CORPS))?;
        let mut rendues = Vec::new();
        for piece in pieces(&chemin) {
            if !piece.complete() {
                return Err(Faute::Conflit);
            }
            let fichier = chemin.join(format!("pj-{}.bin", piece.numero));
            rendues.push((piece, fichier));
        }
        Ok((corps, rendues))
    }
}

/// Ce qu'une pièce de `octets` coûte dans le message composé : le base64 et
/// ses fins de ligne, plus ses en-têtes.
fn encode(octets: u64) -> u64 {
    let base64 = octets.div_ceil(3).saturating_mul(4);
    base64
        .saturating_add(base64.div_ceil(76).saturating_mul(2))
        .saturating_add(512)
}

/// L'expiration d'un brouillon, lue sur son corps.
fn expiration(chemin: &Path) -> Option<u64> {
    let modifie = std::fs::metadata(chemin.join(CORPS))
        .ok()?
        .modified()
        .ok()?;
    let depuis = modifie
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_secs();
    Some(depuis.saturating_add(DUREE_S))
}

/// Les pièces d'un brouillon, lues sur le disque, par numéro croissant.
fn pieces(chemin: &Path) -> Vec<Piece> {
    let Ok(entrees) = std::fs::read_dir(chemin) else {
        return Vec::new();
    };
    let noms: Vec<String> = entrees
        .flatten()
        .filter_map(|entree| entree.file_name().to_str().map(str::to_owned))
        .collect();
    let mut rendues = Vec::new();
    for nom in &noms {
        let Some(numero) = nom
            .strip_prefix("pj-")
            .and_then(|reste| reste.strip_suffix(".meta"))
            .and_then(|numero| numero.parse::<u64>().ok())
        else {
            continue;
        };
        let Ok(meta) = std::fs::read_to_string(chemin.join(nom)) else {
            continue;
        };
        let mut champs = meta.splitn(3, '\t');
        let (Some(taille), Some(media), Some(fichier)) =
            (champs.next(), champs.next(), champs.next())
        else {
            continue;
        };
        let Ok(taille) = taille.parse::<u64>() else {
            continue;
        };
        let prefixe = format!("pj-{numero}.");
        let mut recu: Vec<(u64, u64)> = if noms.contains(&format!("pj-{numero}.bin")) {
            vec![(0, taille.saturating_sub(1))]
        } else {
            noms.iter()
                .filter_map(|autre| {
                    let (a, b) = autre.strip_prefix(&prefixe)?.split_once('-')?;
                    Some((a.parse().ok()?, b.parse().ok()?))
                })
                .collect()
        };
        recu.sort_unstable();
        rendues.push(Piece {
            numero,
            nom: fichier.to_owned(),
            media: media.to_owned(),
            taille,
            recu,
        });
    }
    rendues.sort_unstable_by_key(|piece| piece.numero);
    rendues
}

/// Ces portées, triées, couvrent-elles `0..taille` sans trou ?
fn couvre(recu: &[(u64, u64)], taille: u64) -> bool {
    let mut attendu = 0_u64;
    for &(a, b) in recu {
        if a != attendu {
            return false;
        }
        attendu = b.saturating_add(1);
    }
    attendu == taille
}

/// Rassemble les morceaux d'une pièce en un seul fichier, puis les retire.
///
/// Le fichier naît sous un nom provisoire et prend le sien d'un `rename` : qui
/// le lit voit la pièce entière, ou rien.
fn rassembler(chemin: &Path, piece: &Piece) -> Result<(), Faute> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    let provisoire = chemin.join(format!(".pj-{}.bin.tmp", piece.numero));
    let mut sortie = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&provisoire)?;
    for &(a, b) in &piece.recu {
        let morceau = chemin.join(format!("pj-{}.{a}-{b}", piece.numero));
        let mut entree = std::fs::File::open(&morceau)?;
        std::io::copy(&mut entree, &mut sortie)?;
    }
    sortie.flush()?;
    sortie.sync_all()?;
    drop(sortie);
    std::fs::rename(&provisoire, chemin.join(format!("pj-{}.bin", piece.numero)))?;
    for &(a, b) in &piece.recu {
        let _ = std::fs::remove_file(chemin.join(format!("pj-{}.{a}-{b}", piece.numero)));
    }
    std::fs::File::open(chemin)?.sync_all()?;
    Ok(())
}

/// Compose le message entier et l'écoule, morceau par morceau, dans `ecrire`.
///
/// # LE MESSAGE COMPOSÉ
///
/// Sans pièce jointe, c'est le corps tel quel. Avec, c'est un
/// `multipart/mixed` (RFC 2046 §5.1.3) : l'en-tête du corps — privé de ses
/// champs MIME —, puis le corps comme première partie, puis chaque pièce,
/// `Content-Disposition: attachment`, en base64, lue sur le disque par tranches
/// de 57 octets — soixante-seize caractères par ligne (RFC 2045 §6.8).
///
/// `frontiere` doit être absente du corps : l'appelant la tire au hasard, et
/// cette fonction le vérifie.
///
/// Rend `false` si `ecrire` a refusé, si un fichier ne se lit pas, ou si la
/// frontière se trouve dans le corps.
pub fn composer(
    message: &[u8],
    pieces: &[(Piece, PathBuf)],
    frontiere: &str,
    ecrire: &mut dyn FnMut(&[u8]) -> bool,
) -> bool {
    if pieces.is_empty() {
        return ecrire(message);
    }
    let bornes = ams_mime::Limits::DEFAULT;
    let Ok(lu) = ams_mime::Message::parse(message, &bornes) else {
        return false;
    };
    if message
        .windows(frontiere.len())
        .any(|fenetre| fenetre == frontiere.as_bytes())
    {
        return false;
    }
    // L'en-tête, sans ses champs MIME : ce sont ceux du `multipart` qui
    // parlent désormais. `write_header_fields` finit par la ligne vide, qu'on
    // retire pour ajouter les nôtres.
    let mut entete = vec![0_u8; message.len().saturating_add(64)];
    let Ok(ecrits) = ams_mime::write_header_fields(
        message,
        b"content-type content-transfer-encoding mime-version",
        true,
        &mut entete,
        &bornes,
    ) else {
        return false;
    };
    entete.truncate(ecrits.saturating_sub(2));
    let champ = |nom: &[u8]| {
        lu.fields()
            .find(|champ| champ.name_is(nom))
            .map(|champ| [champ.name(), b":", champ.raw_value(), b"\r\n"].concat())
    };
    let mut debut = entete;
    debut.extend_from_slice(
        format!(
            "MIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=\"{frontiere}\"\r\n\r\n\
             --{frontiere}\r\n"
        )
        .as_bytes(),
    );
    for nom in [&b"content-type"[..], b"content-transfer-encoding"] {
        if let Some(ligne) = champ(nom) {
            debut.extend_from_slice(&ligne);
        }
    }
    debut.extend_from_slice(b"\r\n");
    if !ecrire(&debut) || !ecrire(lu.body()) {
        return false;
    }
    for (piece, fichier) in pieces {
        let entete = format!(
            "\r\n--{frontiere}\r\nContent-Type: {}; {}\r\n\
             Content-Disposition: attachment; {}\r\nContent-Transfer-Encoding: base64\r\n\r\n",
            piece.media,
            parametre("name", &piece.nom),
            parametre("filename", &piece.nom)
        );
        if !ecrire(entete.as_bytes()) || !ecouler_en_base64(fichier, ecrire) {
            return false;
        }
    }
    ecrire(format!("\r\n--{frontiere}--\r\n").as_bytes())
}

/// Un paramètre MIME : `nom="valeur"` pour de l'ASCII simple, `nom*=UTF-8''…`
/// (RFC 2231 §4) pour le reste — un nom accentué s'écrit ainsi.
fn parametre(nom: &str, valeur: &str) -> String {
    let simple = valeur
        .bytes()
        .all(|octet| octet.is_ascii_graphic() || octet == b' ')
        && !valeur.contains(['"', '\\']);
    if simple {
        return format!("{nom}=\"{valeur}\"");
    }
    let mut encode = String::new();
    for octet in valeur.bytes() {
        if octet.is_ascii_alphanumeric() || b"!#$&+-.^_`|~".contains(&octet) {
            encode.push(char::from(octet));
        } else {
            encode.push_str(&format!("%{octet:02X}"));
        }
    }
    format!("{nom}*=UTF-8''{encode}")
}

/// Lit un fichier par tranches de 57 octets × 64, et l'écoule en lignes base64
/// de soixante-seize caractères.
fn ecouler_en_base64(fichier: &Path, ecrire: &mut dyn FnMut(&[u8]) -> bool) -> bool {
    use std::io::Read as _;
    let Ok(mut entree) = std::fs::File::open(fichier) else {
        return false;
    };
    let mut lu = vec![0_u8; 57 * 64];
    let mut sortie = vec![0_u8; 78 * 64];
    loop {
        // On remplit la tranche AVANT d'encoder : une ligne qui ne tombe pas
        // sur un multiple de trois ne peut être que la dernière.
        let mut rempli = 0_usize;
        while rempli < lu.len() {
            match entree.read(lu.get_mut(rempli..).unwrap_or_default()) {
                Ok(0) => break,
                Ok(combien) => rempli = rempli.saturating_add(combien),
                Err(_) => return false,
            }
        }
        if rempli == 0 {
            return true;
        }
        let mut pose = 0_usize;
        for ligne in lu.get(..rempli).unwrap_or_default().chunks(57) {
            let Ok(ecrit) =
                ams_mime::encode_base64_line(ligne, sortie.get_mut(pose..).unwrap_or_default())
            else {
                return false;
            };
            pose = pose.saturating_add(ecrit.len());
            // `encode_base64_line` ne replie ni ne termine : la fin de ligne
            // est la nôtre, une par tranche de 57 octets.
            let Some(fin) = sortie.get_mut(pose..pose.saturating_add(2)) else {
                return false;
            };
            fin.copy_from_slice(b"\r\n");
            pose = pose.saturating_add(2);
        }
        if !ecrire(sortie.get(..pose).unwrap_or_default()) {
            return false;
        }
        if rempli < lu.len() {
            return true;
        }
    }
}

#[cfg(test)]
mod tests;
