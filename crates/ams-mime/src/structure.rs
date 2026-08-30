// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! La `BODYSTRUCTURE` d'un message, telle qu'IMAP la rend (RFC 9051 §7.5.2).
//!
//! # LE MESSAGE NE SÉJOURNE PAS, LA DESCRIPTION SEULE RESTE
//!
//! Une enveloppe se lit dans l'en-tête ; une structure, elle, se lit dans TOUT
//! le message : ce sont les frontières de la RFC 2046 qui la dessinent, et elles
//! sont semées d'un bout à l'autre. Retenir le message pour les trouver
//! reviendrait à réserver ce que l'expéditeur a choisi d'écrire — exactement ce
//! que [C3] interdit.
//!
//! Le balayeur se fait donc POUSSER les octets, par morceaux, et ne retient
//! qu'un état BORNÉ : au plus [`STRUCTURE_PARTS_MAX`] parties, au plus
//! [`STRUCTURE_DEPTH_MAX`] niveaux d'emboîtement, et une arène d'en-têtes de
//! taille fixe. Un message d'un gibioctet et un message de mille octets y
//! coûtent la même mémoire.
//!
//! # CE QUI SE COUPE, ET CE QUE ÇA DONNE
//!
//! Rien de ce qui déborde ne fait échouer : une structure absente couperait la
//! réponse au milieu d'un élément, ce qui est pire qu'une structure incomplète.
//! Au-delà des bornes, on décrit ce qu'on a pu voir, dans une forme que la
//! grammaire admet toujours.
//!
//! # UNE LIGNE FINIT PAR `CRLF`, ET RIEN D'AUTRE
//!
//! C'est la règle de la crate, et elle vaut ici aussi : un `LF` isolé n'ouvre
//! pas de ligne, donc pas de frontière. Tolérer l'inverse rendrait la structure
//! dépendante de qui la lit — la faille même que le refus des fins de ligne
//! isolées ferme ailleurs.
//!
//! [C3]: https://github.com/air-desktop-project/air-mail-server/blob/main/docs/contraintes.md

use crate::envelope::{valeur_de, write_envelope};
use crate::error::Error;
use crate::limits::Limits;
use crate::message::Message;
use crate::plume::{Forme, Plume};

/// Combien de parties au plus une structure décrit.
///
/// **Aucune RFC ne le borne.** C'est le nombre de descriptions qu'un client
/// recevra pour un seul message, et sans borne un message unique en ferait
/// écrire autant que sa taille le permet.
pub const STRUCTURE_PARTS_MAX: usize = 64;

/// Combien de `multipart` emboîtés au plus.
///
/// **Aucune RFC ne le borne** non plus. C'est ce qui empêche un message
/// d'imposer la profondeur de la récursion qui l'écrit.
pub const STRUCTURE_DEPTH_MAX: usize = 8;

/// La place totale où les en-têtes de parties sont retenus.
const ENTETES_MAX: usize = 16 * 1024;

/// Ce qu'on retient au plus de l'en-tête d'une SEULE partie.
const ENTETE_DE_PARTIE_MAX: usize = 2 * 1024;

/// Une frontière compte au plus 70 caractères (RFC 2046 §5.1.1).
const FRONTIERE_MAX: usize = 70;

/// Ce qu'on retient d'une ligne. La RFC 5322 §2.1.1 en borne le texte à 998.
const LIGNE_MAX: usize = 1000;

/// « Pas de partie ».
const SANS: usize = usize::MAX;

/// Ce qu'une partie est.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Genre {
    /// Un contenu simple : son corps est ce qu'il est.
    Feuille,
    /// Un `multipart/…` : son corps est fait de ses filles.
    Multipart,
    /// Un `message/rfc822` : son corps est un message entier.
    Message,
}

/// Une partie du message.
#[derive(Debug, Clone, Copy)]
struct Partie {
    /// La partie qui la contient, ou [`SANS`] pour le message lui-même.
    parent: usize,
    /// Où son en-tête est retenu, dans l'arène.
    entete: usize,
    entete_len: usize,
    /// Où ELLE commence, dans le message : le premier octet de son en-tête.
    ///
    /// C'est ce qui permet de servir `BODY[1.MIME]` — les lignes d'en-tête d'une
    /// partie — sans relire le message une seconde fois pour les retrouver.
    debut: u64,
    /// Où son corps commence, dans le message.
    corps_debut: u64,
    /// Ce que son corps pèse.
    octets: u64,
    /// Combien de `CRLF` son corps porte.
    lignes: u64,
    genre: Genre,
    /// Son corps n'est pas encore fini.
    ouverte: bool,
}

impl Partie {
    const VIDE: Self = Self {
        parent: SANS,
        entete: 0,
        entete_len: 0,
        debut: 0,
        corps_debut: 0,
        octets: 0,
        lignes: 0,
        genre: Genre::Feuille,
        ouverte: false,
    };
}

/// Un niveau de la pile : une frontière ouverte, et la partie qu'elle décrit.
#[derive(Debug, Clone, Copy)]
struct Niveau {
    frontiere: [u8; FRONTIERE_MAX],
    len: usize,
    partie: usize,
}

impl Niveau {
    const VIDE: Self = Self {
        frontiere: [0; FRONTIERE_MAX],
        len: 0,
        partie: SANS,
    };
}

/// Le balayeur : on lui pousse le message, il en retient la structure.
///
/// Il ne fait AUCUNE entrée-sortie (C1) : c'est l'appelant qui lit, et qui
/// pousse ce qu'il a lu, dans l'ordre et par morceaux de la taille qu'il veut.
/// Le découpage ne change pas le résultat.
pub struct BodyScanner {
    limites: Limits,
    parties: [Partie; STRUCTURE_PARTS_MAX],
    nb: usize,
    entetes: [u8; ENTETES_MAX],
    utilise: usize,
    pile: [Niveau; STRUCTURE_DEPTH_MAX],
    profondeur: usize,
    ligne: [u8; LIGNE_MAX],
    ligne_len: usize,
    /// Ce que la ligne en cours pèse VRAIMENT, tampon ou pas.
    ligne_octets: u64,
    /// Le dernier octet poussé était un `CR`.
    dernier_cr: bool,
    /// Où commence la ligne en cours.
    position: u64,
    /// On lit l'en-tête d'une partie, et non un corps.
    dans_l_entete: bool,
    /// La partie dont on lit l'en-tête ou le corps, ou [`SANS`] — préambule,
    /// épilogue, ou partie qui n'a pas trouvé de place.
    courante: usize,
}

impl BodyScanner {
    /// Un balayeur neuf, prêt à recevoir le premier octet du message.
    #[must_use]
    pub fn new(limits: &Limits) -> Self {
        let mut balayeur = Self {
            limites: *limits,
            parties: [Partie::VIDE; STRUCTURE_PARTS_MAX],
            nb: 0,
            entetes: [0; ENTETES_MAX],
            utilise: 0,
            pile: [Niveau::VIDE; STRUCTURE_DEPTH_MAX],
            profondeur: 0,
            ligne: [0; LIGNE_MAX],
            ligne_len: 0,
            ligne_octets: 0,
            dernier_cr: false,
            position: 0,
            dans_l_entete: true,
            courante: 0,
        };
        // Le message lui-même est la partie zéro : la structure qu'IMAP rend est
        // la sienne.
        balayeur.parties[0] = Partie {
            ouverte: true,
            ..Partie::VIDE
        };
        balayeur.nb = 1;
        balayeur
    }

    /// Pousse un morceau du message.
    ///
    /// Les morceaux se suivent : le découpage est libre, et ne change rien.
    pub fn push(&mut self, morceau: &[u8]) {
        for octet in morceau {
            self.octet(*octet);
        }
    }

    /// Dit que le message est fini, et ferme ce qui restait ouvert.
    pub fn finish(&mut self) {
        // UNE DERNIÈRE LIGNE SANS `CRLF` RESTE UNE LIGNE : ses octets comptent,
        // sa fin de ligne non — puisqu'il n'y en a pas.
        if self.ligne_octets > 0 {
            self.compter_les_lignes(self.borne_des_lignes());
        }
        let fin = self.position.saturating_add(self.ligne_octets);
        self.fermer(0, fin);
        self.ligne_len = 0;
        self.ligne_octets = 0;
    }

    /// Écrit la structure dans `out`, et rend ce qu'elle occupe.
    ///
    /// # Errors
    ///
    /// [`Error::BufferTooSmall`] si `out` ne suffit pas.
    pub fn write(&self, out: &mut [u8]) -> Result<usize, Error> {
        let mut plume = Plume::neuve(out);
        // LE MESSAGE EST LA PARTIE ZÉRO, et [`BodyScanner::new`] la pose : la
        // reprendre par `unwrap_or` porte cette impossibilité dans la
        // bibliothèque standard plutôt que dans une garde qu'aucun appel
        // n'emprunte.
        let racine = self.parties.first().copied().unwrap_or(Partie::VIDE);
        self.ecrire_partie(&mut plume, 0, &racine)?;
        Ok(plume.ecrits())
    }

    // --- Le balayage ------------------------------------------------------

    fn octet(&mut self, octet: u8) {
        if self.dernier_cr && octet == b'\n' {
            let octets = self.ligne_octets.saturating_add(1);
            self.fin_de_ligne(octets);
            self.ligne_len = 0;
            self.ligne_octets = 0;
            self.dernier_cr = false;
            return;
        }
        self.dernier_cr = octet == b'\r';
        self.ligne_octets = self.ligne_octets.saturating_add(1);
        if let Some(place) = self.ligne.get_mut(self.ligne_len) {
            *place = octet;
            self.ligne_len = self.ligne_len.saturating_add(1);
        }
    }

    /// Traite une ligne complète, longue de `octets` avec son `CRLF`.
    fn fin_de_ligne(&mut self, octets: u64) {
        let debut = self.position;
        let fin = debut.saturating_add(octets);
        self.position = fin;
        let texte = self.ligne.get(..self.ligne_len).unwrap_or_default();
        let texte = texte.strip_suffix(b"\r").unwrap_or(texte);
        let longueur = texte.len();
        if self.dans_l_entete {
            self.compter_les_lignes(self.borne_des_lignes());
            if longueur == 0 {
                self.fin_d_entete(fin);
            } else {
                self.retenir(longueur);
            }
            return;
        }
        // LA FRONTIÈRE EMPORTE LE `CRLF` QUI LA PRÉCÈDE (RFC 2046 §5.1.1) : il
        // n'appartient pas au corps qu'elle termine.
        match self.frontiere(texte) {
            Some((niveau, close)) => {
                // La ligne de frontière appartient au corps du `multipart` qui
                // la porte, et à rien de plus profond.
                let ouvert = self.pile.get(niveau).map_or(SANS, |niveau| niveau.partie);
                self.compter_les_lignes(ouvert.saturating_add(1));
                self.au_bord(ouvert, close, debut.saturating_sub(2));
                self.profondeur = match close {
                    true => niveau,
                    false => niveau.saturating_add(1),
                };
            }
            None => self.compter_les_lignes(SANS),
        }
    }

    /// Jusqu'où une ligne compte.
    ///
    /// UNE LIGNE D'EN-TÊTE N'EST PAS DANS LE CORPS QU'ELLE OUVRE, mais elle est
    /// bien dans celui de tout ce qui la contient : c'est ce qui fait qu'un
    /// `message/rfc822` compte les lignes du message entier, en-tête compris,
    /// comme la RFC 9051 §7.5.2 le veut.
    fn borne_des_lignes(&self) -> usize {
        match self.dans_l_entete {
            true => self.courante,
            false => SANS,
        }
    }

    /// Retient dans l'arène les `longueur` premiers octets de la ligne en cours,
    /// suivis du `CRLF` qui la termine.
    ///
    /// Ce qui dépasse [`ENTETE_DE_PARTIE_MAX`] ou l'arène est perdu : la partie
    /// sera décrite par les défauts de la RFC 2045, ce qui est faux mais lisible
    /// — au lieu d'une réponse qu'un client ne saurait pas finir de lire.
    fn retenir(&mut self, longueur: usize) {
        let Some(partie) = self.parties.get_mut(self.courante) else {
            return;
        };
        if partie.entete_len == 0 {
            partie.entete = self.utilise;
        }
        let place = ENTETE_DE_PARTIE_MAX.saturating_sub(partie.entete_len);
        let voulu = longueur.saturating_add(2).min(place);
        let debut = self.utilise;
        let fin = debut.saturating_add(voulu);
        let (Some(arene), Some(ligne)) =
            (self.entetes.get_mut(debut..fin), self.ligne.get(..longueur))
        else {
            return;
        };
        for (place, octet) in arene
            .iter_mut()
            .zip(ligne.iter().chain(b"\r\n".iter()).copied())
        {
            *place = octet;
        }
        self.utilise = fin;
        partie.entete_len = partie.entete_len.saturating_add(voulu);
    }

    /// L'en-tête de la partie courante s'achève : on sait enfin ce qu'elle est.
    fn fin_d_entete(&mut self, corps: u64) {
        self.dans_l_entete = false;
        let index = self.courante;
        // La ligne vide fait partie de l'en-tête retenu : `Message::parse`
        // attend un bloc qui se termine, et non un bloc qui s'arrête.
        self.retenir(0);
        let (genre, frontiere, longueur) = {
            let entete = self
                .parties
                .get(index)
                .map_or(&[][..], |partie| self.entete_de(partie));
            let (genre, frontiere) = analyser(entete, &self.limites);
            let mut copie = [0_u8; FRONTIERE_MAX];
            let longueur = frontiere.len().min(FRONTIERE_MAX);
            for (place, octet) in copie
                .iter_mut()
                .zip(frontiere.get(..longueur).unwrap_or_default())
            {
                *place = *octet;
            }
            (genre, copie, longueur)
        };
        // UNE PROFONDEUR ÉPUISÉE NE FAIT PAS DISPARAÎTRE LE CONTENU : le
        // `multipart` qu'on n'a pas pu empiler est décrit comme le contenu
        // simple qu'il est devenu pour nous, avec sa vraie taille, plutôt que
        // comme une coquille sans filles.
        let genre = match genre {
            Genre::Multipart if !self.empiler(index, frontiere.get(..longueur)) => Genre::Feuille,
            autre => autre,
        };
        let Some(place) = self.parties.get_mut(index) else {
            // Plus de place dans la table : on ne décrira pas cette partie, mais
            // on continue de lire ce qu'elle contient.
            return;
        };
        place.corps_debut = corps;
        place.genre = genre;
        match genre {
            // Ce qui suit est le préambule : il n'appartient à aucune fille.
            Genre::Multipart => self.courante = SANS,
            Genre::Message => {
                // Le corps de cette partie EST un message : on en lit l'en-tête.
                self.courante = self.nouvelle(index, corps);
                self.dans_l_entete = true;
            }
            Genre::Feuille => {}
        }
    }

    /// Compte la ligne pour la partie courante et pour tout ce qui la contient.
    ///
    /// Un `message/rfc822` compte les lignes du message qu'il porte, en-tête
    /// compris : la remontée n'est donc pas un détail, c'est sa définition.
    /// LES PARTIES OUVERTES SONT EXACTEMENT CE QUI CONTIENT LA LIGNE. À tout
    /// instant, ce qui n'est pas encore fermé est la partie en cours et la
    /// chaîne de celles qui la portent — remonter les parents parcourrait la
    /// même liste, avec une borne de plus à ne pas manquer.
    fn compter_les_lignes(&mut self, borne: usize) {
        for (rang, partie) in self.parties.iter_mut().enumerate() {
            if partie.ouverte && rang < borne {
                partie.lignes = partie.lignes.saturating_add(1);
            }
        }
    }

    /// Une frontière : laquelle, et est-ce la dernière ?
    fn frontiere(&self, texte: &[u8]) -> Option<(usize, bool)> {
        let reste = texte.strip_prefix(b"--")?;
        // LA PLUS PROFONDE D'ABORD : c'est celle qui est ouverte.
        for (niveau, ouvert) in self.pile.iter().enumerate().take(self.profondeur).rev() {
            let attendue = ouvert.frontiere.get(..ouvert.len).unwrap_or_default();
            let Some(apres) = reste.strip_prefix(attendue) else {
                continue;
            };
            let apres = apres.trim_ascii_end();
            if apres.is_empty() {
                return Some((niveau, false));
            }
            if apres == b"--" {
                return Some((niveau, true));
            }
        }
        None
    }

    /// Une frontière du niveau `niveau` vient d'être lue.
    fn au_bord(&mut self, ouvert: usize, close: bool, fin: u64) {
        self.fermer(ouvert.saturating_add(1), fin);
        if close {
            // LA DERNIÈRE FRONTIÈRE NE FERME PAS LE `multipart` LUI-MÊME. Son
            // contenu, c'est ce que son propre parent délimite : son délimiteur
            // de fin et l'épilogue qui le suit en font partie. Le clore ici
            // rendrait un `BODY[1]` amputé de sa dernière frontière — une entité
            // que le client ne saurait pas relire. Il se fermera avec la
            // frontière du dessus, ou avec le message.
            self.courante = SANS;
            self.dans_l_entete = false;
            return;
        }
        // UNE PARTIE COMMENCE APRÈS SA FRONTIÈRE, jamais avant : `fin` est là où
        // s'arrête ce qui PRÉCÈDE, `CRLF` de frontière déduit. La position, elle,
        // est déjà passée à la ligne suivante.
        self.courante = self.nouvelle(ouvert, self.position);
        // ON LIT L'EN-TÊTE MÊME SANS PLACE POUR LE RETENIR : ce qui suit une
        // frontière est un en-tête, que la table soit pleine ou non. Le prendre
        // pour du corps ferait de ses lignes des lignes de corps.
        self.dans_l_entete = true;
    }

    /// Ferme toutes les parties ouvertes de rang au moins `borne`.
    ///
    /// # POURQUOI UN RANG SUFFIT
    ///
    /// Une partie fille est toujours créée APRÈS celle qui la porte : son rang
    /// est donc plus grand. Ce qui est ouvert au-delà d'un rang est exactement
    /// ce que ce rang contient — l'ordre de la table dit l'emboîtement, et il
    /// n'y a aucune chaîne de parents à remonter sans se tromper.
    ///
    /// # COMPTER LES LIGNES, C'EST COMPTER LES LIGNES
    ///
    /// Le `CRLF` qui précède une frontière lui appartient : il quitte donc la
    /// TAILLE du corps. Mais il ne quitte pas son nombre de LIGNES — ce qu'il
    /// terminait reste une ligne, simplement une ligne sans fin. Retrancher les
    /// deux ferait disparaître la dernière ligne de chaque partie.
    fn fermer(&mut self, borne: usize, fin: u64) {
        for (rang, partie) in self.parties.iter_mut().enumerate() {
            if partie.ouverte && rang >= borne {
                partie.ouverte = false;
                partie.octets = fin.saturating_sub(partie.corps_debut);
            }
        }
    }

    /// Ouvre un niveau pour un `multipart`, ou dit que la pile est pleine.
    ///
    /// LA PROFONDEUR SE DÉCIDE ICI, et nulle part ailleurs : la vérifier chez
    /// l'appelant ferait de ce refus une garde qu'aucun message ne pourrait
    /// faire céder, c'est-à-dire une affirmation que rien ne vérifie.
    fn empiler(&mut self, index: usize, frontiere: Option<&[u8]>) -> bool {
        let (Some(niveau), Some(frontiere)) = (self.pile.get_mut(self.profondeur), frontiere)
        else {
            return false;
        };
        niveau.len = frontiere.len();
        niveau.partie = index;
        for (place, octet) in niveau.frontiere.iter_mut().zip(frontiere) {
            *place = *octet;
        }
        self.profondeur = self.profondeur.saturating_add(1);
        true
    }

    /// Ouvre une partie fille, ou dit qu'il n'y a plus de place.
    fn nouvelle(&mut self, parent: usize, debut: u64) -> usize {
        let index = self.nb;
        let Some(place) = self.parties.get_mut(index) else {
            return SANS;
        };
        *place = Partie {
            parent,
            debut,
            corps_debut: debut,
            ouverte: true,
            ..Partie::VIDE
        };
        self.nb = self.nb.saturating_add(1);
        index
    }

    /// L'en-tête retenu d'une partie.
    fn entete_de(&self, partie: &Partie) -> &[u8] {
        let fin = partie.entete.saturating_add(partie.entete_len);
        self.entetes.get(partie.entete..fin).unwrap_or_default()
    }
}

// --- L'écriture -----------------------------------------------------------

/// Ce qu'on rend d'une partie qu'on n'a pas su décrire.
///
/// **Ce n'est pas une commodité** : la grammaire de §7.5.2 exige au moins un
/// corps dans un `multipart`, et un client qui n'en trouve aucun ne peut plus
/// lire la suite de la réponse. Dire « rien » dans une forme licite vaut mieux
/// que de rompre le dialogue.
const CORPS_VIDE: &[u8] =
    b"(\"TEXT\" \"PLAIN\" (\"CHARSET\" \"US-ASCII\") NIL NIL \"7BIT\" 0 0 NIL NIL NIL NIL)";

/// Ce qu'on rend d'une enveloppe qu'on n'a pas su composer.
const ENVELOPPE_VIDE: &[u8] = b"(NIL NIL NIL NIL NIL NIL NIL NIL NIL NIL)";

impl BodyScanner {
    /// Écrit la description d'une partie.
    ///
    /// # LA RÉCURSION SE TERMINE PARCE QUE LES RANGS MONTENT
    ///
    /// Une fille est créée après ce qui la porte : son rang est strictement plus
    /// grand. La descente ne peut donc pas revenir sur ses pas, et une borne de
    /// profondeur serait ici une garde qu'aucun message ne pourrait faire céder.
    fn ecrire_partie(
        &self,
        plume: &mut Plume<'_>,
        index: usize,
        partie: &Partie,
    ) -> Result<(), Error> {
        let entete = self.entete_de(partie);
        let message = Message::parse(entete, &self.limites).ok();
        let contenu = message
            .as_ref()
            .and_then(|message| valeur_de(message, b"content-type"));
        let (principal, sous, params) = match contenu {
            Some(valeur) => type_de(valeur),
            // RFC 2045 §5.2 : sans `Content-Type:`, c'est du texte en US-ASCII —
            // et le dire explicitement épargne au client d'avoir à connaître ce
            // défaut.
            None => (&b"text"[..], &b"plain"[..], &b"; charset=us-ascii"[..]),
        };
        match partie.genre {
            Genre::Multipart => self.ecrire_multipart(plume, index, entete, sous, params),
            Genre::Feuille => {
                // UN `multipart` QU'ON N'A PAS SU OUVRIR N'EN EST PLUS UN : ni
                // frontière, ni place pour l'emboîter. MIME dit quoi faire d'une
                // entité qu'on ne sait pas interpréter — la traiter en
                // `application/octet-stream` (RFC 2049 §2) — et c'est aussi la
                // seule forme qu'un client ne lira pas de travers : un type
                // `MULTIPART` suivi d'une taille n'existe pas dans la grammaire
                // de §7.5.2.
                let (principal, sous) = match principal.eq_ignore_ascii_case(b"multipart") {
                    true => (&b"application"[..], &b"octet-stream"[..]),
                    false => (principal, sous),
                };
                plume.pousser(b"(")?;
                ecrire_le_tronc(plume, message.as_ref(), principal, sous, params)?;
                plume.pousser(b" ")?;
                plume.nombre(partie.octets)?;
                // LES LIGNES NE SE COMPTENT QUE POUR DU TEXTE : la grammaire ne
                // les admet nulle part ailleurs, et les rendre quand même ferait
                // lire au client un champ à la place d'un autre.
                if principal.eq_ignore_ascii_case(b"text") {
                    plume.pousser(b" ")?;
                    plume.nombre(partie.lignes)?;
                }
                ecrire_la_queue(plume, message.as_ref(), true)
            }
            Genre::Message => {
                plume.pousser(b"(")?;
                ecrire_le_tronc(plume, message.as_ref(), principal, sous, params)?;
                plume.pousser(b" ")?;
                plume.nombre(partie.octets)?;
                plume.pousser(b" ")?;
                let enfant = self.enfant(index);
                self.ecrire_l_enveloppe(plume, enfant.as_ref().map(|(_, fille)| fille))?;
                plume.pousser(b" ")?;
                match enfant {
                    Some((rang, fille)) => self.ecrire_partie(plume, rang, &fille)?,
                    None => plume.pousser(CORPS_VIDE)?,
                }
                plume.pousser(b" ")?;
                plume.nombre(partie.lignes)?;
                ecrire_la_queue(plume, message.as_ref(), true)
            }
        }
    }

    /// Écrit un `multipart` : ses filles, puis ce qu'il est.
    fn ecrire_multipart(
        &self,
        plume: &mut Plume<'_>,
        index: usize,
        entete: &[u8],
        sous: &[u8],
        params: &[u8],
    ) -> Result<(), Error> {
        plume.pousser(b"(")?;
        let mut filles = 0_usize;
        for (rang, fille) in self.parties.iter().enumerate().take(self.nb) {
            if fille.parent == index {
                self.ecrire_partie(plume, rang, fille)?;
                filles = filles.saturating_add(1);
            }
        }
        if filles == 0 {
            plume.pousser(CORPS_VIDE)?;
        }
        plume.pousser(b" ")?;
        jeton_cite(plume, jeton(sous, b"mixed"))?;
        plume.pousser(b" ")?;
        ecrire_parametres(plume, params)?;
        let message = Message::parse(entete, &self.limites).ok();
        // Un `multipart` n'a pas de somme MD5 : la grammaire ne lui en donne pas.
        ecrire_la_queue(plume, message.as_ref(), false)
    }

    /// Écrit l'enveloppe du message porté par une partie `message/rfc822`.
    fn ecrire_l_enveloppe(
        &self,
        plume: &mut Plume<'_>,
        enfant: Option<&Partie>,
    ) -> Result<(), Error> {
        let entete = enfant
            .map(|fille| self.entete_de(fille))
            .unwrap_or_default();
        let marque = plume.marque();
        let limites = self.limites;
        if plume
            .deleguer(|place| write_envelope(entete, place, &limites))
            .is_err()
        {
            // MÊME RAISON QUE PARTOUT ICI : une enveloppe absente couperait la
            // réponse au milieu d'un élément. Dix `NIL` disent « je ne sais
            // rien » dans une forme que la grammaire admet.
            plume.revenir(marque);
            plume.pousser(ENVELOPPE_VIDE)?;
        }
        Ok(())
    }

    /// La première fille d'une partie, et son rang.
    fn enfant(&self, index: usize) -> Option<(usize, Partie)> {
        self.parties
            .iter()
            .enumerate()
            .take(self.nb)
            .find(|(_, fille)| fille.parent == index)
            .map(|(rang, fille)| (rang, *fille))
    }
}

/// Type, sous-type, paramètres, identifiant, description, encodage.
fn ecrire_le_tronc(
    plume: &mut Plume<'_>,
    message: Option<&Message<'_>>,
    principal: &[u8],
    sous: &[u8],
    params: &[u8],
) -> Result<(), Error> {
    jeton_cite(plume, jeton(principal, b"text"))?;
    plume.pousser(b" ")?;
    jeton_cite(plume, jeton(sous, b"plain"))?;
    plume.pousser(b" ")?;
    ecrire_parametres(plume, params)?;
    plume.pousser(b" ")?;
    ecrire_texte(plume, champ(message, b"content-id"))?;
    plume.pousser(b" ")?;
    ecrire_texte(plume, champ(message, b"content-description"))?;
    plume.pousser(b" ")?;
    let encodage = champ(message, b"content-transfer-encoding")
        .map(<[u8]>::trim_ascii)
        .unwrap_or_default();
    jeton_cite(plume, jeton(mot(encodage), b"7bit"))
}

/// Somme MD5, disposition, langue, emplacement — et la parenthèse fermante.
///
/// LA SOMME MD5 EST TOUJOURS `NIL`, et c'est une affirmation, pas un oubli : la
/// calculer demanderait de relire tout le message une seconde fois, pour une
/// valeur que la RFC 9051 laisse facultative et qu'aucun client n'attend.
fn ecrire_la_queue(
    plume: &mut Plume<'_>,
    message: Option<&Message<'_>>,
    md5: bool,
) -> Result<(), Error> {
    if md5 {
        plume.pousser(b" NIL")?;
    }
    plume.pousser(b" ")?;
    ecrire_disposition(plume, champ(message, b"content-disposition"))?;
    // La langue et l'emplacement ne se lisent pas encore : `NIL` dit qu'on ne
    // sait pas, ce qui est vrai.
    plume.pousser(b" NIL NIL)")
}

/// Écrit un jeton MIME entre guillemets, en capitales.
fn jeton_cite(plume: &mut Plume<'_>, texte: &[u8]) -> Result<(), Error> {
    plume.chaine(texte, Forme::Jeton)
}

/// La valeur brute d'un champ, si le message a été lu.
fn champ<'a>(message: Option<&Message<'a>>, nom: &[u8]) -> Option<&'a [u8]> {
    message.and_then(|message| valeur_de(message, nom))
}

/// Ce jeton, ou le défaut quand il n'y en a pas.
fn jeton<'a>(valeur: &'a [u8], defaut: &'a [u8]) -> &'a [u8] {
    if valeur.is_empty() { defaut } else { valeur }
}

/// Le premier mot d'une valeur : ce qui précède le premier blanc ou séparateur.
fn mot(valeur: &[u8]) -> &[u8] {
    let fin = valeur
        .iter()
        .position(|octet| !est_jeton(*octet))
        .unwrap_or(valeur.len());
    valeur.get(..fin).unwrap_or_default()
}

/// Écrit une chaîne, ou `NIL` si le champ est absent ou vide.
fn ecrire_texte(plume: &mut Plume<'_>, valeur: Option<&[u8]>) -> Result<(), Error> {
    let Some(valeur) = valeur.map(<[u8]>::trim_ascii).filter(|v| !v.is_empty()) else {
        return plume.pousser(b"NIL");
    };
    plume.chaine(valeur, Forme::Texte)
}

/// Écrit la disposition : `("attachment" ("FILENAME" "x.pdf"))`, ou `NIL`.
fn ecrire_disposition(plume: &mut Plume<'_>, valeur: Option<&[u8]>) -> Result<(), Error> {
    let Some(valeur) = valeur else {
        return plume.pousser(b"NIL");
    };
    let (avant, params) = couper(valeur, b';');
    let genre = mot(avant.trim_ascii());
    if genre.is_empty() {
        return plume.pousser(b"NIL");
    }
    plume.pousser(b"(")?;
    jeton_cite(plume, genre)?;
    plume.pousser(b" ")?;
    ecrire_parametres(plume, params)?;
    plume.pousser(b")")
}

/// Type, sous-type et paramètres bruts d'un `Content-Type:`.
fn type_de(valeur: &[u8]) -> (&[u8], &[u8], &[u8]) {
    let (avant, params) = couper(valeur, b';');
    let (principal, reste) = couper(avant, b'/');
    // La barre appartient au séparateur, pas au sous-type.
    let sous = reste.get(1..).unwrap_or_default();
    (mot(principal.trim_ascii()), mot(sous.trim_ascii()), params)
}

/// Coupe au premier `separateur` : ce qui précède, et ce qui suit lui compris.
fn couper(valeur: &[u8], separateur: u8) -> (&[u8], &[u8]) {
    match valeur.iter().position(|octet| *octet == separateur) {
        Some(rang) => (
            valeur.get(..rang).unwrap_or_default(),
            valeur.get(rang..).unwrap_or_default(),
        ),
        None => (valeur, &[]),
    }
}

/// Un octet qui peut faire un jeton MIME (RFC 2045 §5.1).
fn est_jeton(octet: u8) -> bool {
    octet > b' '
        && octet < 0x7F
        && !matches!(
            octet,
            b'(' | b')'
                | b'<'
                | b'>'
                | b'@'
                | b','
                | b';'
                | b':'
                | b'\\'
                | b'"'
                | b'/'
                | b'['
                | b']'
                | b'?'
                | b'='
        )
}

/// Parcourt les paramètres, et donne chaque `nom=valeur` à `voir`.
///
/// # UN SEUL LECTEUR
///
/// Chercher un paramètre et les écrire tous sont la même lecture. Deux
/// parcours du même texte finiraient par ne plus dire la même chose — et c'est
/// exactement le défaut qu'un pré-contrôle avait déjà introduit ailleurs.
fn parametres<'a>(params: &'a [u8], mut voir: impl FnMut(&'a [u8], &'a [u8], bool) -> bool) {
    let mut i = 0_usize;
    while i < params.len() {
        let octet = params.get(i).copied().unwrap_or(0);
        if !est_jeton(octet) {
            i = i.saturating_add(1);
            continue;
        }
        let debut = i;
        while i < params.len() && est_jeton(params.get(i).copied().unwrap_or(0)) {
            i = i.saturating_add(1);
        }
        let nom = params.get(debut..i).unwrap_or_default();
        let mut j = saute_le_blanc(params, i);
        if params.get(j).copied() != Some(b'=') {
            continue;
        }
        j = saute_le_blanc(params, j.saturating_add(1));
        let citee = params.get(j).copied() == Some(b'"');
        let (valeur, apres) = if citee {
            let (contenu, apres) = fin_de_chaine(params, j);
            (params.get(j.saturating_add(1)..contenu), apres)
        } else {
            let debut = j;
            while j < params.len() && est_jeton(params.get(j).copied().unwrap_or(0)) {
                j = j.saturating_add(1);
            }
            (params.get(debut..j), j)
        };
        i = apres.max(i);
        if voir(nom, valeur.unwrap_or_default(), citee) {
            return;
        }
    }
}

/// Où finit le CONTENU d'une chaîne citée, et où reprend la lecture.
///
/// Les deux rangs diffèrent d'un octet quand la chaîne se ferme, et pas quand
/// elle ne se ferme pas — les confondre coûterait le dernier octet d'une valeur
/// laissée ouverte.
fn fin_de_chaine(texte: &[u8], debut: usize) -> (usize, usize) {
    let mut i = debut.saturating_add(1);
    while i < texte.len() {
        match texte.get(i).copied().unwrap_or(0) {
            b'\\' => i = i.saturating_add(2),
            b'"' => return (i, i.saturating_add(1)),
            _ => i = i.saturating_add(1),
        }
    }
    (texte.len(), texte.len())
}

/// Le premier rang qui n'est pas un blanc, à partir de `debut`.
fn saute_le_blanc(texte: &[u8], debut: usize) -> usize {
    let mut i = debut;
    while matches!(texte.get(i).copied(), Some(b' ' | b'\t' | b'\r' | b'\n')) {
        i = i.saturating_add(1);
    }
    i
}

/// La valeur d'un paramètre, s'il y en a un.
fn parametre<'a>(params: &'a [u8], nom: &[u8]) -> Option<&'a [u8]> {
    let mut trouve = None;
    parametres(params, |vu, valeur, _| {
        if vu.eq_ignore_ascii_case(nom) {
            trouve = Some(valeur);
            return true;
        }
        false
    });
    trouve
}

/// Écrit la liste des paramètres, ou `NIL` s'il n'y en a aucun.
fn ecrire_parametres(plume: &mut Plume<'_>, params: &[u8]) -> Result<(), Error> {
    let marque = plume.marque();
    plume.pousser(b"(")?;
    let mut ecrits = 0_usize;
    let mut faute = Ok(());
    parametres(params, |nom, valeur, citee| {
        let mut ecrire = || {
            if ecrits > 0 {
                plume.pousser(b" ")?;
            }
            jeton_cite(plume, nom)?;
            plume.pousser(b" ")?;
            plume.chaine(valeur, if citee { Forme::Source } else { Forme::Texte })
        };
        match ecrire() {
            Ok(()) => {
                ecrits = ecrits.saturating_add(1);
                false
            }
            Err(erreur) => {
                faute = Err(erreur);
                true
            }
        }
    });
    faute?;
    if ecrits == 0 {
        // ON REVIENT PLUTÔT QUE DE DEVINER : `()` n'est pas une liste vide dans
        // la grammaire de §7.5.2, c'est une faute de syntaxe.
        plume.revenir(marque);
        return plume.pousser(b"NIL");
    }
    plume.pousser(b")")
}

/// Ce qu'un en-tête de partie dit d'elle : son genre, et sa frontière.
fn analyser<'a>(entete: &'a [u8], limites: &Limits) -> (Genre, &'a [u8]) {
    let Ok(message) = Message::parse(entete, limites) else {
        return (Genre::Feuille, &[]);
    };
    let Some(valeur) = valeur_de(&message, b"content-type") else {
        return (Genre::Feuille, &[]);
    };
    let (principal, sous, params) = type_de(valeur);
    if principal.eq_ignore_ascii_case(b"multipart") {
        // UN `multipart` SANS FRONTIÈRE N'A PAS DE FILLES : on ne saurait pas où
        // elles commencent. Le décrire comme un contenu simple dit ce qu'il est
        // devenu, avec sa vraie taille, plutôt que d'inventer un découpage.
        return match parametre(params, b"boundary") {
            Some(frontiere) if !frontiere.is_empty() => (Genre::Multipart, frontiere),
            _ => (Genre::Feuille, &[]),
        };
    }
    if principal.eq_ignore_ascii_case(b"message") && sous.eq_ignore_ascii_case(b"rfc822") {
        return (Genre::Message, &[]);
    }
    (Genre::Feuille, &[])
}

/// Ce qu'une partie porte : où, sous quel encodage, et si c'est du texte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BodyPart<'a> {
    /// Où son corps commence, dans le message.
    pub start: u64,
    /// Où il finit.
    pub end: u64,
    /// Son `Content-Transfer-Encoding`, tel qu'il est écrit.
    pub encoding: &'a [u8],
    /// Est-ce du texte ? Une pièce jointe binaire ne se cherche pas par son
    /// texte, et la chercher quand même rendrait des correspondances qui n'en
    /// sont pas.
    pub text: bool,
}

impl BodyScanner {
    /// Combien de parties la structure décrit.
    #[must_use]
    pub fn part_count(&self) -> usize {
        self.nb
    }

    /// La partie qu'un chemin désigne, si elle porte un contenu.
    ///
    /// Un chemin vide désigne le message lui-même — ce que `BINARY[]` demande.
    #[must_use]
    pub fn part_of(&self, chemin: &[u32]) -> Option<BodyPart<'_>> {
        self.part(self.resoudre(chemin)?)
    }

    /// La partie de rang `index`, si elle porte un contenu.
    ///
    /// # LES `multipart` ET LES `message/rfc822` NE PORTENT RIEN EN PROPRE
    ///
    /// Leur contenu, ce sont leurs filles — que ce parcours rend aussi. Les
    /// rendre eux-mêmes ferait compter deux fois les mêmes octets, et un
    /// `SEARCH BODY` trouverait deux fois ce qui n'est écrit qu'une.
    #[must_use]
    pub fn part(&self, index: usize) -> Option<BodyPart<'_>> {
        let partie = self.parties.get(index).filter(|_| index < self.nb)?;
        if partie.genre != Genre::Feuille {
            return None;
        }
        let entete = self.entete_de(partie);
        let message = Message::parse(entete, &self.limites).ok();
        let contenu = message
            .as_ref()
            .and_then(|message| valeur_de(message, b"content-type"));
        // RFC 2045 §5.2 : sans `Content-Type:`, c'est du texte.
        let text = match contenu {
            Some(valeur) => type_de(valeur).0.eq_ignore_ascii_case(b"text"),
            None => true,
        };
        let encodage = message
            .as_ref()
            .and_then(|message| valeur_de(message, b"content-transfer-encoding"))
            .map(<[u8]>::trim_ascii)
            .unwrap_or_default();
        Some(BodyPart {
            start: partie.corps_debut,
            end: partie.corps_debut.saturating_add(partie.octets),
            encoding: mot(encodage),
            text,
        })
    }
}

/// Ce qu'on veut d'une partie désignée (RFC 9051 §6.4.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodySpan {
    /// `BODY[1]` — son contenu.
    Content,
    /// `BODY[1.MIME]` — ses lignes d'en-tête MIME.
    Mime,
    /// `BODY[1.HEADER]` — l'en-tête du message qu'elle encapsule.
    Header,
    /// `BODY[1.TEXT]` — le corps du message qu'elle encapsule.
    Text,
}

impl BodyScanner {
    /// Où se trouve la partie que `chemin` désigne, ou `None` si elle n'existe
    /// pas.
    ///
    /// Le chemin est celui de §6.4.5 : `1.2` est la deuxième partie de la
    /// première. **Un `message/rfc822` ne compte pas pour un niveau** — ses
    /// numéros sont ceux du message qu'il porte, comme s'il était seul.
    ///
    /// # CE QUI N'EXISTE PAS N'EST PAS UNE FAUTE
    ///
    /// §6.4.5 admet `NIL` pour une section absente : un client qui demande une
    /// partie qu'un autre a vue dans une structure périmée ne fait rien de mal,
    /// et le lui dire par une erreur ferait échouer toute la commande.
    #[must_use]
    pub fn span(&self, chemin: &[u32], quoi: BodySpan) -> Option<(u64, u64)> {
        let index = self.resoudre(chemin)?;
        // `resoudre` ne rend qu'un rang de la table : le reprendre par
        // `unwrap_or` porte cette impossibilité dans la bibliothèque standard
        // plutôt que dans une garde qu'aucun chemin n'emprunte.
        let partie = self.parties.get(index).copied().unwrap_or(Partie::VIDE);
        match quoi {
            BodySpan::Content => Some((
                partie.corps_debut,
                partie.corps_debut.saturating_add(partie.octets),
            )),
            BodySpan::Mime => Some((partie.debut, partie.corps_debut)),
            // `HEADER` et `TEXT` ne veulent rien dire ailleurs que sur un
            // message encapsulé : c'est SON en-tête et SON corps qu'ils
            // désignent, pas ceux de la partie qui le porte.
            BodySpan::Header | BodySpan::Text => {
                let (_, porte) = self.enfant(index)?;
                match (partie.genre, quoi) {
                    (Genre::Message, BodySpan::Header) => Some((porte.debut, porte.corps_debut)),
                    (Genre::Message, _) => Some((
                        porte.corps_debut,
                        porte.corps_debut.saturating_add(porte.octets),
                    )),
                    _ => None,
                }
            }
        }
    }

    /// La partie qu'un chemin désigne.
    fn resoudre(&self, chemin: &[u32]) -> Option<usize> {
        let mut courant = 0_usize;
        let mut reste = chemin;
        while let Some((numero, suite)) = reste.split_first() {
            // UN `message/rfc822` NE COMPTE PAS POUR UN NIVEAU : on entre dans
            // le message qu'il porte, et l'on numérote ses parties à lui.
            if self.genre_de(courant) == Genre::Message {
                courant = self.enfant(courant)?.0;
            }
            if self.genre_de(courant) == Genre::Multipart {
                courant = self.nieme(courant, *numero)?;
            } else {
                // Un contenu simple n'a qu'une partie — lui-même — et rien ne
                // peut la suivre.
                if *numero != 1 || !suite.is_empty() {
                    return None;
                }
            }
            reste = suite;
        }
        Some(courant)
    }

    /// Ce qu'une partie est.
    fn genre_de(&self, index: usize) -> Genre {
        self.parties
            .get(index)
            .map_or(Genre::Feuille, |partie| partie.genre)
    }

    /// La `numero`-ième fille d'une partie, à partir de un.
    fn nieme(&self, index: usize, numero: u32) -> Option<usize> {
        // `unwrap_or` PLUTÔT QU'UN `?` : un `u32` tient toujours dans le `usize`
        // des cibles servies, et le refus qu'un `?` écrirait là serait une garde
        // qu'aucun chemin ne pourrait faire céder. Une valeur qu'aucune fille
        // n'atteint dit la même chose, et se vérifie.
        let rang = usize::try_from(numero.checked_sub(1)?).unwrap_or(usize::MAX);
        self.parties
            .iter()
            .enumerate()
            .take(self.nb)
            .filter(|(_, fille)| fille.parent == index)
            .map(|(rang, _)| rang)
            .nth(rang)
    }
}

/// Compose la `BODYSTRUCTURE` d'un message entier.
///
/// C'est la commodité de celui qui tient déjà tout le message : le serveur, lui,
/// pousse ce qu'il lit dans un [`BodyScanner`] et ne le retient jamais.
///
/// # Errors
///
/// [`Error::BufferTooSmall`] si `out` ne suffit pas.
pub fn write_body_structure(
    message: &[u8],
    out: &mut [u8],
    limits: &Limits,
) -> Result<usize, Error> {
    let mut balayeur = BodyScanner::new(limits);
    balayeur.push(message);
    balayeur.finish();
    balayeur.write(out)
}

#[cfg(test)]
#[path = "structure/tests.rs"]
mod tests;
