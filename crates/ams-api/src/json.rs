// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! L'écriture des représentations JSON (RFC 8259), **sans allocation**.
//!
//! # ÉCHAPPER N'EST PAS UNE FORMALITÉ, C'EST LA SÉCURITÉ ENTIÈRE
//!
//! Presque tout ce que cette API rend vient d'ailleurs : un nom de boîte qu'un
//! client a choisi, un sujet qu'un inconnu a écrit, une adresse qu'un serveur
//! distant a envoyée. Un seul guillemet non échappé dans l'un d'eux ferme la
//! chaîne, et ce qui suit devient de la STRUCTURE — des champs que personne n'a
//! voulus, dans un document que le client croira de nous.
//!
//! C'est la même faute que l'injection SQL, avec le même remède : ne jamais
//! concaténer, toujours passer par un écrivain qui sait ce qu'il écrit.
//!
//! # LA STRUCTURE EST TENUE PAR LE TYPE, ET NON PAR L'APPELANT
//!
//! Un écrivain qui laisserait poser `{` puis `]` produirait un document que
//! personne ne peut lire — et qui partirait tout de même, avec un code 200.
//! [`Json`] refuse : il sait où il est, et une suite impossible se dit plutôt
//! que de s'écrire.
//!
//! Et [`Json::finish`] refuse un document inachevé. Un JSON tronqué servi avec
//! un 200 est pire qu'une erreur : le client le lit à moitié, et croit avoir
//! tout.
//!
//! # PAS DE NOMBRES À VIRGULE
//!
//! §6 de RFC 8259 laisse la précision des nombres à l'implémentation, et prévient
//! que « numbers that are integers and are in the range [-(2^53)+1, (2^53)-1] »
//! sont les seuls dont l'interopérabilité soit acquise. Un flottant écrit ici
//! serait relu ailleurs avec une autre précision, et deux lecteurs ne verraient
//! pas la même valeur.
//!
//! Cette API n'a de toute façon que des entiers à rendre : des comptes, des
//! tailles, des identifiants, des instants. **Ce qui n'existe pas ne peut pas
//! diverger.**

use crate::error::{Error, Reason};

/// Combien de niveaux d'imbrication on accepte.
///
/// Huit. La représentation la plus profonde de cette API — un message, ses
/// parties, leurs paramètres — en compte cinq. Une borne fixe est ce qui permet
/// à la pile d'être un tableau, donc à cette crate de ne rien allouer.
pub const DEPTH_MAX: usize = 8;

/// Un niveau d'imbrication.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Niveau {
    /// Est-ce un objet ? Sinon, c'est un tableau.
    objet: bool,
    /// N'a-t-on encore rien écrit dedans ?
    vide: bool,
    /// Une clé attend-elle sa valeur ?
    clef_posee: bool,
}

/// Un écrivain JSON qui écrit dans le tampon de l'appelant.
#[derive(Debug)]
pub struct Json<'o> {
    /// Où l'on écrit.
    sortie: &'o mut [u8],
    /// Combien on a écrit.
    ecrits: usize,
    /// Les niveaux ouverts.
    niveaux: [Niveau; DEPTH_MAX],
    /// Combien sont ouverts.
    profondeur: usize,
    /// A-t-on écrit une valeur au niveau le plus haut ?
    racine_ecrite: bool,
}

impl<'o> Json<'o> {
    /// Un écrivain qui écrit là.
    #[must_use]
    pub fn new(sortie: &'o mut [u8]) -> Self {
        Self {
            sortie,
            ecrits: 0,
            niveaux: [Niveau {
                objet: false,
                vide: true,
                clef_posee: false,
            }; DEPTH_MAX],
            profondeur: 0,
            racine_ecrite: false,
        }
    }

    /// Ce qui est écrit jusqu'ici.
    #[must_use]
    pub fn written(&self) -> usize {
        self.ecrits
    }

    /// Ouvre un objet.
    ///
    /// # Errors
    ///
    /// Voir [`Json::string`], plus [`Reason::JsonTooDeep`] au-delà de
    /// [`DEPTH_MAX`].
    pub fn begin_object(&mut self) -> Result<(), Error> {
        self.ouvrir(true, b'{')
    }

    /// Ouvre un tableau.
    ///
    /// # Errors
    ///
    /// Voir [`Json::begin_object`].
    pub fn begin_array(&mut self) -> Result<(), Error> {
        self.ouvrir(false, b'[')
    }

    /// Ferme un objet.
    ///
    /// # Errors
    ///
    /// [`Reason::BadJson`] si l'on n'est pas dans un objet, ou si une clé attend
    /// sa valeur ; [`Reason::BufferTooSmall`].
    pub fn end_object(&mut self) -> Result<(), Error> {
        self.fermer(true, b'}')
    }

    /// Ferme un tableau.
    ///
    /// # Errors
    ///
    /// Voir [`Json::end_object`].
    pub fn end_array(&mut self) -> Result<(), Error> {
        self.fermer(false, b']')
    }

    /// Écrit une clé.
    ///
    /// # Errors
    ///
    /// [`Reason::BadJson`] hors d'un objet, ou si une clé attend déjà sa valeur ;
    /// [`Reason::BufferTooSmall`].
    pub fn key(&mut self, nom: &str) -> Result<(), Error> {
        let niveau = self.niveau().ok_or(Error::new(Reason::BadJson))?;
        if !niveau.objet || niveau.clef_posee {
            return Err(Error::new(Reason::BadJson));
        }
        if !niveau.vide {
            self.poser(b',')?;
        }
        self.ecrire_une_chaine(nom)?;
        self.poser(b':')?;
        self.marquer(|niveau| {
            niveau.clef_posee = true;
            niveau.vide = false;
        });
        Ok(())
    }

    /// Écrit une chaîne, échappée.
    ///
    /// # Errors
    ///
    /// [`Reason::BadJson`] si une valeur n'a pas sa place ici ;
    /// [`Reason::BufferTooSmall`].
    pub fn string(&mut self, valeur: &str) -> Result<(), Error> {
        self.avant_une_valeur()?;
        self.ecrire_une_chaine(valeur)?;
        self.apres_une_valeur();
        Ok(())
    }

    /// Écrit un entier.
    ///
    /// # Errors
    ///
    /// Voir [`Json::string`].
    pub fn number(&mut self, valeur: u64) -> Result<(), Error> {
        self.avant_une_valeur()?;
        self.ecrire_un_nombre(valeur)?;
        self.apres_une_valeur();
        Ok(())
    }

    /// Écrit un booléen.
    ///
    /// # Errors
    ///
    /// Voir [`Json::string`].
    pub fn boolean(&mut self, valeur: bool) -> Result<(), Error> {
        self.avant_une_valeur()?;
        let mot: &[u8] = match valeur {
            true => b"true",
            false => b"false",
        };
        self.poser_tout(mot)?;
        self.apres_une_valeur();
        Ok(())
    }

    /// Écrit `null`.
    ///
    /// # LE VIDE ET L'ABSENCE NE SONT PAS LA MÊME CHOSE
    ///
    /// Un sujet vide et un message sans sujet se distinguent : le premier
    /// s'écrit `""`, le second `null`. Les confondre ferait croire à un client
    /// qu'un message a un sujet vide alors qu'il n'en a pas — et la différence
    /// compte quand on répond, ou quand on classe.
    ///
    /// # Errors
    ///
    /// Voir [`Json::string`].
    pub fn null(&mut self) -> Result<(), Error> {
        self.avant_une_valeur()?;
        self.poser_tout(b"null")?;
        self.apres_une_valeur();
        Ok(())
    }

    /// Un champ dont la valeur est une chaîne.
    ///
    /// # Errors
    ///
    /// Voir [`Json::key`] et [`Json::string`].
    pub fn field_str(&mut self, nom: &str, valeur: &str) -> Result<(), Error> {
        self.key(nom)?;
        self.string(valeur)
    }

    /// Un champ dont la valeur est un entier.
    ///
    /// # Errors
    ///
    /// Voir [`Json::key`] et [`Json::number`].
    pub fn field_u64(&mut self, nom: &str, valeur: u64) -> Result<(), Error> {
        self.key(nom)?;
        self.number(valeur)
    }

    /// Un champ dont la valeur est un booléen.
    ///
    /// # Errors
    ///
    /// Voir [`Json::key`] et [`Json::boolean`].
    pub fn field_bool(&mut self, nom: &str, valeur: bool) -> Result<(), Error> {
        self.key(nom)?;
        self.boolean(valeur)
    }

    /// Rend le document, s'il est complet.
    ///
    /// # Errors
    ///
    /// [`Reason::BadJson`] si rien n'a été écrit, ou si un niveau reste ouvert.
    /// **UN DOCUMENT TRONQUÉ NE SORT PAS D'ICI** : servi avec un 200, il ferait
    /// croire à un client qu'il a tout lu.
    pub fn finish(self) -> Result<&'o [u8], Error> {
        if self.profondeur != 0 || !self.racine_ecrite {
            return Err(Error::new(Reason::BadJson));
        }
        self.sortie
            .get(..self.ecrits)
            .ok_or(Error::new(Reason::BufferTooSmall))
    }

    /// Le niveau courant.
    fn niveau(&self) -> Option<Niveau> {
        self.profondeur
            .checked_sub(1)
            .and_then(|rang| self.niveaux.get(rang))
            .copied()
    }

    /// Modifie le niveau courant.
    ///
    /// **LE RANG EST BORNÉ PAR CONSTRUCTION** : la profondeur ne dépasse jamais
    /// [`DEPTH_MAX`], et l'on n'appelle ceci que dans une structure ouverte. Une
    /// garde ici serait une branche qu'aucune écriture ne peut emprunter.
    fn marquer(&mut self, quoi: impl FnOnce(&mut Niveau)) {
        let rang = self.profondeur.saturating_sub(1);
        quoi(&mut self.niveaux[rang]);
    }

    /// Vérifie qu'une valeur a sa place ici, et écrit la virgule s'il en faut
    /// une.
    fn avant_une_valeur(&mut self) -> Result<(), Error> {
        let Some(niveau) = self.niveau() else {
            // **UNE SEULE VALEUR À LA RACINE** : §2 de RFC 8259 dit qu'un texte
            // JSON EST une valeur. Deux à la suite feraient deux documents collés,
            // que chaque lecteur découperait à sa façon.
            if self.racine_ecrite {
                return Err(Error::new(Reason::BadJson));
            }
            return Ok(());
        };
        if niveau.objet && !niveau.clef_posee {
            // Dans un objet, une valeur ne vient qu'après sa clé.
            return Err(Error::new(Reason::BadJson));
        }
        if !niveau.objet && !niveau.vide {
            self.poser(b',')?;
        }
        Ok(())
    }

    /// Note qu'une valeur vient d'être écrite.
    fn apres_une_valeur(&mut self) {
        if self.profondeur == 0 {
            self.racine_ecrite = true;
            return;
        }
        self.marquer(|niveau| {
            niveau.clef_posee = false;
            niveau.vide = false;
        });
    }

    /// Ouvre un niveau.
    fn ouvrir(&mut self, objet: bool, ouvrant: u8) -> Result<(), Error> {
        self.avant_une_valeur()?;
        if self.profondeur >= DEPTH_MAX {
            return Err(Error::new(Reason::JsonTooDeep));
        }
        self.poser(ouvrant)?;
        // Le niveau parent voit une valeur : c'est celle qu'on ouvre.
        self.apres_une_valeur();
        // La borne vient d'être vérifiée : le rang tient dans le tableau.
        self.niveaux[self.profondeur] = Niveau {
            objet,
            vide: true,
            clef_posee: false,
        };
        self.profondeur = self.profondeur.saturating_add(1);
        Ok(())
    }

    /// Ferme un niveau.
    fn fermer(&mut self, objet: bool, fermant: u8) -> Result<(), Error> {
        let niveau = self.niveau().ok_or(Error::new(Reason::BadJson))?;
        // **ON NE FERME PAS UN TABLEAU AVEC UNE ACCOLADE** : le document serait
        // illisible, et le dire ici est la seule occasion de s'en apercevoir.
        if niveau.objet != objet || niveau.clef_posee {
            return Err(Error::new(Reason::BadJson));
        }
        self.poser(fermant)?;
        self.profondeur = self.profondeur.saturating_sub(1);
        Ok(())
    }

    /// Écrit une chaîne entre guillemets, échappée.
    ///
    /// # CE QU'ON ÉCHAPPE, ET POURQUOI CHACUN
    ///
    /// §7 de RFC 8259 EXIGE le guillemet, la barre oblique inverse, et tout ce
    /// qui est sous `U+0020`. En oublier un, c'est laisser fermer la chaîne.
    ///
    /// Trois autres n'y sont pas et s'échappent quand même :
    ///
    /// - `<`, `>` et `&`, parce qu'un document JSON finit parfois dans une page
    ///   HTML — dans un `<script>`, ou mal typé par un intermédiaire. Un `<` non
    ///   échappé y ouvre alors une balise. Le coût est de cinq octets par
    ///   occurrence, et il n'y en a presque jamais.
    /// - `U+2028` et `U+2029`, les séparateurs de ligne d'Unicode. Ils sont
    ///   licites en JSON et **terminent une ligne en JavaScript** : un
    ///   analyseur JavaScript qui lit ce JSON s'y casse. Ce n'est pas notre
    ///   faute, mais c'est notre client qui plante.
    fn ecrire_une_chaine(&mut self, valeur: &str) -> Result<(), Error> {
        self.poser(b'"')?;
        for caractere in valeur.chars() {
            match caractere {
                '"' => self.poser_tout(b"\\\"")?,
                '\\' => self.poser_tout(b"\\\\")?,
                '\n' => self.poser_tout(b"\\n")?,
                '\r' => self.poser_tout(b"\\r")?,
                '\t' => self.poser_tout(b"\\t")?,
                '\u{8}' => self.poser_tout(b"\\b")?,
                '\u{c}' => self.poser_tout(b"\\f")?,
                autre => self.poser_un_caractere(autre)?,
            }
        }
        self.poser(b'"')
    }

    /// Écrit un caractère qui n'a pas d'échappement court.
    fn poser_un_caractere(&mut self, caractere: char) -> Result<(), Error> {
        // Les gênants : ceux que §7 exige, et ceux que l'aval ne supporte pas.
        let gene = matches!(caractere, '<' | '>' | '&' | '\u{2028}' | '\u{2029}')
            || (caractere as u32) < 0x20;
        if !gene {
            let mut place = [0_u8; 4];
            let ecrit = caractere.encode_utf8(&mut place);
            return self.poser_tout(ecrit.as_bytes());
        }
        // `\uXXXX`, en minuscules et sur quatre chiffres. Aucun des caractères
        // concernés ne sort du plan multilingue de base, donc aucun ne demande
        // de paire d'indirection.
        self.poser_tout(b"\\u")?;
        let valeur = caractere as u32;
        for rang in (0..4_u32).rev() {
            let decalage = rang.saturating_mul(4);
            let quartet = (valeur >> decalage) & 0xf;
            let chiffre = match quartet {
                0..=9 => b'0'.saturating_add(u8::try_from(quartet).unwrap_or(0)),
                _ => b'a'
                    .saturating_add(u8::try_from(quartet).unwrap_or(0))
                    .saturating_sub(10),
            };
            self.poser(chiffre)?;
        }
        Ok(())
    }

    /// Écrit un entier en décimal.
    fn ecrire_un_nombre(&mut self, valeur: u64) -> Result<(), Error> {
        // Vingt chiffres suffisent à `u64::MAX`.
        let mut chiffres = [0_u8; 20];
        let mut combien = 0_usize;
        let mut reste = valeur;
        loop {
            let chiffre = u8::try_from(reste % 10).unwrap_or(0);
            // Vingt chiffres suffisent à `u64::MAX` : le rang tient toujours.
            chiffres[combien] = b'0'.saturating_add(chiffre);
            combien = combien.saturating_add(1);
            reste /= 10;
            if reste == 0 {
                break;
            }
        }
        // Ils sont sortis à l'envers.
        for rang in (0..combien).rev() {
            self.poser(chiffres.get(rang).copied().unwrap_or(b'0'))?;
        }
        Ok(())
    }

    /// Pose un octet.
    fn poser(&mut self, octet: u8) -> Result<(), Error> {
        let place = self
            .sortie
            .get_mut(self.ecrits)
            .ok_or(Error::new(Reason::BufferTooSmall))?;
        *place = octet;
        self.ecrits = self.ecrits.saturating_add(1);
        Ok(())
    }

    /// Pose plusieurs octets.
    fn poser_tout(&mut self, octets: &[u8]) -> Result<(), Error> {
        let fin = self.ecrits.saturating_add(octets.len());
        let place = self
            .sortie
            .get_mut(self.ecrits..fin)
            .ok_or(Error::new(Reason::BufferTooSmall))?;
        for (ou, lu) in place.iter_mut().zip(octets) {
            *ou = *lu;
        }
        self.ecrits = fin;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
