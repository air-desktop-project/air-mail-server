// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! La table dynamique de RFC 7541 §2.3.2.
//!
//! # C'EST L'ÉTAT PARTAGÉ D'UNE CONNEXION, ET C'EST CE QUI LE REND DÉLICAT
//!
//! Tous les flux d'une connexion se compriment contre la même table. Une entrée
//! insérée pour la requête d'un flux sert à la requête du suivant. Trois
//! conséquences, et chacune est une règle du code qui suit :
//!
//! 1. **Une désynchronisation ne se rattrape pas.** Si l'encodeur et le décodeur
//!    cessent d'être d'accord sur le contenu de la table, tous les en-têtes
//!    suivants se lisent de travers — et rien ne le signale. C'est pourquoi une
//!    faute HPACK tue la connexion, jamais un seul flux.
//! 2. **Insérer DÉCALE les index.** L'entrée la plus récente porte l'index
//!    soixante-deux ; celle d'avant, soixante-trois. Un décodeur qui insère là
//!    où l'encodeur n'a pas inséré lira tout le reste avec un cran d'écart.
//! 3. **La taille est bornée par CE QU'ON A ANNONCÉ**, pas par ce que le pair
//!    demande. `SETTINGS_HEADER_TABLE_SIZE` est notre chiffre ; une mise à jour
//!    qui le dépasse est une faute, et non une requête à honorer.
//!
//! # POURQUOI UN ARÈNE LINÉAIRE PLUTÔT QU'UN ANNEAU
//!
//! Les octets d'une entrée doivent se rendre d'un seul tenant — un nom coupé en
//! deux ne se compare pas. Un anneau les couperait au bord ; on garde donc une
//! région contiguë, et l'on la RECOMPACTE quand la place manque en queue. La
//! compaction est rare, et son coût est celui d'un déplacement de quatre
//! kibioctets : C7 préfère cela à une lecture en deux morceaux qu'il faudrait
//! traiter partout.

use crate::error::{Cause, Error, ErrorCode};

/// La plus grande table qu'on accepte de tenir, en octets.
///
/// C'est le chiffre qu'on annonce dans `SETTINGS_HEADER_TABLE_SIZE`, et donc la
/// borne qu'une mise à jour de taille ne peut pas franchir. Quatre kibioctets
/// sont la valeur par défaut de §6.5.2, et personne n'a besoin de plus pour des
/// en-têtes.
pub const TABLE_SIZE_MAX: u32 = 4_096;

/// L'arène des octets, en octets.
///
/// Chaque entrée coûte trente-deux octets de plus que ses octets (§4.1) : la
/// somme des noms et des valeurs est donc toujours inférieure à la taille de la
/// table, et une arène de la taille maximale suffit exactement.
const ARENE: usize = TABLE_SIZE_MAX as usize;

/// Combien d'entrées la table peut porter.
///
/// Trente-deux octets par entrée au minimum : une table de quatre kibioctets
/// n'en tient pas plus de cent vingt-huit.
const ENTREES_MAX: usize = ARENE / 32;

/// Ce que §4.1 compte en plus des octets d'une entrée.
const SURCOUT: u32 = 32;

/// Où une entrée vit dans l'arène.
#[derive(Debug, Clone, Copy, Default)]
struct Entree {
    /// Où son nom commence.
    debut: usize,
    /// La longueur du nom.
    nom: usize,
    /// La longueur de la valeur.
    valeur: usize,
}

/// La table dynamique d'une connexion.
pub struct Dynamique {
    /// Les octets des entrées, de la plus ancienne à la plus récente.
    arene: [u8; ARENE],
    /// Où la région vivante commence.
    debut: usize,
    /// Où elle finit.
    fin: usize,
    /// Les entrées, en anneau, de la plus ancienne à la plus récente.
    entrees: [Entree; ENTREES_MAX],
    /// Le rang de la plus ancienne dans l'anneau.
    tete: usize,
    /// Combien d'entrées valent.
    combien: usize,
    /// Ce que la table pèse, surcoût compris.
    poids: u32,
    /// Ce qu'elle a le droit de peser.
    maximum: u32,
}

impl Dynamique {
    /// Une table vide, à la taille par défaut de §6.5.2.
    #[must_use]
    pub fn new() -> Self {
        Self {
            arene: [0; ARENE],
            debut: 0,
            fin: 0,
            entrees: [Entree::default(); ENTREES_MAX],
            tete: 0,
            combien: 0,
            poids: 0,
            maximum: TABLE_SIZE_MAX,
        }
    }

    /// Combien d'entrées la table porte.
    #[must_use]
    pub fn len(&self) -> u32 {
        // `combien` est borné par `ENTREES_MAX`, donc par cent vingt-huit.
        u32::try_from(self.combien).unwrap_or(u32::MAX)
    }

    /// La table est-elle vide ?
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.combien == 0
    }

    /// Ce que la table pèse, surcoût compris.
    #[must_use]
    pub fn size(&self) -> u32 {
        self.poids
    }

    /// Ce qu'elle a le droit de peser.
    #[must_use]
    pub fn max_size(&self) -> u32 {
        self.maximum
    }

    /// Applique une mise à jour de taille de §6.3.
    ///
    /// # LA BORNE EST CELLE QU'ON A ANNONCÉE, PAS CELLE QU'ON DEMANDE
    ///
    /// §4.2 : « The new maximum size MUST be lower than or equal to the limit
    /// determined by the protocol using HPACK. » Cette limite, c'est notre
    /// `SETTINGS_HEADER_TABLE_SIZE`. Un pair qui demande davantage ne demande
    /// pas : il se trompe, et sa demande est une faute de connexion.
    ///
    /// # Errors
    ///
    /// [`Cause::TableSizeTooLarge`] au-delà de [`TABLE_SIZE_MAX`].
    pub fn set_max_size(&mut self, taille: u32) -> Result<(), Error> {
        if taille > TABLE_SIZE_MAX {
            return Err(Error::connection(
                ErrorCode::CompressionError,
                Cause::TableSizeTooLarge,
            ));
        }
        self.maximum = taille;
        self.evincer_jusqu_a(taille);
        Ok(())
    }

    /// L'entrée de rang `index`, un pour la plus RÉCENTE.
    ///
    /// `None` au-delà de ce que la table porte.
    #[must_use]
    pub fn get(&self, index: u32) -> Option<(&[u8], &[u8])> {
        // §2.3.3 : l'index un désigne la dernière insérée. Zéro ne désigne rien.
        let depuis_la_fin = index.checked_sub(1)? as usize;
        let rang = self.combien.checked_sub(1)?.checked_sub(depuis_la_fin)?;
        // `rang` est sous `combien`, et l'anneau ramène dans le tableau : les
        // trois accès qui suivent aboutissent toujours. `unwrap_or_default`
        // porte cela dans la bibliothèque plutôt que dans trois `?` qu'aucun
        // index n'emprunte — et une entrée par défaut rendrait deux tranches
        // vides, donc rien de faux.
        let entree = self
            .entrees
            .get(self.anneau(rang))
            .copied()
            .unwrap_or_default();
        let milieu = entree.debut.saturating_add(entree.nom);
        let bout = milieu.saturating_add(entree.valeur);
        Some((
            self.arene.get(entree.debut..milieu).unwrap_or_default(),
            self.arene.get(milieu..bout).unwrap_or_default(),
        ))
    }

    /// Le rang dans l'anneau d'une entrée de rang `position` en insertion.
    fn anneau(&self, position: usize) -> usize {
        self.tete.saturating_add(position) % ENTREES_MAX
    }

    /// Insère une entrée, en évinçant ce qu'il faut.
    ///
    /// # UNE ENTRÉE PLUS GROSSE QUE LA TABLE LA VIDE, ET N'ENTRE PAS
    ///
    /// §4.4 : « It is not an error to attempt to add an entry that is larger
    /// than the maximum size; an attempt to add an entry larger than the
    /// maximum size causes the table to be emptied of all existing entries and
    /// results in an empty table. » Ce n'est donc PAS une faute — et un décodeur
    /// qui refuserait se désynchroniserait d'un encodeur qui, lui, a vidé.
    pub fn insert(&mut self, nom: &[u8], valeur: &[u8]) {
        let besoin = u32::try_from(nom.len())
            .unwrap_or(u32::MAX)
            .saturating_add(u32::try_from(valeur.len()).unwrap_or(u32::MAX))
            .saturating_add(SURCOUT);
        if besoin > self.maximum {
            self.clear();
            return;
        }
        self.evincer_jusqu_a(self.maximum.saturating_sub(besoin));

        // LA PLACE EN QUEUE, OU LA COMPACTION. Les octets d'une entrée se
        // rendent d'un seul tenant : on ne les coupe pas au bord de l'arène.
        let octets = nom.len().saturating_add(valeur.len());
        if self.fin.saturating_add(octets) > ARENE {
            self.compacter();
        }
        let debut = self.fin;
        let milieu = debut.saturating_add(nom.len());
        let bout = milieu.saturating_add(valeur.len());
        // L'éviction a fait la place : ces tranches existent. On écrit par
        // `zip`, qui s'arrête de lui-même — plutôt que par un `if let` dont le
        // « sinon » serait une branche qu'aucune insertion n'emprunte.
        for (place, octet) in self
            .arene
            .get_mut(debut..milieu)
            .unwrap_or_default()
            .iter_mut()
            .zip(nom)
        {
            *place = *octet;
        }
        for (place, octet) in self
            .arene
            .get_mut(milieu..bout)
            .unwrap_or_default()
            .iter_mut()
            .zip(valeur)
        {
            *place = *octet;
        }
        self.fin = bout;

        let rang = self.anneau(self.combien);
        for place in self
            .entrees
            .get_mut(rang..)
            .unwrap_or_default()
            .iter_mut()
            .take(1)
        {
            *place = Entree {
                debut,
                nom: nom.len(),
                valeur: valeur.len(),
            };
        }
        self.combien = self.combien.saturating_add(1);
        self.poids = self.poids.saturating_add(besoin);
    }

    /// Vide la table.
    fn clear(&mut self) {
        self.debut = 0;
        self.fin = 0;
        self.tete = 0;
        self.combien = 0;
        self.poids = 0;
    }

    /// Évince les plus anciennes jusqu'à peser au plus `cible`.
    fn evincer_jusqu_a(&mut self, cible: u32) {
        while self.poids > cible && self.combien > 0 {
            let rang = self.anneau(0);
            let partie = self.entrees.get(rang).copied().unwrap_or_default();
            let octets = partie.nom.saturating_add(partie.valeur);
            self.debut = self.debut.saturating_add(octets);
            self.tete = self.tete.saturating_add(1) % ENTREES_MAX;
            self.combien = self.combien.saturating_sub(1);
            self.poids = self.poids.saturating_sub(
                u32::try_from(octets)
                    .unwrap_or(u32::MAX)
                    .saturating_add(SURCOUT),
            );
        }
        if self.combien == 0 {
            self.clear();
        }
    }

    /// Ramène les octets vivants au début de l'arène.
    fn compacter(&mut self) {
        let longueur = self.fin.saturating_sub(self.debut);
        self.arene.copy_within(self.debut..self.fin, 0);
        // Les entrées portent des positions ABSOLUES : elles reculent toutes du
        // même décalage.
        let recul = self.debut;
        for position in 0..self.combien {
            let rang = self.anneau(position);
            for entree in self
                .entrees
                .get_mut(rang..)
                .unwrap_or_default()
                .iter_mut()
                .take(1)
            {
                entree.debut = entree.debut.saturating_sub(recul);
            }
        }
        self.debut = 0;
        self.fin = longueur;
    }
}

impl Default for Dynamique {
    fn default() -> Self {
        Self::new()
    }
}

impl core::fmt::Debug for Dynamique {
    /// **ON NE MONTRE PAS LE CONTENU.** Une table dynamique porte les en-têtes
    /// de toutes les requêtes d'une connexion, `authorization` compris.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Dynamique")
            .field("entrees", &self.combien)
            .field("poids", &self.poids)
            .field("maximum", &self.maximum)
            .finish()
    }
}

#[cfg(test)]
mod tests;
