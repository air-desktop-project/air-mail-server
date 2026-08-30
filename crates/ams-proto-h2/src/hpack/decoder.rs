// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Le décodeur de bloc d'en-têtes (RFC 7541 §6).
//!
//! # CINQ REPRÉSENTATIONS, RECONNUES PAR LEURS BITS DE TÊTE
//!
//! ```text
//! 1xxxxxxx  champ indexé                       §6.1
//! 01xxxxxx  littéral, AVEC indexation          §6.2.1
//! 001xxxxx  mise à jour de la taille de table  §6.3
//! 0001xxxx  littéral, JAMAIS indexé            §6.2.3
//! 0000xxxx  littéral, sans indexation          §6.2.2
//! ```
//!
//! **L'ORDRE DE RECONNAISSANCE EST UNE RÈGLE, PAS UN AGRÉMENT** : `0001xxxx` et
//! `0000xxxx` partagent leurs trois premiers bits, et tester le plus court
//! d'abord ferait lire un « jamais indexé » comme un « sans indexation ». La
//! différence n'est pas cosmétique — voir plus bas.
//!
//! # « JAMAIS INDEXÉ » N'EST PAS « SANS INDEXATION »
//!
//! §7.1.3 : `0001xxxx` dit qu'un intermédiaire ne doit JAMAIS mettre ce champ
//! dans sa table dynamique, même s'il ré-encode. C'est ce qu'un client pose sur
//! un jeton d'autorisation, précisément pour qu'il ne finisse pas dans un état
//! partagé où une attaque par compression pourrait le deviner. `0000xxxx`, lui,
//! dit seulement « moi je ne l'indexe pas ». Les confondre, c'est trahir une
//! promesse qu'on n'a pas faite mais qu'on relaie.
//!
//! # LE DÉCODEUR NE JUGE PAS LES CHAMPS, ET C'EST VOULU
//!
//! Il rend des paires. Ce qui décide qu'une LISTE est recevable — l'ordre des
//! pseudo-en-têtes, les champs interdits, la bombe de décompression — vit dans
//! [`ams_proto_http::HeadBuilder`], et n'est écrit qu'une fois pour h2 et h3.

use super::decode_integer;
use super::decode_string;
use super::dynamique::Dynamique;
use super::table_statique::{STATIQUE_LEN, entree_statique};
use crate::error::{Cause, Error, ErrorCode};

/// Ce qu'un champ décodé demande qu'on fasse de lui en le relayant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sensitivity {
    /// Ordinaire : un intermédiaire peut l'indexer.
    Ordinary,
    /// **JAMAIS INDEXÉ** (§7.1.3) : un intermédiaire qui ré-encode doit
    /// employer la même représentation, et ne pas le mettre en table.
    NeverIndexed,
}

/// Ce qu'un champ décodé laisse derrière lui.
///
/// # POURQUOI LE RESTE DU TAMPON EN FAIT PARTIE
///
/// Un champ décodé EMPRUNTE le tampon qu'on a donné. Sans rendre ce qui n'a pas
/// servi, l'appelant ne peut décoder qu'UN champ par tampon : le second appel
/// voudrait le réemprunter, et l'emprunt du premier n'est pas fini — il vit
/// dans le champ qu'on garde.
///
/// Ce n'était pas une gêne théorique : le décodeur était inutilisable pour ce à
/// quoi il sert, et cela ne s'est vu qu'en écrivant l'appelant. **Une interface
/// ne se juge pas sur ce qu'elle promet, mais sur ce qu'on peut en faire.**
#[derive(Debug)]
pub struct Decoded<'o> {
    /// Le champ.
    pub field: Field<'o>,
    /// Ce qui a été consommé du bloc.
    pub read: usize,
    /// Ce qui reste du tampon, pour le champ suivant.
    pub rest: &'o mut [u8],
}

/// Un champ décodé.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Field<'a> {
    /// Le nom.
    pub name: &'a [u8],
    /// La valeur.
    pub value: &'a [u8],
    /// Ce qu'un intermédiaire a le droit d'en faire.
    pub sensitivity: Sensitivity,
}

/// L'état d'un décodeur, pour toute la durée d'une connexion.
///
/// **IL NE SE REMET PAS À ZÉRO ENTRE DEUX BLOCS** : la table dynamique est
/// commune, et c'est tout l'intérêt de HPACK. C'est aussi ce qui fait qu'une
/// faute condamne la connexion.
#[derive(Debug, Default)]
pub struct Decoder {
    /// La table dynamique.
    table: Dynamique,
    /// A-t-on déjà lu autre chose qu'une mise à jour de taille dans ce bloc ?
    ///
    /// §4.2 : une mise à jour doit venir AU DÉBUT d'un bloc. La tolérer ailleurs
    /// laisserait un encodeur changer la taille au milieu, et un décodeur qui
    /// l'appliquerait plus tard verrait une autre table.
    entame: bool,
}

impl Decoder {
    /// Un décodeur neuf.
    #[must_use]
    pub fn new() -> Self {
        Self {
            table: Dynamique::new(),
            entame: false,
        }
    }

    /// La table dynamique, pour qui veut la regarder.
    #[must_use]
    pub fn table(&self) -> &Dynamique {
        &self.table
    }

    /// Ouvre un nouveau bloc d'en-têtes.
    ///
    /// **À APPELER AVANT CHAQUE BLOC** : c'est ce qui rouvre la fenêtre pendant
    /// laquelle §4.2 admet une mise à jour de taille.
    pub fn begin_block(&mut self) {
        self.entame = false;
    }

    /// Décode le champ suivant, et rend ce qu'il a consommé.
    ///
    /// Rend `None` quand le bloc est épuisé. Le nom et la valeur sont écrits
    /// dans `out` — un décodeur qui prêterait la table dynamique empêcherait
    /// d'y insérer, et les entrées se déplacent quand elle se recompacte.
    ///
    /// # Errors
    ///
    /// Les fautes de §6, toutes de connexion : l'état est partagé, et un
    /// décodeur qui s'est trompé une fois ne saura plus rien lire.
    pub fn next<'o>(
        &mut self,
        bloc: &[u8],
        out: &'o mut [u8],
    ) -> Result<Option<Decoded<'o>>, Error> {
        let Some(premier) = bloc.first().copied() else {
            return Ok(None);
        };
        // §6.3 : LA MISE À JOUR DE TAILLE, ET ELLE SEULE, PEUT PRÉCÉDER TOUT LE
        // RESTE. On la traite ici plutôt que dans le classement plus bas, parce
        // qu'elle ne rend AUCUN champ : la traiter comme les autres obligerait à
        // rendre un champ vide que l'appelant devrait apprendre à ignorer.
        if premier & 0b1110_0000 == 0b0010_0000 {
            if self.entame {
                return Err(Error::connection(
                    ErrorCode::CompressionError,
                    Cause::TableUpdateTooLate,
                ));
            }
            let (taille, lus) = decode_integer(bloc, 5)?;
            self.table.set_max_size(taille)?;
            let suite = bloc.get(lus..).unwrap_or_default();
            // La mise à jour ne rend rien : on enchaîne sur ce qui suit, et
            // l'appelant ne voit que des champs.
            return match self.next(suite, out)? {
                Some(decode) => Ok(Some(Decoded {
                    read: lus.saturating_add(decode.read),
                    ..decode
                })),
                None => Ok(None),
            };
        }
        self.entame = true;

        // §6.1 : LE CHAMP INDEXÉ, NOM ET VALEUR D'UN COUP.
        if premier & 0b1000_0000 != 0 {
            let (index, lus) = decode_integer(bloc, 7)?;
            let (nom, valeur) = self.chercher(index)?;
            let (field, rest) = poser(nom, valeur, Sensitivity::Ordinary, out)?;
            return Ok(Some(Decoded {
                field,
                read: lus,
                rest,
            }));
        }

        // §6.2 : LES TROIS LITTÉRAUX. **LE PLUS LONG MOTIF D'ABORD** :
        // `0001xxxx` et `0000xxxx` partagent leurs trois premiers bits, et
        // tester le plus court d'abord ferait lire un « jamais indexé » comme
        // un « sans indexation ».
        let (bits, indexer, sensibilite) = if premier & 0b1100_0000 == 0b0100_0000 {
            (6, true, Sensitivity::Ordinary)
        } else if premier & 0b1111_0000 == 0b0001_0000 {
            (4, false, Sensitivity::NeverIndexed)
        } else {
            // **IL NE RESTE QUE `0000xxxx`**, et le classement est donc TOTAL :
            // `1xxxxxxx` et `001xxxxx` ont été traités plus haut, `01xxxxxx` et
            // `0001xxxx` à l'instant. Écrire un bras « sinon c'est une faute »
            // serait une branche qu'aucun octet ne peut emprunter — et la
            // couverture le dirait.
            (4, false, Sensitivity::Ordinary)
        };

        let (index, lus) = decode_integer(bloc, bits)?;
        let mut consommes = lus;
        let court = || Error::connection(ErrorCode::CompressionError, Cause::BufferTooSmall);

        // **LE NOM D'ABORD, LA VALEUR JUSTE APRÈS, DANS LE MÊME TAMPON.**
        //
        // Une première écriture coupait `out` en deux parts égales, ce qui
        // obligeait l'appelant à fournir deux fois le plus long des deux au lieu
        // de leur somme — et un nom long avec une valeur vide échouait sur un
        // tampon pourtant suffisant. Le fuzz l'a trouvé en quelques secondes.
        // Les emprunts se referment donc entre les deux écritures, et l'on ne
        // retient que des LONGUEURS.
        //
        // ZÉRO VEUT DIRE « LE NOM SUIT EN CLAIR » (§6.2.1) ; tout le reste
        // désigne une entrée dont on reprend le NOM, et pas la valeur.
        let nom_len = match index {
            0 => {
                let suite = bloc.get(consommes..).unwrap_or_default();
                let (nom, apres) = decode_string(suite, out)?;
                let longueur = nom.len();
                consommes = consommes.saturating_add(apres);
                longueur
            }
            _ => {
                let (nom, _) = self.chercher(index)?;
                let longueur = nom.len();
                let place = out.get_mut(..longueur).ok_or_else(court)?;
                place.copy_from_slice(nom);
                longueur
            }
        };
        let valeur_len = {
            let suite = bloc.get(consommes..).unwrap_or_default();
            // Le nom vient d'être écrit DANS `out` : la tranche qui le suit
            // existe toujours, fût-elle vide. `unwrap_or_default` porte cela
            // dans la bibliothèque plutôt que dans une garde qu'aucune entrée
            // n'emprunte — et si elle est vide, c'est `decode_string` qui dira
            // que la place manque.
            let apres_le_nom = out.get_mut(nom_len..).unwrap_or_default();
            let (valeur, apres) = decode_string(suite, apres_le_nom)?;
            let longueur = valeur.len();
            consommes = consommes.saturating_add(apres);
            longueur
        };

        // LES DEUX ONT ÉTÉ ÉCRITS DANS `out` : les deux coupures y tiennent. Le
        // `min` rend `split_at_mut` total — il panique au-delà, et une panique
        // vaut moins qu'une borne —, et `unwrap_or_default` fait le reste.
        let (place_nom, apres) = out.split_at_mut(nom_len.min(out.len()));
        let (place_valeur, rest) = apres.split_at_mut(valeur_len.min(apres.len()));
        if indexer {
            // L'insertion RECOPIE : la table a son arène, et les tranches qu'on
            // vient d'écrire vivent dans celle de l'appelant.
            self.table.insert(place_nom, place_valeur);
        }
        Ok(Some(Decoded {
            field: Field {
                name: place_nom,
                value: place_valeur,
                sensitivity: sensibilite,
            },
            read: consommes,
            rest,
        }))
    }

    /// L'entrée d'un index, statique ou dynamique (§2.3.3).
    ///
    /// # LES DEUX TABLES SE LISENT COMME UNE SEULE
    ///
    /// Un à soixante et un : la statique. Au-delà : la dynamique, la plus
    /// récente d'abord. **Zéro ne désigne rien** (§6.1), et un index qui dépasse
    /// est une faute — pas une entrée vide qu'on rendrait en silence.
    fn chercher(&self, index: u32) -> Result<(&[u8], &[u8]), Error> {
        let absent = || Error::connection(ErrorCode::CompressionError, Cause::BadIndex);
        if let Some(entree) = entree_statique(index) {
            return Ok(entree);
        }
        let dans_la_dynamique = index.checked_sub(STATIQUE_LEN).ok_or_else(absent)?;
        self.table.get(dans_la_dynamique).ok_or_else(absent)
    }
}

/// Recopie un nom et une valeur dans `out`, et compose le champ.
fn poser<'o>(
    nom: &[u8],
    valeur: &[u8],
    sensibilite: Sensitivity,
    out: &'o mut [u8],
) -> Result<(Field<'o>, &'o mut [u8]), Error> {
    let court = || Error::connection(ErrorCode::CompressionError, Cause::BufferTooSmall);
    let fin = nom.len().saturating_add(valeur.len());
    let Some((place, reste)) = out.split_at_mut_checked(fin) else {
        return Err(court());
    };
    let (place_nom, place_valeur) = place.split_at_mut(nom.len());
    place_nom.copy_from_slice(nom);
    place_valeur.copy_from_slice(valeur);
    Ok((
        Field {
            name: place_nom,
            value: place_valeur,
            sensitivity: sensibilite,
        },
        reste,
    ))
}

#[cfg(test)]
mod tests;
