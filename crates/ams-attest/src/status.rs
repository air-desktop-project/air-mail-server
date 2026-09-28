// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! La liste de révocation que Google publie pour les clefs d'attestation
//! (`https://android.googleapis.com/attestation/status`).
//!
//! ```text
//! { "entries": { "<numéro de série en hexadécimal minuscule>":
//!                  { "status": "REVOKED" | "SUSPENDED", "reason": …, … }, … } }
//! ```
//!
//! # TOUTE ENTRÉE COMPTE
//!
//! La liste ne nomme que les clefs qui ne sont PLUS valides — révoquées, ou
//! suspendues. Qu'une entrée dise l'une ou l'autre, ou un statut qu'une
//! version future ajouterait, la clef qu'elle nomme ne se croit plus : on lit
//! le numéro, et on ne lit pas le reste.
//!
//! # UN LECTEUR À PART, ET STRICT
//!
//! Le lecteur JSON de l'API borne un objet à seize champs : c'est juste pour un
//! corps de requête, et la liste en compte près de deux mille. Celui-ci ne lit
//! que la forme ci-dessus, et saute tout le reste — sous une profondeur bornée,
//! parce que ces octets viennent du réseau.

use crate::Refusal;

/// Le plus long numéro de série que la liste nomme : trente-deux chiffres
/// hexadécimaux, seize octets — ce qu'un `u128` porte.
pub const SERIAL_HEX_MAX: usize = 32;

/// La profondeur d'imbrication au-delà de laquelle la liste est refusée.
const PROFONDEUR_MAX: usize = 16;

/// Lit la liste, et appelle `chaque` pour chaque numéro de série qu'elle nomme.
/// Rend combien.
///
/// # Errors
///
/// [`Refusal::Malformed`] sur ce qui n'a pas la forme de la liste — y compris un
/// numéro de série qui n'est pas de l'hexadécimal minuscule sans zéro de tête,
/// ou plus long que [`SERIAL_HEX_MAX`]. **UNE LISTE MAL FORMÉE SE REFUSE
/// ENTIÈRE** : en retenir une partie ferait croire valides des clefs qu'elle
/// révoquait peut-être plus loin.
pub fn read_status_list(json: &[u8], chaque: &mut dyn FnMut(u128)) -> Result<usize, Refusal> {
    let mut lecteur = Json { reste: json };
    let mut combien = 0_usize;
    lecteur.attendre(b'{')?;
    if !lecteur.fermer(b'}')? {
        loop {
            let cle = lecteur.chaine()?;
            lecteur.attendre(b':')?;
            if cle == b"entries" {
                lecteur.attendre(b'{')?;
                if !lecteur.fermer(b'}')? {
                    loop {
                        let serie = numero_de_serie(lecteur.chaine()?)?;
                        lecteur.attendre(b':')?;
                        lecteur.sauter(0)?;
                        chaque(serie);
                        combien = combien.saturating_add(1);
                        if lecteur.fermer(b'}')? {
                            break;
                        }
                        lecteur.attendre(b',')?;
                    }
                }
            } else {
                lecteur.sauter(0)?;
            }
            if lecteur.fermer(b'}')? {
                break;
            }
            lecteur.attendre(b',')?;
        }
    }
    lecteur.blancs();
    if !lecteur.reste.is_empty() {
        return Err(Refusal::Malformed);
    }
    Ok(combien)
}

/// Un numéro de série : hexadécimal minuscule, sans zéro de tête (le motif
/// `^[a-f1-9][a-f0-9]*$` que la documentation publie), seize octets au plus.
fn numero_de_serie(texte: &[u8]) -> Result<u128, Refusal> {
    if texte.is_empty() || texte.len() > SERIAL_HEX_MAX || texte.first() == Some(&b'0') {
        return Err(Refusal::Malformed);
    }
    let mut valeur = 0_u128;
    for &chiffre in texte {
        let quatre = match chiffre {
            b'0'..=b'9' => chiffre.wrapping_sub(b'0'),
            b'a'..=b'f' => chiffre.wrapping_sub(b'a').wrapping_add(10),
            _ => return Err(Refusal::Malformed),
        };
        valeur = (valeur << 4) | u128::from(quatre);
    }
    Ok(valeur)
}

/// Un curseur sur du JSON.
struct Json<'a> {
    reste: &'a [u8],
}

impl<'a> Json<'a> {
    fn blancs(&mut self) {
        let debut = self
            .reste
            .iter()
            .position(|octet| !matches!(octet, b' ' | b'\t' | b'\n' | b'\r'))
            .unwrap_or(self.reste.len());
        self.reste = self.reste.get(debut..).unwrap_or_default();
    }

    /// Le prochain octet significatif doit être `attendu`.
    fn attendre(&mut self, attendu: u8) -> Result<(), Refusal> {
        self.blancs();
        match self.reste.split_first() {
            Some((&lu, apres)) if lu == attendu => {
                self.reste = apres;
                Ok(())
            }
            _ => Err(Refusal::Malformed),
        }
    }

    /// Le prochain octet significatif est-il `fin` ? Si oui, le consomme.
    fn fermer(&mut self, fin: u8) -> Result<bool, Refusal> {
        self.blancs();
        match self.reste.first() {
            Some(&lu) if lu == fin => {
                self.reste = self.reste.get(1..).unwrap_or_default();
                Ok(true)
            }
            Some(_) => Ok(false),
            None => Err(Refusal::Malformed),
        }
    }

    /// Une chaîne, rendue telle qu'écrite — échappements compris, qu'on ne
    /// défait pas : une clef de la liste n'en a jamais.
    fn chaine(&mut self) -> Result<&'a [u8], Refusal> {
        self.attendre(b'"')?;
        let mut rang = 0_usize;
        loop {
            match self.reste.get(rang) {
                Some(b'"') => break,
                Some(b'\\') => rang = rang.saturating_add(2),
                Some(octet) if *octet < 0x20 => return Err(Refusal::Malformed),
                Some(_) => rang = rang.saturating_add(1),
                None => return Err(Refusal::Malformed),
            }
        }
        let lue = self.reste.get(..rang).unwrap_or_default();
        self.reste = self.reste.get(rang.saturating_add(1)..).unwrap_or_default();
        Ok(lue)
    }

    /// Saute une valeur quelconque, sous une profondeur bornée.
    fn sauter(&mut self, profondeur: usize) -> Result<(), Refusal> {
        if profondeur > PROFONDEUR_MAX {
            return Err(Refusal::Malformed);
        }
        self.blancs();
        match self.reste.first() {
            Some(b'"') => self.chaine().map(|_| ()),
            Some(b'{') => {
                // L'accolade vient d'être vue : elle se consomme sans plus.
                self.reste = self.reste.get(1..).unwrap_or_default();
                if self.fermer(b'}')? {
                    return Ok(());
                }
                loop {
                    let _ = self.chaine()?;
                    self.attendre(b':')?;
                    self.sauter(profondeur.saturating_add(1))?;
                    if self.fermer(b'}')? {
                        return Ok(());
                    }
                    self.attendre(b',')?;
                }
            }
            Some(b'[') => {
                self.reste = self.reste.get(1..).unwrap_or_default();
                if self.fermer(b']')? {
                    return Ok(());
                }
                loop {
                    self.sauter(profondeur.saturating_add(1))?;
                    if self.fermer(b']')? {
                        return Ok(());
                    }
                    self.attendre(b',')?;
                }
            }
            Some(_) => {
                // Un nombre, `true`, `false`, `null` : jusqu'au prochain
                // séparateur, et fait des seuls caractères qui les écrivent.
                // Ce qu'il vaut ne compte pas.
                let fin = self
                    .reste
                    .iter()
                    .position(|octet| {
                        !matches!(
                            octet,
                            b'0'..=b'9'
                                | b'-'
                                | b'+'
                                | b'.'
                                | b'e'
                                | b'E'
                                | b'a'
                                | b'f'
                                | b'l'
                                | b'n'
                                | b'r'
                                | b's'
                                | b't'
                                | b'u'
                        )
                    })
                    .unwrap_or(self.reste.len());
                if fin == 0 {
                    return Err(Refusal::Malformed);
                }
                self.reste = self.reste.get(fin..).unwrap_or_default();
                Ok(())
            }
            None => Err(Refusal::Malformed),
        }
    }
}

#[cfg(test)]
mod tests;
