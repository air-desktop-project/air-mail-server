//! Le compte des sauts déjà faits (RFC 5321 §6.3).
//!
//! # UNE BOUCLE NE S'ARRÊTE PAS TOUTE SEULE
//!
//! Deux serveurs mal réglés qui se renvoient un message le multiplient à chaque
//! tour. Rien dans SMTP ne le détecte : chaque saut est licite, et chacun croit
//! bien faire. §6.3 donne la seule méthode qui marche sans mémoire partagée —
//! **compter les `Received:`**, et refuser au-delà d'un seuil large.
//!
//! Ce serveur en pose un à chaque message qu'il accepte ; le compter est donc
//! ce qui rend cette pose utile à quelqu'un d'autre que le lecteur humain.
//!
//! # POURQUOI COMPTER AU FIL DE L'EAU, ET NON APRÈS COUP
//!
//! Le bloc d'en-têtes n'est rassemblé que si DKIM ou DMARC sont réglés — c'est
//! une décision d'exploitation. Une garde de sûreté qui ne s'appliquerait qu'aux
//! serveurs qui vérifient les signatures n'est pas une garde : c'est une option.
//!
//! Ce compteur voit donc les octets passer, sans rien retenir : il ne connaît
//! que sa position dans une ligne, et si cette ligne ressemblait au début de
//! `Received:`. **Rien ne croît avec le message** (C3).

/// Le nom du champ qu'on compte, en minuscules.
const CHAMP: &[u8] = b"received:";

/// Ce que le compteur est en train de lire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Ou {
    /// Au début d'une ligne : les octets qui suivent peuvent être le champ.
    Debut { vus: usize },
    /// Ailleurs dans la ligne : plus rien à reconnaître avant le prochain `LF`.
    Ailleurs,
    /// La ligne vide a été vue : le bloc d'en-têtes est fini, et le corps peut
    /// contenir ce qu'il veut sans que cela compte.
    Corps,
}

/// Compte les `Received:` d'un bloc d'en-têtes, octet par octet.
#[derive(Debug, Clone)]
pub struct Sauts {
    ou: Ou,
    /// Le nombre d'octets déjà lus sur la ligne courante.
    dans_la_ligne: usize,
    combien: u32,
}

impl Default for Sauts {
    fn default() -> Self {
        Self::new()
    }
}

impl Sauts {
    /// Un compteur pour un message neuf.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            ou: Ou::Debut { vus: 0 },
            dans_la_ligne: 0,
            combien: 0,
        }
    }

    /// Combien de `Received:` ont été vus.
    #[must_use]
    pub const fn count(&self) -> u32 {
        self.combien
    }

    /// Donne des octets du message.
    ///
    /// **Le découpage n'a aucune importance** : le compteur ne retient qu'une
    /// position, et deux appels valent un seul appel sur la concaténation.
    pub fn update(&mut self, morceau: &[u8]) {
        for octet in morceau {
            self.avancer(*octet);
        }
    }

    /// Un octet de plus.
    fn avancer(&mut self, octet: u8) {
        if self.ou == Ou::Corps {
            return;
        }
        if octet == b'\n' {
            // Une ligne VIDE ferme le bloc d'en-têtes. Le `CR` du `CRLF` compte
            // pour un octet : une ligne vide en fait donc exactement un.
            if self.dans_la_ligne <= 1 {
                self.ou = Ou::Corps;
            } else {
                self.ou = Ou::Debut { vus: 0 };
            }
            self.dans_la_ligne = 0;
            return;
        }
        self.dans_la_ligne = self.dans_la_ligne.saturating_add(1);
        let Ou::Debut { vus } = self.ou else {
            return;
        };
        // La casse ne compte pas : §2.2 de RFC 5322 veut qu'un nom de champ se
        // compare sans elle, et un pair qui écrit `RECEIVED:` en écrit un.
        if CHAMP.get(vus).copied() == Some(octet.to_ascii_lowercase()) {
            let vus = vus.saturating_add(1);
            if vus == CHAMP.len() {
                self.combien = self.combien.saturating_add(1);
                self.ou = Ou::Ailleurs;
            } else {
                self.ou = Ou::Debut { vus };
            }
            return;
        }
        self.ou = Ou::Ailleurs;
    }
}

#[cfg(test)]
mod tests;
