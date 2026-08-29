//! La canonicalisation du corps (RFC 6376 §3.4.3, §3.4.4), **en flux**.
//!
//! # Pourquoi en flux, et pas sur un tampon
//!
//! Le corps d'un message est ce qu'un pair envoie de plus gros. Le rassembler
//! pour le canonicaliser reviendrait à lui laisser choisir combien de mémoire on
//! lui consacre — et le condensat qui viendra ensuite se calcule de toute façon
//! morceau par morceau. La machine à états d'ici prend donc ce qui arrive et
//! rend ce qui est décidé, sans jamais retenir plus de quelques octets.
//!
//! # Ce qu'elle doit retenir, et pourquoi c'est borné
//!
//! Deux choses seulement, et aucune ne grandit avec le message :
//!
//! - **combien de fins de ligne attendent.** Les lignes vides de la fin d'un
//!   corps s'ignorent (§3.4.3), et on ne sait qu'une ligne était finale qu'en
//!   voyant qu'il n'y a plus rien. Un COMPTEUR suffit : on les réémettra à
//!   l'identique si du contenu suit.
//! - **qu'un blanc attend**, en `relaxed`. Une suite de blancs se réduit à une
//!   seule espace, et celle de fin de ligne disparaît : un booléen suffit, quelle
//!   que soit la longueur de la suite.

use crate::canonical::Canon;

/// La canonicalisation d'un corps, morceau par morceau.
#[derive(Debug, Clone)]
pub struct BodyCanon {
    canon: Canon,
    /// Les fins de ligne vues et pas encore écrites.
    lignes_en_attente: u64,
    /// Un blanc attend d'être réduit (`relaxed` seulement).
    blanc_en_attente: bool,
    /// Un `CR` a été vu ; on attend de savoir s'il annonce un `LF`.
    cr_en_attente: bool,
    /// A-t-on écrit le moindre octet de contenu ?
    vide: bool,
    /// Ce qui a été écrit.
    ecrits: u64,
    /// La borne du `l=`, s'il y en a une.
    limite: Option<u64>,
}

impl BodyCanon {
    /// Ouvre une canonicalisation.
    ///
    /// # La borne `l=` est un DANGER CONNU, pas une commodité
    ///
    /// Elle dit « ne condense que les `n` premiers octets du corps
    /// canonicalisé », ce qui laisse **ajouter ce qu'on veut après** sans
    /// invalider la signature (RFC 6376 §8.2). Un message signé avec `l=` peut
    /// donc arriver avec une pièce jointe que son auteur n'a jamais écrite. Cette
    /// crate l'applique parce que la RFC la définit ; c'est à la couche qui
    /// décide de s'en méfier, et de le dire.
    #[must_use]
    pub fn new(canon: Canon, limite: Option<u64>) -> Self {
        Self {
            canon,
            lignes_en_attente: 0,
            blanc_en_attente: false,
            cr_en_attente: false,
            vide: true,
            ecrits: 0,
            limite,
        }
    }

    /// Donne un morceau du corps.
    pub fn update(&mut self, morceau: &[u8], sortie: &mut impl FnMut(&[u8])) {
        for octet in morceau {
            self.un_octet(*octet, sortie);
        }
    }

    /// Termine, et rend le nombre d'octets canonicalisés.
    ///
    /// # Le corps canonicalisé finit TOUJOURS par une fin de ligne — sauf s'il
    /// est vide
    ///
    /// §3.4.3 : « s'il n'y a pas de corps, ou pas de `CRLF` final, un `CRLF` est
    /// ajouté ». Et §3.4.4 : un corps entièrement vide se canonicalise en RIEN.
    /// Les deux ne disent pas la même chose, et confondre les deux fait échouer
    /// toutes les signatures d'un des deux algorithmes.
    pub fn finish(mut self, sortie: &mut impl FnMut(&[u8])) -> u64 {
        if self.cr_en_attente {
            // Un `CR` que rien n'a suivi n'est pas une fin de ligne : c'est un
            // octet du corps, et il compte comme tel.
            self.contenu(b'\r', sortie);
        }
        match self.canon {
            Canon::Simple => self.pousser(b"\r\n", sortie),
            Canon::Relaxed if !self.vide => self.pousser(b"\r\n", sortie),
            Canon::Relaxed => {}
        }
        self.ecrits
    }

    /// Ce qui a été écrit jusqu'ici.
    #[must_use]
    pub fn written(&self) -> u64 {
        self.ecrits
    }

    fn un_octet(&mut self, octet: u8, sortie: &mut impl FnMut(&[u8])) {
        if self.cr_en_attente {
            self.cr_en_attente = false;
            if octet == b'\n' {
                // Une fin de ligne : le blanc qui la précédait disparaît
                // (§3.4.4), et la ligne attend de savoir si elle est finale.
                self.blanc_en_attente = false;
                self.lignes_en_attente = self.lignes_en_attente.saturating_add(1);
                return;
            }
            // Le `CR` n'annonçait rien : c'est un octet ordinaire.
            self.contenu(b'\r', sortie);
        }
        if octet == b'\r' {
            self.cr_en_attente = true;
            return;
        }
        if self.canon == Canon::Relaxed && matches!(octet, b' ' | b'\t') {
            // On ne l'écrit pas : s'il finit la ligne, il ne s'écrira jamais.
            self.blanc_en_attente = true;
            return;
        }
        self.contenu(octet, sortie);
    }

    /// Un octet de contenu : ce qui attendait n'était donc pas final.
    fn contenu(&mut self, octet: u8, sortie: &mut impl FnMut(&[u8])) {
        while self.lignes_en_attente > 0 {
            self.lignes_en_attente = self.lignes_en_attente.saturating_sub(1);
            self.pousser(b"\r\n", sortie);
        }
        if self.blanc_en_attente {
            self.blanc_en_attente = false;
            self.pousser(b" ", sortie);
        }
        self.pousser(core::slice::from_ref(&octet), sortie);
        self.vide = false;
    }

    /// Écrit, en respectant la borne du `l=`.
    fn pousser(&mut self, morceau: &[u8], sortie: &mut impl FnMut(&[u8])) {
        let reste = match self.limite {
            Some(borne) => borne.saturating_sub(self.ecrits),
            None => u64::MAX,
        };
        let combien = usize::try_from(reste)
            .unwrap_or(usize::MAX)
            .min(morceau.len());
        let ecrit = morceau.get(..combien).unwrap_or_default();
        if ecrit.is_empty() {
            return;
        }
        sortie(ecrit);
        self.ecrits = self.ecrits.saturating_add(combien as u64);
    }
}

#[cfg(test)]
mod tests;
