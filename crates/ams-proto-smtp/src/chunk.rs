//! Les morceaux comptés de `BDAT` (RFC 3030 §2).
//!
//! # CE QUI DISPARAÎT PAR RAPPORT À `DATA`, ET C'EST L'ESSENTIEL
//!
//! La phase `DATA` cherche une fin dans le flux : `<CRLF>.<CRLF>`. Chercher une
//! fin, c'est décider où couper — et c'est exactement là que vit la contrebande
//! SMTP de 2023, quand deux serveurs ne coupent pas au même endroit.
//!
//! `BDAT` ne cherche rien. La longueur est ANNONCÉE sur la ligne de commande, en
//! chiffres décimaux, et le morceau fait exactement ce nombre d'octets. Il n'y a
//! pas de délimiteur, donc pas de délimiteur à fabriquer, et **pas de point à
//! échapper** : un `.` en début de ligne est un point, rien de plus.
//!
//! # CE QUI NE DISPARAÎT PAS : LE `CR` ET LE `LF` ISOLÉS
//!
//! Ils restent refusés, comme en phase `DATA`. Ce n'est pas la fin de CE
//! message qu'on protège — elle est comptée — c'est celle du PROCHAIN SAUT.
//!
//! Ce qu'on dépose ici repart un jour par la file de réémission, vers un voisin
//! qui, lui, lit `<CRLF>.<CRLF>`. Un `LF` nu accepté ici et réémis là-bas y
//! ouvrirait la faille qu'on vient de fermer chez nous : nous aurions blanchi la
//! contrebande au lieu de la commettre, et la victime ne verrait pas la
//! différence. **Une seule règle pour les deux phases**, et le message stocké
//! n'a qu'une seule façon de finir ses lignes.
//!
//! # UN `CRLF` PEUT ÊTRE COUPÉ EN DEUX PAR UNE FRONTIÈRE DE MORCEAU
//!
//! `BDAT 5` puis `BDAT 3 LAST` peuvent livrer `abc\r` puis `\ndef` : le `CR` est
//! dans un morceau et le `LF` dans le suivant. L'état de lecture vit donc dans
//! le récepteur, qui traverse toute la transaction, et non dans le morceau.
//! L'inverse ferait refuser un message parfaitement légal, ou pire, accepterait
//! un `CR` pendant qui ne serait jamais suivi.

use crate::{DataFault, Limits};

/// Ce que le récepteur rend à chaque appel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChunkEvent<'i> {
    /// Des octets du message, empruntés à l'entrée. Jamais vide.
    Content(&'i [u8]),
    /// Le morceau courant est épuisé, et **ce n'était pas le dernier**.
    ///
    /// L'appelant doit répondre `250` et attendre la commande suivante.
    ChunkComplete,
    /// Le dernier morceau est épuisé : le message est entier.
    Complete,
    /// L'entrée est épuisée ; il en faut d'autre.
    NeedMore,
}

/// Lit les morceaux de `BDAT`, **sans entrée-sortie et sans allouer**.
///
/// Un récepteur vit le temps d'une TRANSACTION, et non d'un morceau : c'est ce
/// qui lui permet de compter les octets du message entier, et de voir un `CRLF`
/// coupé par une frontière de morceau.
#[derive(Debug, Clone)]
pub struct ChunkReceiver {
    /// Ce qui reste à lire du morceau courant.
    reste: u64,
    /// Le morceau courant est-il le dernier ?
    last: bool,
    /// Un `CR` a été rendu, et seul un `LF` peut le suivre.
    after_cr: bool,
    /// Octets de message rendus depuis le début de la transaction.
    content_octets: u64,
    /// Le message est-il entier ?
    done: bool,
    max_message: u64,
}

impl ChunkReceiver {
    /// Ouvre la lecture d'un message par morceaux.
    ///
    /// `limits` n'est pas lu aujourd'hui : `BDAT` n'a pas de lignes, donc pas de
    /// longueur de ligne à borner. Il est demandé quand même pour que la
    /// signature soit celle de [`DataReceiver`](crate::DataReceiver) — deux
    /// façons d'ouvrir la même chose finiraient par diverger.
    #[must_use]
    pub const fn new(limits: &Limits, max_message_octets: u64) -> Self {
        let _ = limits;
        Self {
            reste: 0,
            last: false,
            after_cr: false,
            content_octets: 0,
            done: false,
            max_message: max_message_octets,
        }
    }

    /// Annonce un morceau de `size` octets, dernier ou non.
    ///
    /// # UN MORCEAU DE ZÉRO OCTET EST LICITE, ET C'EST MÊME L'IDIOME
    ///
    /// `BDAT 0 LAST` termine un message dont tous les octets sont déjà arrivés
    /// (RFC 3030 §2). Rien à lire, et le message est entier.
    ///
    /// # Errors
    ///
    /// [`DataFault::MessageTooLarge`] si ce morceau ferait franchir la borne du
    /// message — **avant d'en lire le moindre octet**, parce qu'il annonce sa
    /// taille : refuser tout de suite évite de lire un mébioctet qu'on jettera.
    pub fn begin(&mut self, size: u64, last: bool) -> Result<(), DataFault> {
        if self.content_octets.saturating_add(size) > self.max_message {
            return Err(DataFault::MessageTooLarge {
                limit: self.max_message,
            });
        }
        self.reste = size;
        self.last = last;
        Ok(())
    }

    /// Le nombre d'octets de message rendus jusqu'ici.
    #[must_use]
    pub const fn content_octets(&self) -> u64 {
        self.content_octets
    }

    /// Le message est-il entier ?
    #[must_use]
    pub const fn is_complete(&self) -> bool {
        self.done
    }

    /// Consomme des octets d'entrée, et rend un événement.
    ///
    /// Rend aussi le nombre d'octets **consommés**, qui est ici celui des octets
    /// rendus : `BDAT` n'échappe rien, et ne mange donc aucun octet en chemin.
    ///
    /// # Il progresse toujours
    ///
    /// Sur une entrée non vide et un morceau non épuisé, cet appel consomme au
    /// moins un octet. Sans cette garantie, un pair enfermerait la boucle de
    /// l'appelant avec trois octets.
    ///
    /// # Errors
    ///
    /// [`DataFault`]. Une faute est **définitive** : le récepteur ne doit plus
    /// être sollicité, et le message ne peut plus être accepté.
    pub fn next<'i>(&mut self, input: &'i [u8]) -> Result<(ChunkEvent<'i>, usize), DataFault> {
        if self.reste == 0 {
            return self.fin_de_morceau();
        }
        if input.is_empty() {
            return Ok((ChunkEvent::NeedMore, 0));
        }
        // On ne lit jamais au-delà du morceau : ce qui suit est une COMMANDE, et
        // la confondre avec des données est précisément ce que `BDAT` évite.
        let combien = usize::try_from(self.reste)
            .unwrap_or(usize::MAX)
            .min(input.len());
        let morceau = input.get(..combien).unwrap_or_default();
        // **ON REND CE QUI EST BON, PUIS ON REFUSE.** Refuser le morceau entier
        // dès qu'un octet cloche ferait dépendre le nombre d'octets rendus du
        // DÉCOUPAGE des lectures — c'est-à-dire du réseau. Le fuzz l'a montré
        // sur trois octets : `T\nr` d'un seul tenant ne rendait rien, et lu
        // octet par octet rendait `T`. Un même flux doit donner un même compte.
        let bons = self.avancer(morceau);
        if bons == 0 {
            return Err(DataFault::BareLineEnding);
        }
        let bon = morceau.get(..bons).unwrap_or_default();
        self.reste = self.reste.saturating_sub(bons as u64);
        self.content_octets = self.content_octets.saturating_add(bons as u64);
        Ok((ChunkEvent::Content(bon), bons))
    }

    /// Ce qu'on rend quand le morceau courant n'a plus d'octets.
    fn fin_de_morceau(&mut self) -> Result<(ChunkEvent<'static>, usize), DataFault> {
        if !self.last {
            return Ok((ChunkEvent::ChunkComplete, 0));
        }
        // **UN MESSAGE NE SE TERMINE PAS SUR UN `CR` PENDANT.** Il n'y aura plus
        // de `LF` pour le suivre : c'est un `CR` isolé, et il le reste.
        if self.after_cr {
            return Err(DataFault::BareLineEnding);
        }
        self.done = true;
        Ok((ChunkEvent::Complete, 0))
    }

    /// Combien d'octets de tête sont acceptables — **aucun `CR` ni `LF` isolé**,
    /// quelle que soit la frontière de morceau.
    ///
    /// Rend zéro quand le PREMIER octet cloche, ce que l'appelant traduit en
    /// refus. L'état avance jusqu'à l'octet fautif et pas au-delà : le prochain
    /// appel le retrouvera en tête, et rendra zéro à son tour.
    fn avancer(&mut self, morceau: &[u8]) -> usize {
        for (rang, octet) in morceau.iter().enumerate() {
            match (self.after_cr, *octet) {
                // Un `CR` en attente : seul un `LF` peut le suivre.
                (true, b'\n') => self.after_cr = false,
                // Un `LF` sans `CR` devant est la faille elle-même.
                (false, b'\n') | (true, _) => return rang,
                (false, b'\r') => self.after_cr = true,
                (false, _) => {}
            }
        }
        morceau.len()
    }
}

#[cfg(test)]
mod tests;
