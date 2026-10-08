// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Ce que ce serveur annonce à un annuaire `air-service-locator`, et ce qu'il
//! lit de sa réponse.
//!
//! # LE PROBLÈME QUE CELA RÉSOUT, VU D'ICI
//!
//! Ce serveur n'écoute pas sur les ports que ses clients attendent. Il lie
//! 2525, 4465, 9993 — il n'a aucune capacité de se lier sous 1024 —, et c'est
//! une redirection du pare-feu qui expose 25, 587, 465, 993. **Un client qui ne
//! connaît que le nom de la machine ne sait pas où frapper**, et l'exploitant
//! est seul à détenir la correspondance.
//!
//! `air-service-locator` renverse la question : le serveur **annonce** où le
//! joindre, ses clients **demandent**. Cette crate-ci est la moitié du travail
//! qui ne fait aucune entrée-sortie : composer les annonces, lire une fiche
//! d'identité, lire la réponse de l'annuaire. Le transport est
//! `ams-quic-dial`, la boucle est dans `ams-loop-tokio`.
//!
//! # CE QUI N'EST PAS RÉÉCRIT ICI, ET POURQUOI
//!
//! Ni le protocole, ni les identifiants, ni la politique de reprise :
//! `asl-proto`, `asl-id` et `asl-client` les portent, éprouvés chez eux. Une
//! seconde lecture du même protocole finirait par diverger, et c'est celle
//! qu'on ne relit plus qui ferait autorité.
//!
//! Cette crate n'ajoute donc que ce qui est propre à CE serveur : **ce qu'il
//! annonce** — huit noms, un point d'écoute chacun — et la fiche où vit
//! l'identité de la machine.
//!
//! # LES PORTS ANNONCÉS VIENNENT DE LA CONFIGURATION, JAMAIS DES ÉCOUTES
//!
//! C'est la décision qui gouverne tout ce module (Thierry, 2026-10-08). Ce
//! serveur connaît les ports qu'il a LIÉS ; il ne connaît pas la redirection
//! qui les expose, et il ne peut pas la mesurer. Annoncer ce qu'il a lié
//! affirmerait que 9993 est ce qu'un client doit joindre, ce qui est vrai par
//! accident et faux en principe.
//!
//! L'exploitant écrit donc ce qui est joignable du dehors, puisque lui seul le
//! sait — et **l'annuaire le vérifie** : il sonde chaque point TCP annoncé et
//! rend un verdict. Une annonce fausse se voit, au lieu de se croire.
//!
//! # ET RIEN N'EST ANNONCÉ PAR DÉFAUT
//!
//! Comme le relais et comme l'API : éteint, jusqu'à ce que quelqu'un l'allume.
//! Un serveur qui s'annoncerait de lui-même publierait l'existence de ses
//! écoutes à un tiers que son exploitant n'a pas choisi.

#![no_std]
// **AUCUN `unsafe`** : c'est une crate de l'étage 2, elle ne fait que lire et
// écrire des octets qu'on lui donne.
#![forbid(unsafe_code)]

pub mod annonce;
pub mod bail;
pub mod fiche;

pub use annonce::{Declaration, SERVICES_MAX, composer_une_annonce};
pub use bail::{Cadence, lire_la_reponse};
pub use fiche::{FICHE_OCTETS_MAX, Fiche, GRAINE_OCTETS, ecrire_une_fiche, lire_une_fiche};

/// Ce qui peut clocher, et rien d'autre.
///
/// # PAS UN SEUL CAS QUI N'AIT SA LIGNE
///
/// Une variante fourre-tout — `Illisible(&'static str)` — aurait laissé
/// l'appelant deviner s'il doit refuser de démarrer ou passer outre. Ici, un
/// compte illisible se distingue d'une graine illisible, parce que **le premier
/// ne compte pas et le second condamne** (voir [`fiche`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Faute {
    /// La fiche ne porte pas de ligne `machine =`.
    SansMachine,
    /// La ligne `machine =` ne porte pas l'identifiant d'une machine.
    PasUneMachine,
    /// La fiche ne porte pas de ligne `graine =`.
    SansGraine,
    /// La ligne `graine =` ne fait pas trente-deux octets en hexadécimal.
    GraineIllisible,
    /// Le nom de service n'est pas de ceux que le protocole admet.
    NomRefuse,
    /// Ce nom est réservé par le protocole : un daemon ne l'annonce pas.
    NomReserve,
    /// Deux déclarations portent le même nom.
    ///
    /// **CE N'EST PAS UN DÉTAIL** : une réannonce du même nom REMPLACE la
    /// précédente (`modele.md` §2.4). Deux déclarations homonymes feraient
    /// donc disparaître la première en silence, et l'exploitant croirait avoir
    /// annoncé deux choses.
    NomEnDouble,
    /// Le port est nul : il n'en existe pas.
    PortNul,
    /// Il y a plus de déclarations que [`SERVICES_MAX`].
    TropDeServices,
    /// L'annonce ne s'encode pas, ou la réponse ne se décode pas.
    ProtocoleRefuse,
    /// Le tampon fourni est trop court pour ce qu'on y écrit.
    TamponTropCourt,
}

impl core::fmt::Display for Faute {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let quoi = match self {
            Self::SansMachine => "la fiche ne porte pas de ligne `machine =`",
            Self::PasUneMachine => "`machine =` ne porte pas l'identifiant d'une machine",
            Self::SansGraine => "la fiche ne porte pas de ligne `graine =`",
            Self::GraineIllisible => "`graine =` n'est pas trente-deux octets en hexadécimal",
            Self::NomRefuse => "ce nom de service n'est pas admis par le protocole",
            Self::NomReserve => "ce nom est réservé : un daemon ne l'annonce pas",
            Self::NomEnDouble => "deux déclarations portent le même nom",
            Self::PortNul => "le port est nul",
            Self::TropDeServices => "il y a plus de services que la borne",
            Self::ProtocoleRefuse => "le protocole refuse ce message",
            Self::TamponTropCourt => "le tampon est trop court",
        };
        f.write_str(quoi)
    }
}

/// Un écrivain qui pose du texte dans une tranche, et refuse de déborder.
///
/// # POURQUOI PAS `format!`
///
/// Cette crate est `#![no_std]` **sans `alloc`**, comme tout l'étage 2 sauf
/// `ams-config`. Un `String` y ferait entrer l'allocateur pour composer un
/// fichier de trois lignes dont la taille est connue d'avance.
///
/// **IL NE TRONQUE JAMAIS EN SILENCE** : un tampon trop court fait échouer
/// l'écriture entière, parce qu'une fiche d'identité à moitié écrite serait
/// lue comme une fiche sans graine — et l'appelant croirait avoir enrôlé la
/// machine.
struct Ecrivain<'a> {
    vers: &'a mut [u8],
    pose: usize,
    deborde: bool,
}

impl<'a> Ecrivain<'a> {
    const fn neuf(vers: &'a mut [u8]) -> Self {
        Self {
            vers,
            pose: 0,
            deborde: false,
        }
    }

    /// Ce qui a été posé, ou la faute si l'on a débordé.
    const fn fini(self) -> Result<usize, Faute> {
        if self.deborde {
            Err(Faute::TamponTropCourt)
        } else {
            Ok(self.pose)
        }
    }
}

impl core::fmt::Write for Ecrivain<'_> {
    fn write_str(&mut self, texte: &str) -> core::fmt::Result {
        // **UNE FOIS DÉBORDÉ, ON N'ÉCRIT PLUS RIEN**, et ce n'est pas une
        // économie : sans cela, une écriture plus COURTE qui suit une écriture
        // refusée tient dans la place restante et se pose **là où la refusée
        // aurait dû commencer**. Le tampon ne porte alors plus un préfixe du
        // texte voulu, mais un mélange — et personne ne peut raisonner sur un
        // mélange. Le fuzz l'a montré sur la fiche : les trente-deux paires
        // hexadécimales de la graine se posaient derrière le compte, sans leur
        // clé `graine = `, formant une ligne que la lecture saute par chance et
        // non par construction.
        //
        // Avec cette garde, le tampon porte TOUJOURS un préfixe. C'est ce qui
        // rend la propriété éprouvable : un préfixe se lit comme la même
        // identité, ou ne se lit pas.
        if self.deborde {
            return Ok(());
        }
        let octets = texte.as_bytes();
        let fin = self.pose.saturating_add(octets.len());
        match self.vers.get_mut(self.pose..fin) {
            Some(place) => {
                place.copy_from_slice(octets);
                self.pose = fin;
                Ok(())
            }
            None => {
                // **ON RETIENT LE DÉBORDEMENT, ET ON REND `Ok`.** `core::fmt`
                // avale l'erreur d'un argument au milieu d'un `write!` et rend
                // un résultat global : s'arrêter ici laisserait l'appelant
                // avec un tampon à moitié rempli sans savoir qu'il l'est.
                self.deborde = true;
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests;
