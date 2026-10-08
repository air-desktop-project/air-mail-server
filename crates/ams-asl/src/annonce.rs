// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Ce que ce serveur annonce : un nom par point d'écoute.
//!
//! # POURQUOI UN NOM PAR POINT, ET NON UN NOM PAR PROTOCOLE
//!
//! Tranché le 2026-10-08 (Thierry). Une annonce peut porter plusieurs points,
//! et il était tentant de dire `air-mail-imap` → `tcp/143` et `tcp/993`.
//! **Mais rien, dans la réponse, ne dit lequel des deux est le TLS implicite.**
//! Un client qui résout obtient deux candidats et doit deviner ; deux clients
//! devineraient différemment.
//!
//! Un nom par point d'écoute ne laisse rien à deviner : `asl where <m>
//! air-mail-imaps` répond une chose et une seule. Le prix est huit annonces au
//! lieu de quatre, et elles voyagent sur une connexion déjà ouverte.
//!
//! # LES NOMS NE SONT PAS IMPOSÉS ICI
//!
//! Cette crate les VALIDE, elle ne les choisit pas : ils viennent de la
//! configuration, et l'exploitant qui fait tourner deux serveurs sur une même
//! machine a besoin de les distinguer. Les noms d'usage sont documentés avec
//! l'option qui les porte, pas gravés dans le code.
//!
//! # DEUX NOMS SONT REFUSÉS, ET POUR DEUX RAISONS DIFFÉRENTES
//!
//! - **`asl-directory`** est réservé par le protocole : il désigne l'annuaire
//!   lui-même, et l'annoncer fait répondre `403` avec une ligne au journal
//!   (décision 73). Le refuser ici évite un aller-retour pour apprendre une
//!   chose qu'on sait d'avance.
//! - **`asl-echo`** n'est pas réservé, et c'est pire : il serait ACCEPTÉ. Ce
//!   nom désigne une machine qui répond à des sondes signées, et `asl ping`
//!   résout `asl-echo` pour conclure si une machine est joignable. L'annoncer
//!   sans y répondre ferait conclure « injoignable » à tout qui sonde cette
//!   machine — **un diagnostic faux, sur une machine saine**, et personne ne
//!   saurait d'où il vient.

use asl_id::{Genre, Identifiant};
use asl_proto::{Annonce, NOM_ASL_ECHO, NomService, PointEcoute, Port, Protocole};
use core::net::IpAddr;

use crate::Faute;

/// Combien de services ce serveur peut annoncer.
///
/// **SEIZE, POUR HUIT ATTENDUS.** Les huit noms d'usage — SMTP, soumission,
/// SMTPS, IMAP, IMAPS, POP3, POP3S, l'API — plus la marge d'un exploitant qui
/// en nommerait d'autres. Ce n'est pas une borne du protocole : c'est une borne
/// de nous, pour qu'une configuration fautive se refuse à l'écriture plutôt que
/// d'ouvrir seize connexions de trop.
pub const SERVICES_MAX: usize = 16;

/// Ce que l'exploitant déclare : un nom, un protocole, un port.
///
/// # LE PORT EST CELUI QU'UN CLIENT DOIT JOINDRE
///
/// Pas celui que ce serveur a lié. Il n'y a aucune façon pour ce serveur de
/// deviner la redirection qui les sépare, et l'annuaire **sonde** ce qui est
/// annoncé : une déclaration fausse se voit dans son verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Declaration<'a> {
    /// Le nom sous lequel les clients le chercheront.
    pub nom: &'a str,
    /// TCP ou UDP. **UDP ne se sonde pas** (`modele.md` §4.3) : son verdict
    /// sera `non_sonde`, et ce n'est pas une panne.
    pub protocole: Protocole,
    /// Le port joignable du dehors.
    pub port: u16,
}

/// Vérifie un jeu de déclarations **avant** d'en encoder aucune.
///
/// # POURQUOI D'UN SEUL COUP, ET NON UNE PAR UNE
///
/// Le doublon de nom ne se voit que sur l'ensemble. Et il ne pardonne pas :
/// une réannonce du même nom REMPLACE la précédente (`modele.md` §2.4), si bien
/// que deux déclarations homonymes feraient disparaître la première **sans que
/// rien ne le dise** — l'exploitant croirait avoir annoncé deux services, et
/// l'annuaire n'en publierait qu'un.
///
/// # Errors
///
/// [`Faute::TropDeServices`], [`Faute::NomRefuse`], [`Faute::NomReserve`],
/// [`Faute::NomEnDouble`], [`Faute::PortNul`].
pub fn verifier_les_declarations(declarations: &[Declaration<'_>]) -> Result<(), Faute> {
    if declarations.len() > SERVICES_MAX {
        return Err(Faute::TropDeServices);
    }
    for (rang, declaration) in declarations.iter().enumerate() {
        verifier_un_nom(declaration.nom)?;
        if declaration.port == 0 {
            return Err(Faute::PortNul);
        }
        // Comparaison deux à deux : seize au plus, donc cent vingt
        // comparaisons. Un tri demanderait un tampon que cette crate n'a pas le
        // droit d'allouer, pour gagner sur un compte qui ne dépassera jamais
        // seize.
        if declarations
            .iter()
            .skip(rang.saturating_add(1))
            .any(|autre| autre.nom == declaration.nom)
        {
            return Err(Faute::NomEnDouble);
        }
    }
    Ok(())
}

/// Ce nom est-il annonçable par ce serveur ?
///
/// # Errors
///
/// [`Faute::NomRefuse`], [`Faute::NomReserve`].
pub fn verifier_un_nom(nom: &str) -> Result<(), Faute> {
    let lu = NomService::analyser(nom).map_err(|_| Faute::NomRefuse)?;
    // **`reserve()` EST CE QUI COUVRE `asl-directory`**, et le renommer ici
    // ferait deux écritures de la même règle — dont une qui vieillirait le jour
    // où le protocole en réserverait un second. `asl-echo`, lui, n'est pas
    // réservé par le protocole : c'est NOUS qui le refusons, et c'est pourquoi
    // il est nommé.
    if lu.reserve() || nom == NOM_ASL_ECHO {
        return Err(Faute::NomReserve);
    }
    Ok(())
}

/// Encode l'annonce de cette déclaration, et rend combien d'octets elle occupe.
///
/// `adresses_locales` est **facultatif, et ce n'est pas ce qui sert à nous
/// joindre** (`protocole.md` §1.1) : c'est ce qui permet à l'annuaire de
/// trancher si ce serveur est derrière un NAT, en comparant ce qu'on annonce à
/// ce qu'il observe. Sans aucune, il répond `indetermine` — et c'est juste :
/// il n'a rien mesuré (C6).
///
/// # Errors
///
/// Celles de [`verifier_un_nom`], [`Faute::PortNul`],
/// [`Faute::PasUneMachine`], [`Faute::ProtocoleRefuse`],
/// [`Faute::TamponTropCourt`].
pub fn composer_une_annonce(
    machine: Identifiant,
    declaration: &Declaration<'_>,
    adresses_locales: &[IpAddr],
    vers: &mut [u8],
) -> Result<usize, Faute> {
    verifier_un_nom(declaration.nom)?;
    if machine.genre() != Genre::Machine {
        return Err(Faute::PasUneMachine);
    }

    // **DEUXIÈME LECTURE DU MÊME NOM, ET ELLE NE PEUT PAS ÉCHOUER** :
    // `verifier_un_nom` vient de le lire. Un `?` ici ouvrirait une branche que
    // rien ne peut emprunter ; le relire plutôt que de faire rendre le
    // `NomService` par `verifier_un_nom` garde cette fonction-là utilisable
    // seule, pour valider une configuration sans rien encoder.
    let nom = NomService::analyser(declaration.nom).expect("`verifier_un_nom` vient de le lire");
    let port = Port::depuis_u16(declaration.port).map_err(|_| Faute::PortNul)?;
    let points = [PointEcoute::nouveau(declaration.protocole, port)];

    let annonce = Annonce::nouvelle(machine, nom, &points, adresses_locales)
        .map_err(|_| Faute::ProtocoleRefuse)?;
    annonce.encoder(vers).map_err(|_| Faute::TamponTropCourt)
}
