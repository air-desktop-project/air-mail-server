// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Ce que l'annuaire répond à une annonce, et ce qu'on en retient.
//!
//! # LA MOITIÉ UTILE DE CETTE RÉPONSE N'EST PAS L'IDENTIFIANT
//!
//! Elle en porte cinq choses, et trois sont du diagnostic qu'aucun autre moyen
//! ne donne (`protocole.md` §1.1) :
//!
//! - **la cadence du bail**, qui décide du keepalive — et qui **vient du
//!   serveur**, jamais d'ici ;
//! - **`vu_depuis`**, sous quelle adresse l'annuaire nous a vus. Rien d'autre
//!   ne l'apprend à un daemon ;
//! - **`derriere_nat`**, le verdict que l'annuaire est SEUL à pouvoir rendre,
//!   et qui vaut `indetermine` quand on ne lui a annoncé aucune adresse
//!   locale — parce qu'il n'a alors rien à comparer, et qu'un booléen l'aurait
//!   forcé à affirmer « non » ;
//! - **un verdict par point annoncé** : est-ce que quelqu'un peut vraiment
//!   nous atteindre, à la seconde où l'on démarre, et non le jour où un
//!   utilisateur s'en plaint.
//!
//! # POURQUOI CE MODULE EXISTE, PUISQUE `asl-proto` DÉCODE DÉJÀ
//!
//! Parce que le décodage demande un jeu de tampons que l'appelant doit tenir,
//! et que ce qui nous intéresse est une poignée de valeurs `Copy`. Rendre une
//! `asl_proto::Reponse` obligerait l'étage 3 à garder les tampons vivants le
//! temps qu'il la lise, pour quatre nombres et deux verdicts.
//!
//! **Ce module ne juge rien** : il ne fait que prendre ce dont la boucle a
//! besoin — la cadence à poser sur la connexion, et de quoi écrire une ligne
//! de journal qui dise la vérité.

use asl_id::Identifiant;
use asl_proto::{Reponse, VerdictNat, cadrage::TamponsReponse};

use crate::Faute;

/// Ce qu'on retient de la réponse à une annonce.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cadence {
    /// L'identifiant que l'annuaire a attribué au service.
    ///
    /// **IL EST DÉRIVÉ, DONC STABLE** (serveur 0.37.0) : la même machine et le
    /// même nom rendent le même `s-…`, à l'autre racine comme après un
    /// redémarrage. Deux annonces qui rendraient deux identifiants seraient
    /// deux services, et ce n'est pas le cas.
    pub service: Identifiant,
    /// À quelle cadence tenir le bail, en secondes.
    pub keepalive_secondes: u16,
    /// Au bout de combien de temps sans un mot l'annuaire nous oublie.
    ///
    /// Le type garantit qu'elle vaut au moins le double du keepalive : à un
    /// pour un, la première perte de paquet tuerait un daemon parfaitement
    /// sain.
    pub inactivite_secondes: u16,
    /// Le verdict de NAT, qui peut être indéterminé.
    pub derriere_nat: VerdictNat,
    /// Combien de points l'annuaire a jugés joignables.
    pub joignables: usize,
    /// Combien il en a jugés injoignables.
    ///
    /// **CE N'EST PAS LE COMPLÉMENT DU PRÉCÉDENT** : un point peut être
    /// `en_cours` — l'annuaire n'a pas encore sondé — ou `non_sonde`, ce qu'est
    /// toujours un point UDP. Les additionner pour en déduire le reste
    /// affirmerait un verdict que personne n'a rendu.
    pub injoignables: usize,
}

/// Lit la réponse à une annonce.
///
/// # Errors
///
/// [`Faute::ProtocoleRefuse`] si le corps ne se décode pas, ou s'il dit quelque
/// chose que le protocole interdit — un point UDP jugé joignable, par exemple,
/// qu'`asl-proto` refuse parce que rien ne l'a mesuré.
pub fn lire_la_reponse(corps: &[u8]) -> Result<Cadence, Faute> {
    let mut tampons = TamponsReponse::nouveaux();
    let lue = Reponse::decoder(corps, &mut tampons).map_err(|_| Faute::ProtocoleRefuse)?;
    Ok(resumer(&lue))
}

/// Ce qu'on garde d'une réponse décodée.
fn resumer(lue: &Reponse<'_>) -> Cadence {
    Cadence {
        service: lue.service,
        keepalive_secondes: lue.bail.keepalive_secondes(),
        inactivite_secondes: lue.bail.inactivite_secondes(),
        derriere_nat: lue.derriere_nat,
        joignables: lue
            .joignabilite
            .iter()
            .filter(|un| matches!(un.verdict, asl_proto::Verdict::Joignable { .. }))
            .count(),
        injoignables: lue
            .joignabilite
            .iter()
            .filter(|un| matches!(un.verdict, asl_proto::Verdict::Injoignable { .. }))
            .count(),
    }
}
