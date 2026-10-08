// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Le pont entre le conducteur HTTP/3 et une connexion QUIC, **côté client**.
//!
//! # POURQUOI UN SECOND PONT, ALORS QUE `ams-loop-tokio` EN A DÉJÀ UN
//!
//! Il y en a deux parce qu'il y a deux rôles, et la différence tient en une
//! méthode : `open_bi`. §6.1 de RFC 9114 dit qu'une requête voyage sur un flux
//! bidirectionnel **ouvert par le client** — le pont du serveur la refuse donc
//! tout net, et celui-ci est le seul endroit du dépôt où elle a un sens.
//!
//! Les deux auraient pu n'en faire qu'un, avec un drapeau. Ce drapeau serait
//! lu à chaque appel pour trancher une question qui ne change jamais pendant la
//! vie d'une connexion, et un pont mal réglé ouvrirait côté serveur un flux
//! dont le pair ne saurait rien faire.
//!
//! # LA RÈGLE DE L'ORPHELIN, ET CE QU'ELLE IMPOSE
//!
//! [`Transport`] appartient à `ams-h3`, [`Connection`] à `ams-quic-tls` :
//! aucun des deux n'est à nous, et leur mariage ne peut vivre que chez l'un
//! d'eux ou chez nous. Il vit donc ici, dans la crate qui tient la socket.

use ams_h3::Transport;
use ams_proto_quic::{Directional, StreamId};
use ams_quic::RecvState;
use ams_quic_tls::Connection;

/// Le pont : une connexion emprunté le temps d'un geste du conducteur.
pub(crate) struct Pont<'a>(pub(crate) &'a mut Connection);

impl Transport for Pont<'_> {
    fn open_uni(&mut self) -> Result<StreamId, ams_h3::Error> {
        self.0
            .open_stream(Directional::Unidirectional)
            .map_err(|_| ams_h3::Error::transport())
    }

    fn open_bi(&mut self) -> Result<StreamId, ams_h3::Error> {
        // **CE PONT SERT UN CLIENT**, et c'est tout ce qui le distingue de son
        // jumeau dans `ams-loop-tokio` : ici la méthode ouvre, là-bas elle
        // refuse.
        self.0
            .open_stream(Directional::Bidirectional)
            .map_err(|_| ams_h3::Error::transport())
    }

    fn read(&mut self, flux: StreamId, vers: &mut [u8]) -> usize {
        self.0.read(flux, vers)
    }

    fn write(&mut self, flux: StreamId, octets: &[u8]) -> Result<usize, ams_h3::Error> {
        self.0
            .write(flux, octets)
            .map_err(|_| ams_h3::Error::transport())
    }

    fn reset(&mut self, flux: StreamId, code: u64) -> Result<(), ams_h3::Error> {
        self.0
            .reset(flux, code)
            .map_err(|_| ams_h3::Error::transport())
    }

    fn finish(&mut self, flux: StreamId) -> Result<(), ams_h3::Error> {
        self.0.finish(flux).map_err(|_| ams_h3::Error::transport())
    }

    fn recv_state(&self, flux: StreamId) -> Option<RecvState> {
        self.0.recv_state(flux)
    }
}
