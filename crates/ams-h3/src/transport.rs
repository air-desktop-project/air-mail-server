// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Ce que HTTP/3 demande au transport, et rien de plus.
//!
//! # POURQUOI NOMMER CETTE FRONTIÈRE PLUTÔT QUE D'APPELER `Connection`
//!
//! HTTP/3 n'a besoin que de quatre choses de QUIC : ouvrir un flux
//! unidirectionnel, lire un flux, y écrire, et savoir si le pair l'a terminé.
//! **Tout le reste — les clés, les numéros, la congestion, les retransmissions —
//! ne le regarde pas**, et le lui laisser voir donnerait à un conducteur d'étage
//! supérieur les moyens de défaire ce que l'étage du dessous a décidé.
//!
//! Écrire cette frontière la rend aussi éprouvable : les essais d'HTTP/3 ne
//! demandent alors ni certificat ni poignée de main, et ce qu'ils montrent porte
//! sur HTTP/3 plutôt que sur TLS. **C'est une conséquence, et non le motif** : la
//! frontière serait juste même si elle ne servait à rien d'autre.
//!
//! # ET LE PONT VERS QUIC VIT AILLEURS
//!
//! Ce crate ne connaît pas `ams-quic-tls`, et c'est voulu : l'implémentation qui
//! relie les deux est une pièce d'assemblage, elle demande une vraie connexion
//! pour être éprouvée, et sa place est donc à l'étage qui les assemble.

use ams_proto_quic::StreamId;
use ams_quic::RecvState;

use crate::error::Error;

/// Le transport sous HTTP/3.
pub trait Transport {
    /// Ouvre un flux unidirectionnel (§6.2).
    ///
    /// # Errors
    ///
    /// Ce que le transport rend quand le pair n'en a pas ouvert le crédit
    /// (§4.6 de RFC 9000).
    fn open_uni(&mut self) -> Result<StreamId, Error>;

    /// Prend ce qui est prêt sur ce flux, dans l'ordre. Rend combien.
    fn read(&mut self, flux: StreamId, vers: &mut [u8]) -> usize;

    /// Écrit sur ce flux. Rend combien d'octets ont été pris.
    ///
    /// **CE N'EST PAS FORCÉMENT TOUT** : ce qui attend d'être émis est borné, et
    /// l'appelant doit regarder ce qu'il rend.
    ///
    /// # Errors
    ///
    /// Ce que le transport rend quand ce flux n'émet plus (§3.1 de RFC 9000).
    fn write(&mut self, flux: StreamId, octets: &[u8]) -> Result<usize, Error>;

    /// Annule ce flux : le pair recevra un `RESET_STREAM` (§19.4 de RFC 9000).
    ///
    /// **CE N'EST PAS `finish`**, et la différence porte tout §5.2 : `finish` dit
    /// « j'ai tout dit », celui-ci dit « ne l'attends pas, rien n'a été fait ».
    /// C'est ce qui permet à un client de rejouer sa requête ailleurs sans
    /// craindre de la faire exécuter deux fois.
    ///
    /// # Errors
    ///
    /// Ce que le transport rend quand ce flux n'a plus rien à annuler.
    fn reset(&mut self, flux: StreamId, code: u64) -> Result<(), Error>;

    /// Termine notre côté de ce flux (§19.8 de RFC 9000).
    ///
    /// # Errors
    ///
    /// Ce que le transport rend quand ce flux est déjà terminé.
    fn finish(&mut self, flux: StreamId) -> Result<(), Error>;

    /// Où en est la réception de ce flux (§3.2 de RFC 9000).
    fn recv_state(&self, flux: StreamId) -> Option<RecvState>;
}
