//! Implémentation des traits d'[`ams_rt`] sur la bibliothèque standard.
//!
//! C'est l'implémentation d'aujourd'hui : TCP par [`std::net`], horloge par
//! [`std::time`]. Elle n'a pas d'autre rôle que de traduire, et n'ajoute aucune
//! politique — pas de délai d'attente, pas de limite de connexions, pas de
//! journalisation. Ces décisions appartiennent au serveur, qui les prendra une
//! fois pour toutes les implémentations.

use std::io::{Read as _, Write as _};
use std::net::{TcpListener, TcpStream, ToSocketAddrs};
use std::time::{SystemTime, UNIX_EPOCH};

use ams_rt::{Clock, Error, Listener, Result, Stream};

/// Traduit une erreur `std::io` vers le vocabulaire restreint d'[`ams_rt`].
///
/// Tout ce qui n'est pas l'un des trois cas nommés devient [`Error::Refused`] :
/// la couture ne promet pas de distinguer plus finement, et prétendre le
/// contraire ferait dépendre le serveur de détails que la cible Air n'aura pas.
fn traduire(erreur: &std::io::Error) -> Error {
    match erreur.kind() {
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut => Error::WouldBlock,
        std::io::ErrorKind::Interrupted => Error::Interrupted,
        std::io::ErrorKind::BrokenPipe
        | std::io::ErrorKind::ConnectionReset
        | std::io::ErrorKind::ConnectionAborted
        | std::io::ErrorKind::NotConnected
        | std::io::ErrorKind::UnexpectedEof => Error::Closed,
        _ => Error::Refused,
    }
}

/// Un flux TCP de la bibliothèque standard.
#[derive(Debug)]
pub struct StdStream(TcpStream);

impl StdStream {
    /// Enveloppe un [`TcpStream`] déjà établi.
    #[must_use]
    pub fn new(flux: TcpStream) -> Self {
        Self(flux)
    }
}

impl Stream for StdStream {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        self.0.read(buf).map_err(|e| traduire(&e))
    }

    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        self.0.write(buf).map_err(|e| traduire(&e))
    }

    fn flush(&mut self) -> Result<()> {
        self.0.flush().map_err(|e| traduire(&e))
    }
}

/// Un écouteur TCP de la bibliothèque standard.
#[derive(Debug)]
pub struct StdListener(TcpListener);

impl StdListener {
    /// Ouvre un écouteur sur `adresse`.
    ///
    /// # Erreurs
    ///
    /// Rend [`Error::Refused`] si l'adresse ne peut pas être résolue ou si le
    /// système refuse la mise en écoute (port occupé, privilèges insuffisants).
    pub fn bind<A: ToSocketAddrs>(adresse: A) -> Result<Self> {
        TcpListener::bind(adresse)
            .map(Self)
            .map_err(|e| traduire(&e))
    }

    /// L'adresse effectivement écoutée.
    ///
    /// Utile quand `bind` a reçu le port `0` : le système en a choisi un, et
    /// c'est ici qu'on apprend lequel.
    ///
    /// # Erreurs
    ///
    /// Rend [`Error::Refused`] si le système ne peut pas rendre l'adresse.
    pub fn local_addr(&self) -> Result<std::net::SocketAddr> {
        self.0.local_addr().map_err(|e| traduire(&e))
    }
}

impl Listener for StdListener {
    type Stream = StdStream;

    fn accept(&mut self) -> Result<Self::Stream> {
        self.0
            .accept()
            .map(|(flux, _pair)| StdStream(flux))
            .map_err(|e| traduire(&e))
    }
}

/// L'horloge murale du système.
#[derive(Debug, Clone, Copy, Default)]
pub struct StdClock;

impl Clock for StdClock {
    fn now_unix_seconds(&self) -> i64 {
        // `SystemTime` peut précéder l'époque si l'horloge de la machine est
        // réglée avant 1970 ; le cas est traité plutôt qu'ignoré.
        match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(depuis) => i64::try_from(depuis.as_secs()).unwrap_or(i64::MAX),
            Err(avant) => {
                i64::try_from(avant.duration().as_secs()).map_or(i64::MIN, i64::wrapping_neg)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn un_aller_retour_sur_boucle_locale() {
        let mut ecouteur = StdListener::bind("127.0.0.1:0").expect("mise en écoute");
        let adresse = ecouteur.local_addr().expect("adresse locale");

        let client = std::thread::spawn(move || {
            let mut flux = StdStream::new(TcpStream::connect(adresse).expect("connexion"));
            flux.write(b"PING\r\n").expect("écriture");
            flux.flush().expect("vidage");
            let mut recu = [0_u8; 6];
            flux.read(&mut recu).expect("lecture");
            recu
        });

        let mut servi = ecouteur.accept().expect("acceptation");
        let mut recu = [0_u8; 6];
        let lus = servi.read(&mut recu).expect("lecture");
        assert_eq!(&recu[..lus], b"PING\r\n");
        servi.write(b"PONG\r\n").expect("écriture");
        servi.flush().expect("vidage");

        assert_eq!(&client.join().expect("fil client"), b"PONG\r\n");
    }

    #[test]
    fn l_horloge_est_posterieure_a_l_ecriture_de_ce_test() {
        // 2026-01-01T00:00:00Z. Une borne inférieure vraie et stable : le test ne
        // peut pas passer sur une horloge manifestement fausse.
        assert!(StdClock.now_unix_seconds() > 1_767_225_600);
    }
}
