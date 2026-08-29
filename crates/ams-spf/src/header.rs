//! L'en-tête `Received-SPF` (RFC 7208 §9.1), **composé sans allouer**.
//!
//! # Pourquoi un verdict qu'on n'écrit pas ne sert à rien
//!
//! L'évaluation conclut, la session décide, et là s'arrête ce que SPF apporte —
//! sauf si on l'ÉCRIT. Un message accepté ne porte alors aucune trace de ce
//! qu'on a vérifié : ni le lecteur, ni un filtre en aval, ni DMARC (C9) ne
//! peuvent savoir si l'expéditeur était autorisé. C'est ce que cet en-tête
//! répare : il dépose dans le message ce que le journal savait déjà.
//!
//! # Ces octets viennent du pair, et ils vont dans un en-tête
//!
//! L'expéditeur d'enveloppe et le `HELO` sont **choisis par celui qu'on
//! vérifie**. Les recopier tels quels dans un en-tête serait exactement la
//! faille qu'on passe son temps à fermer ailleurs : un `CR LF` bien placé, et le
//! pair écrit les en-têtes qu'il veut dans le message qu'on remet.
//!
//! Deux règles ferment cela, et aucune n'est facultative :
//!
//! 1. **Tout octet hors de l'ASCII imprimable fait REFUSER l'en-tête entier.**
//!    Pas d'échappement, pas de remplacement : on n'écrit pas un en-tête dont on
//!    ne sait pas ce qu'il dit.
//! 2. **Les quatre octets qui ont un sens syntaxique** — `"`, `\`, `(` et `)` —
//!    sont préfixés d'une contre-oblique (RFC 5322 §3.2.1, `quoted-pair`). Sans
//!    cela, une parenthèse dans une partie locale fermerait le commentaire, et
//!    la suite se lirait comme des paramètres.
//!
//! # Le pliage n'est pas cosmétique
//!
//! RFC 5322 §2.1.1 borne une ligne à 998 octets. Un expéditeur de 320 octets, un
//! `HELO` de 255 et un domaine de serveur de 255 ne tiennent pas sur une ligne :
//! l'en-tête est donc plié (§2.2.3), et **la borne des 998 est vérifiée**, pas
//! supposée. Un en-tête qui la dépasserait est refusé plutôt qu'émis.

use core::fmt::Write as _;
use core::net::IpAddr;

use crate::{Error, Verdict};

/// Un tampon qui suffit toujours à cet en-tête.
///
/// L'expéditeur (320 au plus), le `HELO` et le domaine du serveur (255 chacun)
/// y figurent DEUX FOIS — une dans le commentaire, une dans les paramètres — et
/// l'échappement peut allonger. Deux kibioctets majorent tout cela largement.
pub const RECEIVED_SPF_MAX: usize = 2048;

/// La longueur maximale d'une ligne (RFC 5322 §2.1.1), `CRLF` non compris.
const LIGNE_MAX: usize = 998;

/// La longueur au-delà de laquelle on plie, quand un point de pliage se
/// présente (RFC 5322 §2.1.1 : « 78 octets recommandés »).
const LIGNE_SOUHAITEE: usize = 78;

/// Quelle identité a été vérifiée (RFC 7208 §9.1, clé `identity`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Identity {
    /// L'expéditeur d'enveloppe.
    MailFrom,
    /// Le nom du `HELO` — c'est le cas de l'expéditeur nul (§2.4).
    Helo,
}

impl Identity {
    fn mot(self) -> &'static [u8] {
        match self {
            Self::MailFrom => b"mailfrom",
            Self::Helo => b"helo",
        }
    }
}

/// Ce que l'en-tête doit dire.
#[derive(Debug, Clone, Copy)]
pub struct ReceivedSpf<'a> {
    /// Le verdict.
    pub result: Verdict,
    /// L'adresse du pair.
    pub client: IpAddr,
    /// L'expéditeur vérifié, sous la forme `locale@domaine`.
    pub sender: &'a [u8],
    /// Le nom annoncé au `HELO`.
    pub helo: &'a [u8],
    /// Le nom du serveur qui a vérifié.
    pub receiver: &'a [u8],
    /// Laquelle des deux identités a été vérifiée.
    pub identity: Identity,
}

/// Compose l'en-tête, `CRLF` final compris.
///
/// # Errors
///
/// [`Error::HeaderTooLong`] si `out` ne suffit pas, ou si une ligne dépasserait
/// 998 octets ; [`Error::NotPrintable`] si une valeur porte un octet hors de
/// l'ASCII imprimable — voir la documentation du module.
pub fn write_received_spf<'b>(
    out: &'b mut [u8],
    champ: &ReceivedSpf<'_>,
) -> Result<&'b [u8], Error> {
    for valeur in [champ.sender, champ.helo, champ.receiver] {
        if !valeur
            .iter()
            .all(|octet| octet.is_ascii_graphic() || *octet == b' ')
        {
            return Err(Error::NotPrintable);
        }
    }

    let mut plume = Plume::neuve(out);
    plume.pousser(b"Received-SPF: ")?;
    plume.pousser(mot_du_verdict(champ.result))?;

    // ── Le commentaire (RFC 5322 §3.2.2) ────────────────────────────────────
    plume.plier_si_besoin(longueur_du_commentaire(champ))?;
    plume.pousser(b"(")?;
    plume.echapper(champ.receiver)?;
    plume.pousser(b": ")?;
    let (avant, milieu, apres) = phrase_du_verdict(champ.result);
    plume.pousser(avant)?;
    plume.echapper(champ.sender)?;
    plume.pousser(milieu)?;
    plume.adresse(champ.client)?;
    plume.pousser(apres)?;
    plume.pousser(b")")?;

    // ── Les paramètres (RFC 7208 §9.1) ──────────────────────────────────────
    plume.pousser(b";")?;
    plume.plier_si_besoin(b"client-ip=".len().saturating_add(ADRESSE_MAX))?;
    plume.pousser(b"client-ip=")?;
    plume.adresse(champ.client)?;
    plume.paire(b"envelope-from=", champ.sender, true)?;
    plume.paire(b"helo=", champ.helo, true)?;
    plume.paire(b"identity=", champ.identity.mot(), false)?;
    plume.paire(b"receiver=", champ.receiver, true)?;

    plume.pousser(b"\r\n")?;
    Ok(plume.fini())
}

/// Le mot du verdict (RFC 7208 §2.6).
fn mot_du_verdict(verdict: Verdict) -> &'static [u8] {
    match verdict {
        Verdict::None => b"none",
        Verdict::Neutral => b"neutral",
        Verdict::Pass => b"pass",
        Verdict::Fail => b"fail",
        Verdict::SoftFail => b"softfail",
        Verdict::TempError => b"temperror",
        Verdict::PermError => b"permerror",
    }
}

/// Les trois morceaux de la phrase du commentaire, autour de l'expéditeur puis
/// de l'adresse du pair.
///
/// **Sept verdicts, sept phrases**, et aucune n'est décorative : c'est ce que
/// lira l'humain qui, six mois plus tard, se demandera pourquoi ce message est
/// passé. Les tournures suivent les exemples de la RFC 7208 §9.1, que les
/// lecteurs de courrier savent déjà rendre.
fn phrase_du_verdict(verdict: Verdict) -> (&'static [u8], &'static [u8], &'static [u8]) {
    match verdict {
        Verdict::Pass => (b"domain of ", b" designates ", b" as permitted sender"),
        Verdict::Fail => (
            b"domain of ",
            b" does not designate ",
            b" as permitted sender",
        ),
        Verdict::SoftFail => (
            b"transitioning domain of ",
            b" does not designate ",
            b" as permitted sender",
        ),
        Verdict::Neutral => (b"domain of ", b" neither permits nor denies ", b""),
        Verdict::None => (
            b"domain of ",
            b" does not designate permitted sender hosts for ",
            b"",
        ),
        Verdict::TempError => (b"error in processing during lookup of ", b"; client ", b""),
        Verdict::PermError => (
            b"permanent error in processing during lookup of ",
            b"; client ",
            b"",
        ),
    }
}

/// Ce que le commentaire fera, au plus, avant qu'on décide de plier.
///
/// **Une majoration suffit** : ce nombre ne sert qu'à décider d'un repli, c'est
/// à dire d'une recommandation (78 octets). La seule borne qui doit être exacte
/// est celle des 998, et elle est vérifiée à l'écriture, pas estimée ici.
fn longueur_du_commentaire(champ: &ReceivedSpf<'_>) -> usize {
    let (avant, milieu, apres) = phrase_du_verdict(champ.result);
    longueur_echappee(champ.receiver)
        .saturating_add(longueur_echappee(champ.sender))
        .saturating_add(avant.len())
        .saturating_add(milieu.len())
        .saturating_add(apres.len())
        .saturating_add(ADRESSE_MAX)
        // `(`, `: ` et `)`.
        .saturating_add(4)
}

/// Ce que `valeur` fera une fois échappée.
fn longueur_echappee(valeur: &[u8]) -> usize {
    valeur.iter().fold(0_usize, |total, octet| {
        total.saturating_add(if doit_etre_echappe(*octet) { 2 } else { 1 })
    })
}

/// Cet octet a-t-il un sens syntaxique ?
///
/// Les quatre qui en ont : la contre-oblique elle-même, le guillemet qui ferme
/// une chaîne, et les deux parenthèses qui ouvrent et ferment un commentaire.
fn doit_etre_echappe(octet: u8) -> bool {
    matches!(octet, b'\\' | b'"' | b'(' | b')')
}

/// La plus longue écriture d'une adresse par la bibliothèque standard.
const ADRESSE_MAX: usize = 45;

/// De quoi écrire un en-tête plié, sans jamais dépasser une ligne.
struct Plume<'a> {
    out: &'a mut [u8],
    ecrits: usize,
    /// Où commence la ligne courante.
    ligne: usize,
    /// Ce qui a fait échouer une écriture passée par `core::fmt`.
    ///
    /// `fmt::Write` ne rend qu'une erreur SANS CAUSE ; on retient la nôtre pour
    /// dire laquelle des deux bornes a cédé.
    faute: Option<Error>,
}

impl core::fmt::Write for Plume<'_> {
    fn write_str(&mut self, morceau: &str) -> core::fmt::Result {
        match self.pousser(morceau.as_bytes()) {
            Ok(()) => Ok(()),
            Err(cause) => {
                self.faute = Some(cause);
                Err(core::fmt::Error)
            }
        }
    }
}

impl<'a> Plume<'a> {
    fn neuve(out: &'a mut [u8]) -> Self {
        Self {
            out,
            ecrits: 0,
            ligne: 0,
            faute: None,
        }
    }

    /// Écrit l'adresse du pair sous sa forme usuelle.
    ///
    /// **On emprunte le `Display` de la bibliothèque standard** plutôt que
    /// d'écrire le nôtre : la forme abrégée d'une adresse IPv6 a ses règles
    /// (RFC 5952) qu'un second écrivain finirait par appliquer autrement, et
    /// deux écritures d'une même adresse dans un même message seraient un
    /// défaut qu'on ne verrait pas.
    fn adresse(&mut self, client: IpAddr) -> Result<(), Error> {
        // Une adresse ne porte aucun des quatre octets à échapper : ce sont des
        // chiffres, des points et des deux-points.
        match write!(self, "{client}") {
            Ok(()) => Ok(()),
            // `fmt::Error` ne dit rien ; la cause, elle, a été retenue.
            Err(_) => Err(self.faute.unwrap_or(Error::HeaderTooLong)),
        }
    }

    fn pousser(&mut self, morceau: &[u8]) -> Result<(), Error> {
        let fin = self.ecrits.saturating_add(morceau.len());
        let place = self
            .out
            .get_mut(self.ecrits..fin)
            .ok_or(Error::HeaderTooLong)?;
        place.copy_from_slice(morceau);
        self.ecrits = fin;
        // LA BORNE DES 998 EST VÉRIFIÉE, PAS SUPPOSÉE. Un en-tête plus long
        // qu'une ligne n'est pas un en-tête : les analyseurs en aval le coupent
        // où ils veulent, et ce qu'ils en lisent n'est plus ce qu'on a écrit.
        if self.ecrits.saturating_sub(self.ligne) > LIGNE_MAX {
            return Err(Error::HeaderTooLong);
        }
        Ok(())
    }

    /// Plie si ce qui vient ne tient pas sur la ligne recommandée.
    fn plier_si_besoin(&mut self, longueur: usize) -> Result<(), Error> {
        let courante = self.ecrits.saturating_sub(self.ligne);
        if courante.saturating_add(longueur) > LIGNE_SOUHAITEE {
            // Le repli : `CRLF` suivi d'une espace (RFC 5322 §2.2.3). L'espace
            // FAIT PARTIE du repli — sans elle, la ligne suivante serait un
            // nouvel en-tête.
            self.pousser(b"\r\n")?;
            self.ligne = self.ecrits;
            return self.pousser(b" ");
        }
        self.pousser(b" ")
    }

    /// Un paramètre `clé=valeur`, précédé de son point-virgule.
    fn paire(&mut self, cle: &[u8], valeur: &[u8], entre_guillemets: bool) -> Result<(), Error> {
        self.pousser(b";")?;
        let guillemets = usize::from(entre_guillemets).saturating_mul(2);
        self.plier_si_besoin(
            cle.len()
                .saturating_add(longueur_echappee(valeur))
                .saturating_add(guillemets),
        )?;
        self.pousser(cle)?;
        if entre_guillemets {
            self.pousser(b"\"")?;
            self.echapper(valeur)?;
            return self.pousser(b"\"");
        }
        self.echapper(valeur)
    }

    /// Écrit `valeur` en préfixant d'une contre-oblique ce qui a un sens.
    fn echapper(&mut self, valeur: &[u8]) -> Result<(), Error> {
        for octet in valeur {
            if doit_etre_echappe(*octet) {
                self.pousser(b"\\")?;
            }
            self.pousser(core::slice::from_ref(octet))?;
        }
        Ok(())
    }

    fn fini(self) -> &'a [u8] {
        self.out.get(..self.ecrits).unwrap_or_default()
    }
}

#[cfg(test)]
mod tests;
