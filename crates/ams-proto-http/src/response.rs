//! Une réponse HTTP/1.1, lue par le CLIENT.
//!
//! # POURQUOI CETTE CRATE APPREND À LIRE UNE RÉPONSE
//!
//! Elle ne servait qu'au serveur : des requêtes entrent, des réponses sortent.
//! MTA-STS (RFC 8461 §3.3) inverse la relation pour un seul cas — aller chercher
//! `https://mta-sts.<domaine>/.well-known/mta-sts.txt` — et **ce qui revient est
//! une entrée hostile comme une autre** : le serveur est désigné par le domaine
//! qu'on interroge, c'est-à-dire, quand cela compte, par celui qui usurpe.
//!
//! Ce n'est pas un client HTTP général. Il n'y a ici ni négociation de contenu,
//! ni redirections — §3.3 les INTERDIT —, ni connexions persistantes, ni cookies.
//! **Écrire ce qu'on n'utilise pas serait écrire du code que rien n'éprouve.**
//!
//! # TROIS FAÇONS DE DÉLIMITER UN CORPS, ET ON LES CONNAÎT TOUTES LES TROIS
//!
//! §6 de RFC 9112 : `Transfer-Encoding: chunked`, `Content-Length`, ou la
//! fermeture de la connexion. On demande `Connection: close`, ce qui rend la
//! troisième suffisante — mais un serveur a le droit de découper, et **refuser
//! ce qu'on rencontrera est pire que de savoir le lire**.
//!
//! Ce qu'on refuse, en revanche : les DEUX à la fois. Un message qui porte
//! `Content-Length` ET `Transfer-Encoding` se découpe différemment selon qui le
//! lit, et c'est exactement la contrebande de requêtes (§11.2 de RFC 9112).

use crate::Error;
use crate::status::StatusCode;

/// Longueur maximale de la ligne d'état.
///
/// `HTTP/1.1 999 ` plus une raison : cent octets sont larges, et au-delà c'est
/// de la donnée qui a pris le chemin d'une ligne d'état.
const STATUS_LINE_MAX: usize = 128;

/// Comment le corps est délimité (§6 de RFC 9112).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Body {
    /// `Content-Length` : exactement ce nombre d'octets.
    Length(u64),
    /// `Transfer-Encoding: chunked` : des morceaux, jusqu'au morceau vide.
    Chunked,
    /// Ni l'un ni l'autre : le corps va jusqu'à la fermeture.
    ///
    /// **C'est le seul cas où l'on ne sait pas si l'on a tout lu**, et l'appelant
    /// doit le savoir : une connexion coupée au milieu rend un corps tronqué qui
    /// ressemble à un corps complet.
    UntilClose,
}

/// Ce que la tête d'une réponse porte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResponseHead {
    status: StatusCode,
    body: Body,
    /// Combien d'octets la tête occupe, ligne vide comprise.
    length: usize,
}

impl ResponseHead {
    /// Le code d'état.
    #[must_use]
    pub fn status(self) -> StatusCode {
        self.status
    }

    /// Comment le corps est délimité.
    #[must_use]
    pub fn body(self) -> Body {
        self.body
    }

    /// Combien d'octets la tête occupe — le corps commence après.
    #[must_use]
    pub fn length(self) -> usize {
        self.length
    }
}

/// Lit la tête d'une réponse.
///
/// Rend `Ok(None)` quand la tête n'est pas encore ENTIÈRE : l'appelant lit
/// davantage et rappelle. **Ce n'est pas une erreur**, et le distinguer d'un
/// refus est ce qui permet de lire un flux morceau par morceau sans deviner.
///
/// # Errors
///
/// [`Error::MalformedPath`] pour une ligne d'état qui n'en est pas une,
/// [`Error::MalformedFieldName`] et [`Error::MalformedFieldValue`] pour un champ
/// mal formé, [`Error::MalformedContentLength`] pour une longueur illisible ou
/// contradictoire, [`Error::FieldTooLong`] pour une tête démesurée.
pub fn parse_response(octets: &[u8], max_head: usize) -> Result<Option<ResponseHead>, Error> {
    let Some(fin) = fin_de_tete(octets, max_head)? else {
        return Ok(None);
    };
    let tete = octets.get(..fin).unwrap_or_default();

    // ── Les lignes, découpées sur `\r\n` ET SUR RIEN D'AUTRE ────────────────
    //
    // **UN `LF` ISOLÉ NE TERMINE PAS UNE LIGNE**, et c'est le refus qui compte
    // le plus ici. `Foo: bar\nBaz: qux` se lit comme DEUX champs chez les uns et
    // comme UN chez les autres : c'est ainsi qu'on fait passer un second message
    // à travers un intermédiaire (§11.2 de RFC 9112), et c'est la même faille
    // que la contrebande SMTP dans un autre protocole.
    let mut position = 0_usize;
    let mut status: Option<StatusCode> = None;
    let mut longueur: Option<u64> = None;
    let mut decoupe = false;
    // **LA TÊTE FINIT TOUJOURS PAR UNE LIGNE VIDE**, puisque `fin_de_tete` l'a
    // trouvée : la boucle sort là, et jamais faute de séparateur. Se rabattre
    // sur la longueur du reste porte cette certitude sans ouvrir un bras que
    // rien ne pourrait atteindre.
    while let Some(reste) = tete.get(position..) {
        let rang = trouver(reste, b"\r\n").unwrap_or(reste.len());
        let ligne = reste.get(..rang).unwrap_or_default();
        position = position.saturating_add(rang).saturating_add(2);
        // La ligne vide clôt la tête.
        if ligne.is_empty() {
            break;
        }
        if ligne.iter().any(|octet| matches!(octet, b'\r' | b'\n')) {
            return Err(Error::MalformedFieldName);
        }
        let Some(_) = status else {
            status = Some(ligne_d_etat(ligne)?);
            continue;
        };
        // **UNE CONTINUATION N'EST PLUS DU HTTP** (§5.2 de RFC 9112 : « obsolete
        // line folding »). Un message qui en porte se lit différemment selon
        // l'implémentation, et c'est encore une façon d'en faire passer un
        // second.
        if ligne
            .first()
            .is_some_and(|octet| matches!(octet, b' ' | b'\t'))
        {
            return Err(Error::MalformedFieldName);
        }
        let (nom, valeur) = champ(ligne)?;
        if egal_sans_casse(nom, b"content-length") {
            let lue = nombre(valeur).ok_or(Error::MalformedContentLength)?;
            // **DEUX `Content-Length` QUI DIFFÈRENT SE LISENT DE DEUX FAÇONS.**
            if longueur.is_some_and(|deja| deja != lue) {
                return Err(Error::MalformedContentLength);
            }
            longueur = Some(lue);
        } else if egal_sans_casse(nom, b"transfer-encoding") {
            // On ne connaît que `chunked`, et il doit être le seul codage.
            if !egal_sans_casse(valeur, b"chunked") {
                return Err(Error::MalformedContentLength);
            }
            decoupe = true;
        }
    }
    // Une tête sans ligne d'état n'est pas une réponse.
    let status = status.ok_or(Error::MalformedPath)?;

    // **LES DEUX À LA FOIS, C'EST LA CONTREBANDE** (§11.2 de RFC 9112).
    if decoupe && longueur.is_some() {
        return Err(Error::MalformedContentLength);
    }
    let body = if decoupe {
        Body::Chunked
    } else {
        longueur.map_or(Body::UntilClose, Body::Length)
    };
    Ok(Some(ResponseHead {
        status,
        body,
        length: fin,
    }))
}

/// Le code d'état d'une ligne `HTTP/1.x NNN raison`.
fn ligne_d_etat(ligne: &[u8]) -> Result<StatusCode, Error> {
    if ligne.len() > STATUS_LINE_MAX {
        return Err(Error::FieldTooLong);
    }
    // **HTTP/1.0 ET HTTP/1.1 SEULEMENT.** Un serveur qui répondrait `HTTP/2` sur
    // une connexion où l'on a parlé 1.1 ne répond pas à notre question.
    let reste = ligne
        .strip_prefix(b"HTTP/1.1 ")
        .or_else(|| ligne.strip_prefix(b"HTTP/1.0 "))
        .ok_or(Error::MalformedPath)?;
    let chiffres = reste.get(..3).ok_or(Error::MalformedPath)?;
    // Ce qui suit le code est une raison libre, précédée d'une espace — ou rien.
    match reste.get(3) {
        None => {}
        Some(b' ') => {}
        Some(_) => return Err(Error::MalformedPath),
    }
    let mut code = 0_u16;
    for chiffre in chiffres {
        if !chiffre.is_ascii_digit() {
            return Err(Error::MalformedPath);
        }
        code = code
            .saturating_mul(10)
            .saturating_add(u16::from(chiffre.saturating_sub(b'0')));
    }
    // `new` refuse hors de `100..=599` : un code à trois chiffres qui n'est
    // pas un code d'état n'est pas une réponse.
    StatusCode::new(code)
}

/// Découpe `nom: valeur`.
fn champ(ligne: &[u8]) -> Result<(&[u8], &[u8]), Error> {
    let rang = ligne
        .iter()
        .position(|octet| *octet == b':')
        .ok_or(Error::MalformedFieldName)?;
    let nom = ligne.get(..rang).unwrap_or_default();
    // **PAS D'ESPACE AVANT LE DEUX-POINTS** (§5.1 de RFC 9112) : `Foo : bar` se
    // lit `Foo ` chez les uns et `Foo` chez les autres, et c'est ainsi qu'on
    // fait diverger deux lecteurs sur un même message.
    //
    // Un seul contrôle suffit, et il dit davantage : un nom de champ est de
    // l'ASCII GRAPHIQUE, ce qui exclut l'espace et la tabulation PARTOUT, pas
    // seulement à la fin. Un second contrôle sur le dernier octet ne serait
    // qu'une garde que rien ne pourrait atteindre.
    if nom.is_empty() || !nom.iter().all(u8::is_ascii_graphic) {
        return Err(Error::MalformedFieldName);
    }
    let valeur = ligne.get(rang.saturating_add(1)..).unwrap_or_default();
    let valeur = rogner(valeur);
    if !valeur
        .iter()
        .all(|octet| octet.is_ascii_graphic() || matches!(octet, b' ' | b'\t'))
    {
        return Err(Error::MalformedFieldValue);
    }
    Ok((nom, valeur))
}

/// Où la tête finit, ligne vide comprise.
///
/// `Ok(None)` quand elle n'est pas encore entière.
fn fin_de_tete(octets: &[u8], max_head: usize) -> Result<Option<usize>, Error> {
    for (rang, fenetre) in octets.windows(4).enumerate() {
        if fenetre == b"\r\n\r\n" {
            return Ok(Some(rang.saturating_add(4)));
        }
    }
    // **UNE TÊTE QUI NE FINIT PAS EST UNE TÊTE QU'ON REFUSE**, et non un tampon
    // qu'on agrandit : un pair qui n'enverrait jamais de ligne vide ferait
    // croître la mémoire d'un client qui l'attend (C3).
    if octets.len() >= max_head {
        return Err(Error::FieldTooLong);
    }
    Ok(None)
}

/// Où `aiguille` commence dans `botte`.
fn trouver(botte: &[u8], aiguille: &[u8]) -> Option<usize> {
    botte
        .windows(aiguille.len())
        .position(|fenetre| fenetre == aiguille)
}

/// La valeur, sans ses blancs de tête et de queue.
fn rogner(valeur: &[u8]) -> &[u8] {
    let debut = valeur
        .iter()
        .position(|octet| !matches!(octet, b' ' | b'\t'))
        .unwrap_or(valeur.len());
    let apres = valeur
        .iter()
        .rposition(|octet| !matches!(octet, b' ' | b'\t'))
        .map_or(debut, |rang| rang.saturating_add(1));
    valeur.get(debut..apres.max(debut)).unwrap_or_default()
}

/// Un nombre décimal, sans signe ni blanc.
fn nombre(octets: &[u8]) -> Option<u64> {
    if octets.is_empty() {
        return None;
    }
    let mut valeur = 0_u64;
    for chiffre in octets {
        if !chiffre.is_ascii_digit() {
            return None;
        }
        valeur = valeur
            .checked_mul(10)?
            .checked_add(u64::from(chiffre.saturating_sub(b'0')))?;
    }
    Some(valeur)
}

/// Deux tranches d'ASCII, comparées sans égard à la casse.
fn egal_sans_casse(gauche: &[u8], droite: &[u8]) -> bool {
    gauche.len() == droite.len()
        && gauche
            .iter()
            .zip(droite)
            .all(|(un, autre)| un.eq_ignore_ascii_case(autre))
}

#[cfg(test)]
mod tests;
