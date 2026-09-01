//! Le décodage d'une réponse.

use crate::name::{self, Name};
use crate::{Error, KIND_OPT};

/// La taille de l'en-tête (RFC 1035 §4.1.1).
const HEADER: usize = 12;

/// Le bit `AD` des drapeaux (RFC 4035 §3.2.3).
const AUTHENTIC: u16 = 0x0020;

/// Ce que le serveur a répondu (RFC 1035 §4.1.1, code `RCODE`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// Le nom existe, et voici ce qu'on en sait.
    NoError,
    /// Le nom **n'existe pas**. C'est une réponse, pas une panne : SPF la compte
    /// comme une résolution vide (RFC 7208 §4.6.4).
    NameError,
    /// Le serveur n'a pas pu répondre. C'est une panne, et SPF veut alors
    /// `temperror` — jamais un refus.
    ServerFailure,
    /// Tout le reste : question mal formée, refus, code inconnu.
    ///
    /// On ne les distingue pas, parce que la décision est la même : ce n'est pas
    /// une réponse, et l'inventer serait pire.
    Other(u8),
}

impl Status {
    fn depuis(code: u8) -> Self {
        match code {
            0 => Self::NoError,
            3 => Self::NameError,
            2 => Self::ServerFailure,
            autre => Self::Other(autre),
        }
    }
}

/// Une réponse DNS décodée.
///
/// # Elle est validée D'UN SEUL TENANT
///
/// [`Message::parse`] marche **toutes** les sections avant de rendre le premier
/// enregistrement. Un décodeur qui s'arrêterait au premier enregistrement utile
/// laisserait passer un message dont la queue est absurde — et un pair qui sait
/// ce qu'on lit d'abord choisirait ce qu'on ne lit pas.
#[derive(Debug, Clone, Copy)]
pub struct Message<'a> {
    octets: &'a [u8],
    /// Où commence la section des réponses, et combien elle en porte.
    reponses: usize,
    combien: u16,
    /// Le résolveur dit-il avoir VALIDÉ cette réponse (bit `AD`) ?
    authentifiee: bool,
}

impl<'a> Message<'a> {
    /// Décode une réponse.
    ///
    /// # Errors
    ///
    /// [`Error::NotAResponse`] si le bit `QR` manque, et les erreurs de
    /// structure : troncature, octet réservé, pointeur qui ne recule pas.
    pub fn parse(octets: &'a [u8]) -> Result<Self, Error> {
        let drapeaux = lire_u16(octets, 2).ok_or(Error::Truncated)?;
        if drapeaux & 0x8000 == 0 {
            return Err(Error::NotAResponse);
        }
        let questions = lire_u16(octets, 4).ok_or(Error::Truncated)?;
        let reponses = lire_u16(octets, 6).ok_or(Error::Truncated)?;
        let autorites = lire_u16(octets, 8).ok_or(Error::Truncated)?;
        let additionnels = lire_u16(octets, 10).ok_or(Error::Truncated)?;

        // ── Les questions ───────────────────────────────────────────────────
        let mut position = HEADER;
        for _ in 0..questions {
            position = name::sauter(octets, position)?;
            // Type et classe.
            position = position.saturating_add(4);
            if position > octets.len() {
                return Err(Error::Truncated);
            }
        }
        let debut_reponses = position;

        // ── Les trois sections d'enregistrements ────────────────────────────
        let total = u32::from(reponses)
            .saturating_add(u32::from(autorites))
            .saturating_add(u32::from(additionnels));
        for _ in 0..total {
            let (_, fin) = lire_enregistrement(octets, position).ok_or(Error::Truncated)?;
            position = fin;
        }

        Ok(Self {
            octets,
            reponses: debut_reponses,
            combien: reponses,
            // Le bit `AD` (RFC 4035 §3.2.3), tel que le résolveur l'a posé.
            authentifiee: drapeaux & AUTHENTIC != 0,
        })
    }

    /// Le résolveur dit-il avoir VALIDÉ cette réponse ?
    ///
    /// # CE QUE CE BIT VAUT, ET CE QU'IL NE VAUT PAS
    ///
    /// Il vaut ce que vaut le chemin jusqu'au résolveur, et **rien de plus**.
    /// C'est un résolveur valideur qui le pose, et n'importe qui sur le trajet
    /// peut le poser aussi. Il n'a donc de sens que pour un résolveur local, ou
    /// joint par un lien qu'on maîtrise — exactement l'hypothèse que ce projet
    /// fait déjà pour SPF, et qui est écrite partout.
    ///
    /// **Ce n'est pas une validation DNSSEC**, et cette crate n'en fait aucune :
    /// elle ne demande même pas les signatures (`DO` n'est pas posé). Ce qu'elle
    /// rend ici est ce que le résolveur A DIT, transporté sans être maquillé.
    ///
    /// Un résolveur qui ne valide pas ne pose jamais ce bit, et ce qui en dépend
    /// — DANE (RFC 7672) — cesse alors simplement de s'appliquer. C'est la bonne
    /// façon d'échouer : on retombe sur le chiffrement opportuniste, on ne
    /// prétend rien.
    #[must_use]
    pub fn authentic_data(&self) -> bool {
        self.authentifiee
    }

    /// L'identifiant, à confronter à celui de la question.
    ///
    /// **Le confronter n'est pas une politesse** : sans cela, n'importe quel
    /// datagramme arrivé sur le bon port passerait pour la réponse attendue.
    #[must_use]
    pub fn id(&self) -> u16 {
        lire_u16(self.octets, 0).unwrap_or(0)
    }

    /// La réponse a-t-elle été tronquée faute de place ?
    ///
    /// Elle se reprend alors en TCP (RFC 1035 §4.2.1) — et **ce qui est arrivé
    /// ne s'utilise pas** : une politique SPF coupée en deux se lirait comme une
    /// politique valide qui dit autre chose.
    #[must_use]
    pub fn truncated(&self) -> bool {
        lire_u16(self.octets, 2).unwrap_or(0) & 0x0200 != 0
    }

    /// Ce que le serveur a répondu.
    #[must_use]
    pub fn status(&self) -> Status {
        let drapeaux = lire_u16(self.octets, 2).unwrap_or(0);
        Status::depuis(u8::try_from(drapeaux & 0x000F).unwrap_or(0))
    }

    /// Les enregistrements de la section des réponses.
    ///
    /// Les sections d'autorité et d'additionnels ne sont **pas** rendues : elles
    /// portent ce que le serveur a jugé bon d'ajouter, et un client stub qui les
    /// croirait accepterait des données que personne n'a demandées.
    #[must_use]
    pub fn answers(&self) -> Records<'a> {
        Records {
            octets: self.octets,
            position: self.reponses,
            restants: self.combien,
        }
    }
}

fn lire_u16(octets: &[u8], position: usize) -> Option<u16> {
    octets
        .get(position..)?
        .first_chunk::<2>()
        .map(|paire| u16::from_be_bytes(*paire))
}

/// Les enregistrements d'une section.
///
/// L'itérateur est **infaillible** : `Message::parse` a déjà marché la section
/// entière, et ce qu'il n'a pas su lire n'est jamais arrivé jusqu'ici.
#[derive(Debug, Clone)]
pub struct Records<'a> {
    octets: &'a [u8],
    position: usize,
    restants: u16,
}

impl<'a> Iterator for Records<'a> {
    type Item = Record<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        self.restants = self.restants.checked_sub(1)?;
        let (enregistrement, fin) = lire_enregistrement(self.octets, self.position)?;
        self.position = fin;
        Some(enregistrement)
    }
}

/// Lit un enregistrement, et rend l'offset qui le suit.
///
/// La MÊME lecture sert à [`Message::parse`], qui marche les sections pour les
/// valider, et à [`Records`], qui les rend. Deux lectures d'un même format
/// finissent par diverger, et c'est la divergence qu'on ne verrait pas.
fn lire_enregistrement(octets: &[u8], position: usize) -> Option<(Record<'_>, usize)> {
    let apres_nom = name::sauter(octets, position).ok()?;
    let kind = lire_u16(octets, apres_nom)?;
    let class = lire_u16(octets, apres_nom.saturating_add(2))?;
    let longueur = lire_u16(octets, apres_nom.saturating_add(8))?;
    let donnees = apres_nom.saturating_add(10);
    let fin = donnees.saturating_add(usize::from(longueur));
    let rdata = octets.get(donnees..fin)?;
    Some((
        Record {
            message: octets,
            proprietaire: position,
            donnees,
            kind,
            class,
            rdata,
        },
        fin,
    ))
}

/// Un enregistrement de ressource.
#[derive(Debug, Clone, Copy)]
pub struct Record<'a> {
    message: &'a [u8],
    proprietaire: usize,
    donnees: usize,
    kind: u16,
    class: u16,
    rdata: &'a [u8],
}

impl<'a> Record<'a> {
    /// Le type — à confronter à celui qu'on a demandé.
    ///
    /// Une section de réponses porte ce que le résolveur a suivi : demander un
    /// `TXT` peut rendre des `CNAME`. **Filtrer sur le type n'est donc pas une
    /// précaution, c'est la lecture normale.**
    #[must_use]
    pub fn kind(&self) -> u16 {
        self.kind
    }

    /// La classe, qui doit être `IN`.
    #[must_use]
    pub fn class(&self) -> u16 {
        self.class
    }

    /// Est-ce l'`OPT` d'EDNS(0) ? Il n'est pas une donnée.
    #[must_use]
    pub fn is_opt(&self) -> bool {
        self.kind == KIND_OPT
    }

    /// Les octets bruts, tels qu'ils sont arrivés.
    #[must_use]
    pub fn rdata(&self) -> &'a [u8] {
        self.rdata
    }

    /// Le nom auquel l'enregistrement appartient.
    ///
    /// # Errors
    ///
    /// Les erreurs de nom : nom trop long, pointeur qui ne recule pas.
    pub fn owner(&self) -> Result<Name, Error> {
        name::lire(self.message, self.proprietaire).map(|(nom, _)| nom)
    }

    /// Les chaînes d'un `TXT`.
    ///
    /// **Un `TXT` n'est pas une chaîne, c'en est une SUITE** (RFC 1035 §3.3.14),
    /// chacune de 255 octets au plus. RFC 7208 §3.3 veut qu'on les concatène
    /// SANS séparateur pour lire une politique SPF : un enregistrement de 300
    /// octets arrive en deux morceaux, et les joindre par une espace en ferait
    /// une politique différente.
    #[must_use]
    pub fn strings(&self) -> Strings<'a> {
        Strings { reste: self.rdata }
    }

    /// L'adresse d'un `A` ou d'un `AAAA`.
    ///
    /// Rend `None` si la longueur ne correspond pas au type : un `A` de cinq
    /// octets n'est pas une adresse, et en fabriquer une serait décider à la
    /// place du serveur.
    /// La longueur est éprouvée DANS l'aiguillage, et c'est le sujet :
    /// `first_chunk` accepterait un `A` de huit octets en n'en lisant que
    /// quatre. Ce qui reste ne serait pas lu, et ce qui n'est pas lu dans un
    /// message qui vient d'ailleurs mérite un refus, pas une interprétation.
    #[must_use]
    pub fn address(&self) -> Option<core::net::IpAddr> {
        match (self.kind, self.rdata.len()) {
            (k, 4) if k == crate::Kind::A.code() => self
                .rdata
                .first_chunk::<4>()
                .map(|octets| core::net::IpAddr::V4(core::net::Ipv4Addr::from(*octets))),
            (k, 16) if k == crate::Kind::Aaaa.code() => self
                .rdata
                .first_chunk::<16>()
                .map(|octets| core::net::IpAddr::V6(core::net::Ipv6Addr::from(*octets))),
            _ => None,
        }
    }

    /// Le nom d'un `PTR` ou d'un `CNAME`.
    ///
    /// # Errors
    ///
    /// Les erreurs de nom.
    pub fn target(&self) -> Result<Name, Error> {
        name::lire(self.message, self.donnees).map(|(nom, _)| nom)
    }

    /// La préférence et le nom d'un `MX`.
    ///
    /// # Errors
    ///
    /// [`Error::Truncated`] si les deux octets de préférence manquent, et les
    /// erreurs de nom.
    pub fn exchange(&self) -> Result<(u16, Name), Error> {
        let preference = lire_u16(self.message, self.donnees).ok_or(Error::Truncated)?;
        let (nom, _) = name::lire(self.message, self.donnees.saturating_add(2))?;
        Ok((preference, nom))
    }
}

/// Les chaînes d'un `TXT`.
#[derive(Debug, Clone)]
pub struct Strings<'a> {
    reste: &'a [u8],
}

impl<'a> Iterator for Strings<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<Self::Item> {
        let (&longueur, suite) = self.reste.split_first()?;
        // UNE CHAÎNE QUI DÉBORDE ARRÊTE LA SUITE. Rendre ce qu'on a lu jusque-là
        // ferait passer une moitié de politique pour une politique.
        let (chaine, reste) = suite.split_at_checked(usize::from(longueur))?;
        self.reste = reste;
        Some(chaine)
    }
}

#[cfg(test)]
mod tests;
