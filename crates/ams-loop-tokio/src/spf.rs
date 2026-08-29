//! La résolution des questions que SPF pose (C9).
//!
//! # C'est ICI que le DNS est parlé, et nulle part ailleurs
//!
//! `ams-spf` conduit l'évaluation sans résoudre quoi que ce soit : il rend des
//! **questions**. Ce module y répond, et c'est tout ce qu'il fait — il ne décide
//! d'aucun verdict, il n'écrit aucune réponse SMTP. Le partage est celui de C1 :
//! ce qui attend vit à l'étage 3, ce qui décide vit à l'étage 2.
//!
//! # Ce qu'une question recouvre, et pourquoi c'est ici que ça se déplie
//!
//! `MxAddresses` veut « les adresses des serveurs de courrier de ce domaine » :
//! une résolution `MX`, puis une résolution d'adresses par serveur rendu. La RFC
//! 7208 §4.6.4 compte tout cela comme **une seule** des dix résolutions, et
//! borne séparément ce qui se déplie : **dix enregistrements `MX` au plus, dix
//! noms au plus** pour une résolution inverse. Ces deux bornes-là sont tenues
//! ici, parce que c'est ici qu'on sait combien de messages sont partis.
//!
//! # Le transport, lui, vit ailleurs
//!
//! Poser une question et attendre une réponse est le travail de
//! [`crate::Resolver`], que DKIM emprunte aussi : c'est le même fil, le même
//! délai, la même défense contre qui voudrait répondre à notre place. Deux
//! copies de ce transport finiraient par diverger, et la première qui
//! divergerait serait celle qu'on ne relit plus.

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use ams_dns::{Kind, Message, Name};
use ams_session::SenderIdentity;
use ams_spf::{Answer, Context, Evaluator, Limits, Query, Step, Verdict};

use crate::resolver::{Issue, Resolver, Txt};

/// Le nombre d'enregistrements `MX` qu'on déplie (RFC 7208 §4.6.4).
const MX_MAX: usize = 10;

/// Le nombre de noms qu'on retient d'une résolution inverse (§4.6.4).
const PTR_MAX: usize = 10;

/// De quoi répondre aux questions de SPF.
#[derive(Clone, Debug)]
pub struct SenderChecker {
    resolveur: Resolver,
}

impl SenderChecker {
    /// Prépare un vérificateur.
    ///
    /// # Errors
    ///
    /// Si la liste de résolveurs est vide, ou si `/dev/urandom` ne s'ouvre pas.
    /// **On ne se rabat sur rien** : un identifiant prévisible est une faiblesse
    /// silencieuse, et refuser de démarrer la rend visible.
    pub fn new(serveurs: Vec<SocketAddr>, delai: Duration) -> io::Result<Self> {
        Ok(Self {
            resolveur: Resolver::new(serveurs, delai)?,
        })
    }

    /// Le résolveur, que DKIM emprunte pour ses propres questions.
    #[must_use]
    pub fn resolver(&self) -> &Resolver {
        &self.resolveur
    }

    /// Conduit une évaluation SPF jusqu'à son verdict.
    ///
    /// Ne rend jamais d'erreur : une résolution qui échoue vaut
    /// [`Verdict::TempError`], et c'est la session qui décide ce qu'elle en
    /// fait.
    pub async fn verdict(&self, client: IpAddr, identite: &SenderIdentity<'_>) -> Verdict {
        let contexte = Context {
            client,
            sender: identite.sender,
            helo: identite.helo,
        };
        let mut evaluateur = Evaluator::new(contexte, identite.domain, Limits::DEFAULT);
        loop {
            let question = match evaluateur.poll() {
                Step::Done(verdict) => return verdict,
                Step::Ask(question) => question,
            };
            let reponse = self
                .repondre(question.kind(), question.name(), client)
                .await;
            match &reponse {
                Reponse::Txt(textes) => {
                    let empruntes: Vec<&[u8]> = textes.iter().map(Vec::as_slice).collect();
                    evaluateur.answer(Answer::Txt(&empruntes));
                }
                Reponse::Adresses(adresses) => evaluateur.answer(Answer::Addresses(adresses)),
                Reponse::Noms(noms) => {
                    let empruntes: Vec<&[u8]> = noms.iter().map(Vec::as_slice).collect();
                    evaluateur.answer(Answer::Names(&empruntes));
                }
                Reponse::Existe(trouve) => evaluateur.answer(Answer::Exists(*trouve)),
                Reponse::Absent => evaluateur.answer(Answer::NotFound),
                Reponse::Panne => evaluateur.answer(Answer::TempError),
            }
        }
    }

    /// Répond à une question, en autant de résolutions qu'il faut.
    async fn repondre(&self, genre: Query, nom: &[u8], client: IpAddr) -> Reponse {
        match genre {
            Query::Txt => self.textes(nom).await,
            Query::Addresses => self.adresses(nom).await,
            Query::MxAddresses => self.adresses_des_mx(nom).await,
            Query::Exists => self.existe(nom).await,
            Query::PtrNames => self.noms_confirmes(client).await,
        }
    }

    /// Les `TXT` d'un nom, chaînes recollées par le résolveur.
    async fn textes(&self, nom: &[u8]) -> Reponse {
        match self.resolveur.txt(nom).await {
            Txt::Trouves(textes) => Reponse::Txt(textes),
            Txt::Absent => Reponse::Absent,
            Txt::Panne => Reponse::Panne,
        }
    }

    /// Les adresses d'un nom, dans les deux familles.
    ///
    /// `A` **et** `AAAA` : un pair qui arrive en IPv6 ne correspondrait à rien
    /// si l'on n'interrogeait que les `A`, et la RFC 7208 §5.3 veut les deux.
    async fn adresses(&self, nom: &[u8]) -> Reponse {
        let mut adresses = Vec::new();
        let mut panne = false;
        let mut absent = 0_u8;
        for kind in [Kind::A, Kind::Aaaa] {
            match self.resolveur.interroger(nom, kind).await {
                Issue::Reponse(octets) => match Message::parse(&octets) {
                    Ok(message) => adresses.extend(
                        message
                            .answers()
                            .filter(|enregistrement| enregistrement.kind() == kind.code())
                            .filter_map(|enregistrement| enregistrement.address()),
                    ),
                    Err(_) => panne = true,
                },
                Issue::Absent => absent = absent.saturating_add(1),
                Issue::Panne => panne = true,
            }
        }
        if !adresses.is_empty() {
            return Reponse::Adresses(adresses);
        }
        // AUCUNE ADRESSE, ET UNE PANNE : on ne conclut pas. Dire « ce nom n'a
        // pas d'adresse » alors qu'on n'a pas su demander ferait échouer un
        // mécanisme qui aurait correspondu.
        if panne {
            return Reponse::Panne;
        }
        Reponse::Absent
    }

    /// Les adresses des serveurs de courrier d'un nom.
    async fn adresses_des_mx(&self, nom: &[u8]) -> Reponse {
        let octets = match self.resolveur.interroger(nom, Kind::Mx).await {
            Issue::Reponse(octets) => octets,
            Issue::Absent => return Reponse::Absent,
            Issue::Panne => return Reponse::Panne,
        };
        let Ok(message) = Message::parse(&octets) else {
            return Reponse::Panne;
        };
        let echanges: Vec<Name> = message
            .answers()
            .filter(|enregistrement| enregistrement.kind() == Kind::Mx.code())
            .filter_map(|enregistrement| enregistrement.exchange().ok())
            .map(|(_, nom)| nom)
            // DIX AU PLUS (RFC 7208 §4.6.4) : sans cette borne, une zone
            // hostile publie mille `MX` et fait faire mille résolutions.
            .take(MX_MAX)
            .collect();
        if echanges.is_empty() {
            return Reponse::Absent;
        }
        let mut adresses = Vec::new();
        let mut panne = false;
        for echange in echanges {
            match self.adresses(echange.as_bytes()).await {
                Reponse::Adresses(trouvees) => adresses.extend(trouvees),
                Reponse::Panne => panne = true,
                _ => {}
            }
        }
        if adresses.is_empty() && panne {
            return Reponse::Panne;
        }
        Reponse::Adresses(adresses)
    }

    /// Ce nom existe-t-il ? (RFC 7208 §5.7 : c'est l'existence qui répond.)
    async fn existe(&self, nom: &[u8]) -> Reponse {
        match self.resolveur.interroger(nom, Kind::A).await {
            Issue::Reponse(octets) => match Message::parse(&octets) {
                Ok(message) => Reponse::Existe(
                    message
                        .answers()
                        .any(|enregistrement| enregistrement.kind() == Kind::A.code()),
                ),
                Err(_) => Reponse::Panne,
            },
            Issue::Absent => Reponse::Existe(false),
            Issue::Panne => Reponse::Panne,
        }
    }

    /// Les noms que la résolution inverse **confirme** (RFC 7208 §5.5).
    ///
    /// Un `PTR` ne prouve rien : il est publié par qui détient le bloc
    /// d'adresses, et il peut nommer n'importe quoi. La RFC exige donc de
    /// **revérifier en avant** — le nom rendu doit résoudre vers l'adresse du
    /// pair. Sans cela, qui contrôle une zone inverse se ferait passer pour
    /// n'importe quel domaine.
    async fn noms_confirmes(&self, client: IpAddr) -> Reponse {
        let inverse = nom_inverse(client);
        let octets = match self
            .resolveur
            .interroger(inverse.as_bytes(), Kind::Ptr)
            .await
        {
            Issue::Reponse(octets) => octets,
            Issue::Absent => return Reponse::Absent,
            Issue::Panne => return Reponse::Panne,
        };
        let Ok(message) = Message::parse(&octets) else {
            return Reponse::Panne;
        };
        let candidats: Vec<Name> = message
            .answers()
            .filter(|enregistrement| enregistrement.kind() == Kind::Ptr.code())
            .filter_map(|enregistrement| enregistrement.target().ok())
            .take(PTR_MAX)
            .collect();

        let mut confirmes = Vec::new();
        for candidat in candidats {
            if let Reponse::Adresses(adresses) = self.adresses(candidat.as_bytes()).await
                && adresses.contains(&client)
            {
                confirmes.push(candidat.as_bytes().to_vec());
            }
        }
        if confirmes.is_empty() {
            return Reponse::Absent;
        }
        Reponse::Noms(confirmes)
    }
}

/// Ce qu'on a fini par savoir, sous une forme que l'évaluateur emprunte.
enum Reponse {
    Txt(Vec<Vec<u8>>),
    Adresses(Vec<IpAddr>),
    Noms(Vec<Vec<u8>>),
    Existe(bool),
    Absent,
    Panne,
}

/// Le nom de la résolution inverse d'une adresse (RFC 1035 §3.5, RFC 3596 §2.5).
fn nom_inverse(client: IpAddr) -> String {
    match client {
        IpAddr::V4(adresse) => {
            let [a, b, c, d] = adresse.octets();
            format!("{d}.{c}.{b}.{a}.in-addr.arpa")
        }
        IpAddr::V6(adresse) => {
            let mut nom = String::with_capacity(72);
            for octet in adresse.octets().iter().rev() {
                nom.push(quartet(octet & 0x0F));
                nom.push('.');
                nom.push(quartet(octet >> 4));
                nom.push('.');
            }
            nom.push_str("ip6.arpa");
            nom
        }
    }
}

fn quartet(valeur: u8) -> char {
    char::from_digit(u32::from(valeur), 16).unwrap_or('0')
}

#[cfg(test)]
mod tests;
