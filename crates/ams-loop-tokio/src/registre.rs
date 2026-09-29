//! Ce que la boucle apporte au registre de réception (0.2.44) : ce qu'elle
//! seule sait — le DNS tel qu'il répond, l'heure, l'identifiant de session.
//!
//! # LA QUALITÉ D'ABORD, LA VITESSE ENSUITE
//!
//! La résolution inverse part dès l'acceptation, en parallèle de la
//! conversation, et elle est **attendue** avant d'écrire un message au
//! registre : chaque message porte le DNS tel qu'il répondait. Un pair dont le
//! DNS est lent attend un peu plus son `250` ; c'est le prix d'un registre qui
//! ne dit pas « inconnu » là où il aurait pu savoir.
//!
//! Les enregistrements eux-mêmes, et leur écriture, vivent ailleurs : les
//! types dans `ams-config`, le fichier dans le serveur. La boucle ne connaît
//! aucun fichier.

use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};

use ams_config::registre::{Inverse, Salut, StatutDns, StatutSalut, borne_octets};
use ams_dns::{Kind, Message};

use crate::resolver::{Issue, Resolver};

/// Combien de noms `PTR` on confirme au plus : chacun coûte deux questions.
const NOMS_CONFIRMES_MAX: usize = 4;

/// L'heure, en millisecondes depuis l'époque.
pub(crate) fn maintenant_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |ecoule| {
            u64::try_from(ecoule.as_millis()).unwrap_or(u64::MAX)
        })
}

/// Un identifiant de session : l'heure d'ouverture en millisecondes, puis un
/// compteur propre au processus. Deux sessions ouvertes à la même
/// milliseconde diffèrent par le compteur ; deux processus successifs, par
/// l'heure.
pub(crate) fn identifiant(ouverte: u64) -> [u8; 16] {
    static COMPTEUR: AtomicU64 = AtomicU64::new(0);
    let rang = COMPTEUR.fetch_add(1, Ordering::Relaxed);
    let mut id = [0_u8; 16];
    id[..8].copy_from_slice(&ouverte.to_be_bytes());
    id[8..].copy_from_slice(&rang.to_be_bytes());
    id
}

/// Les adresses d'un nom, et si la résolution a échoué.
async fn adresses(resolveur: &Resolver, nom: &[u8]) -> (Vec<IpAddr>, bool) {
    let mut trouvees = Vec::new();
    let mut panne = false;
    for genre in [Kind::A, Kind::Aaaa] {
        let octets = match resolveur.interroger(nom, genre).await {
            Issue::Reponse(octets) => octets,
            Issue::Absent => continue,
            Issue::Panne => {
                panne = true;
                continue;
            }
        };
        let Ok(message) = Message::parse(&octets) else {
            panne = true;
            continue;
        };
        trouvees.extend(
            message
                .answers()
                .filter(|enregistrement| enregistrement.kind() == genre.code())
                .filter_map(|enregistrement| enregistrement.address()),
        );
    }
    (trouvees, panne)
}

/// La résolution inverse de l'adresse du pair, et sa confirmation.
pub(crate) async fn inverse(resolveur: &Resolver, adresse: IpAddr) -> Inverse {
    let octets = match resolveur
        .interroger(crate::spf::nom_inverse(adresse).as_bytes(), Kind::Ptr)
        .await
    {
        Issue::Reponse(octets) => octets,
        Issue::Absent => {
            return Inverse {
                statut: StatutDns::Absent,
                ..Inverse::default()
            };
        }
        Issue::Panne => {
            return Inverse {
                statut: StatutDns::Panne,
                ..Inverse::default()
            };
        }
    };
    let Ok(message) = Message::parse(&octets) else {
        return Inverse {
            statut: StatutDns::Panne,
            ..Inverse::default()
        };
    };
    let mut noms = Vec::new();
    let mut ttl = u32::MAX;
    for enregistrement in message
        .answers()
        .filter(|enregistrement| enregistrement.kind() == Kind::Ptr.code())
    {
        if let Ok(nom) = enregistrement.target() {
            noms.push(borne_octets(nom.as_bytes()).0);
            ttl = ttl.min(enregistrement.ttl());
        }
    }
    if noms.is_empty() {
        return Inverse {
            statut: StatutDns::Absent,
            authentifiee: message.authentic_data(),
            ..Inverse::default()
        };
    }
    // **FCrDNS** : un `PTR` se déclare par le propriétaire de l'ADRESSE ; il
    // ne vaut que si le nom qu'il désigne revient vers elle — c'est le
    // propriétaire du NOM qui le confirme.
    let mut confirmee = false;
    for nom in noms.iter().take(NOMS_CONFIRMES_MAX) {
        if adresses(resolveur, nom.as_bytes())
            .await
            .0
            .contains(&adresse)
        {
            confirmee = true;
            break;
        }
    }
    Inverse {
        statut: StatutDns::Trouve,
        noms,
        ttl,
        authentifiee: message.authentic_data(),
        confirmee,
    }
}

/// Ce que vaut le nom annoncé au `HELO` ou à l'`EHLO`.
pub(crate) async fn salut(resolveur: Option<&Resolver>, annonce: &[u8], pair: IpAddr) -> Salut {
    let nom = borne_octets(annonce).0;
    if annonce.first() == Some(&b'[') {
        return Salut {
            nom,
            statut: StatutSalut::Litteral,
            adresses: Vec::new(),
        };
    }
    let Some(resolveur) = resolveur else {
        return Salut {
            nom,
            ..Salut::default()
        };
    };
    let (adresses, panne) = adresses(resolveur, annonce).await;
    let statut = if adresses.contains(&pair) {
        StatutSalut::PointeLePair
    } else if !adresses.is_empty() {
        StatutSalut::PointeAilleurs
    } else if panne {
        StatutSalut::Panne
    } else {
        StatutSalut::NeResoutPas
    };
    Salut {
        nom,
        statut,
        adresses,
    }
}

#[cfg(test)]
mod tests {
    use super::{identifiant, maintenant_ms};

    #[test]
    fn deux_sessions_ont_deux_identifiants() {
        let quand = maintenant_ms();
        assert!(quand > 1_700_000_000_000);
        let un = identifiant(quand);
        let deux = identifiant(quand);
        assert_ne!(un, deux);
        assert_eq!(un[..8], quand.to_be_bytes());
    }
}
