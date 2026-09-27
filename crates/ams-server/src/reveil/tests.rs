//! Ce que le réveil décide, et à qui il l'envoie.

use std::string::String;
use std::sync::{Arc, Mutex};
use std::vec::Vec;

use super::{
    Bilan, Carnet, DESTINATIONS_MAX, Destination, Envoi, Envoyeur, INTERVALLE, Reveil, Sources,
    demarrer, destinations,
};

fn vers(qui: &str, boite: &str) -> Destination {
    Destination {
        destinataire: String::from(qui),
        compte: String::from(boite),
    }
}

/// **LE PREMIER SIGNAL RÉVEILLE TOUT DE SUITE**, les suivants attendent la fin
/// de l'intervalle, et n'en font qu'un.
#[test]
fn une_rafale_ne_fait_que_deux_reveils() {
    let mut carnet = Carnet::new();
    carnet.signaler(vers("marie", "marie"), 1_000);
    assert_eq!(carnet.a_reveiller(1_000), [vers("marie", "marie")]);
    assert_eq!(carnet.prochain(), None, "rien n'attend encore");
    for seconde in 1..10 {
        carnet.signaler(vers("marie", "marie"), 1_000 + seconde);
        assert!(carnet.a_reveiller(1_000 + seconde).is_empty());
    }
    assert_eq!(carnet.prochain(), Some(1_000 + INTERVALLE));
    assert!(carnet.a_reveiller(1_000 + INTERVALLE - 1).is_empty());
    assert_eq!(
        carnet.a_reveiller(1_000 + INTERVALLE),
        [vers("marie", "marie")]
    );
    assert_eq!(carnet.prochain(), None);
    // Ce réveil-là rouvre un intervalle : un signal juste après attend.
    carnet.signaler(vers("marie", "marie"), 1_000 + INTERVALLE + 1);
    assert!(carnet.a_reveiller(1_000 + INTERVALLE + 1).is_empty());
    assert_eq!(carnet.prochain(), Some(1_000 + 2 * INTERVALLE));
    // Longtemps après, un signal réveille de nouveau tout de suite.
    let tard = 10_000;
    assert_eq!(carnet.a_reveiller(tard), [vers("marie", "marie")]);
    carnet.signaler(vers("marie", "marie"), tard + 1_000);
    assert_eq!(carnet.a_reveiller(tard + 1_000), [vers("marie", "marie")]);
}

/// Deux destinations ne s'attendent pas l'une l'autre, et deux signaux au même
/// instant ne font qu'un réveil.
#[test]
fn deux_destinations_sont_independantes() {
    let mut carnet = Carnet::new();
    carnet.signaler(vers("marie", "marie"), 5);
    carnet.signaler(vers("paul", "marie"), 5);
    carnet.signaler(vers("paul", "support"), 5);
    let mut prets = carnet.a_reveiller(5);
    prets.sort();
    assert_eq!(
        prets,
        [
            vers("marie", "marie"),
            vers("paul", "marie"),
            vers("paul", "support")
        ]
    );
    assert_eq!(carnet.suivies(), 3);
}

/// **LA MÉMOIRE EST BORNÉE** : au plein, ce qui n'attend plus rien s'oublie —
/// et oublier ne perd aucun réveil.
#[test]
fn le_carnet_oublie_ce_qui_n_attend_rien() {
    let mut carnet = Carnet::new();
    for rang in 0..DESTINATIONS_MAX {
        carnet.signaler(vers(&std::format!("c{rang}"), "x"), 0);
    }
    assert_eq!(carnet.a_reveiller(0).len(), DESTINATIONS_MAX);
    // Les intervalles sont passés : tout s'oublie au signal suivant.
    carnet.signaler(vers("neuf", "x"), INTERVALLE + 1);
    assert_eq!(carnet.suivies(), 1);
    // Plein d'entrées encore dans leur intervalle : la plus ancienne cède.
    let mut carnet = Carnet::new();
    for rang in 0..DESTINATIONS_MAX {
        let rang_u64 = u64::try_from(rang).expect("petit");
        carnet.signaler(vers(&std::format!("c{rang}"), "x"), rang_u64 / 100);
    }
    let _ = carnet.a_reveiller(0);
    carnet.signaler(vers("neuf", "x"), 1);
    assert_eq!(carnet.suivies(), DESTINATIONS_MAX);
    // Plein d'entrées qui ATTENDENT un réveil : on n'en perd aucune.
    let mut carnet = Carnet::new();
    for rang in 0..DESTINATIONS_MAX {
        carnet.signaler(vers(&std::format!("c{rang}"), "x"), 0);
    }
    let _ = carnet.a_reveiller(0);
    for rang in 0..DESTINATIONS_MAX {
        carnet.signaler(vers(&std::format!("c{rang}"), "x"), 1);
    }
    carnet.signaler(vers("neuf", "x"), 2);
    assert_eq!(carnet.suivies(), DESTINATIONS_MAX + 1);
    assert_eq!(carnet.a_reveiller(INTERVALLE).len(), DESTINATIONS_MAX + 1);
}

/// **LE TITULAIRE, ET QUI PEUT LIRE SA BOÎTE.**
#[test]
fn le_titulaire_et_ses_lecteurs_se_reveillent() {
    let atelier = std::env::temp_dir().join(std::format!("ams-reveil-{}", std::process::id()));
    let table = crate::delegations::Delegations::new(
        atelier.join("delegations.bin"),
        std::vec![
            ams_config::Delegation {
                delegate: String::from("paul"),
                owner: String::from("support"),
                rights: ams_config::Rights::READ,
            },
            ams_config::Delegation {
                delegate: String::from("anne"),
                owner: String::from("support"),
                rights: ams_config::Rights::SEND,
            },
            ams_config::Delegation {
                delegate: String::from("marie"),
                owner: String::from("autre"),
                rights: ams_config::Rights::WRITE,
            },
        ],
    );
    let mut toutes = destinations("support", Some(&table));
    toutes.sort();
    assert_eq!(
        toutes,
        [
            vers("anne", "support"),
            vers("paul", "support"),
            vers("support", "support")
        ]
    );
    assert_eq!(destinations("seul", None), [vers("seul", "seul")]);
}

/// Un envoyeur qui retient ce qu'on lui confie.
#[derive(Default)]
struct Temoin {
    vus: Mutex<Vec<(String, String, &'static str)>>,
    rendu: Option<Envoi>,
}

impl Envoyeur for Temoin {
    fn envoyer<'a>(
        &'a self,
        appareil: &'a ams_config::Device,
        push: &'a ams_config::Push,
        compte: &'a str,
    ) -> super::EnvoiEnCours<'a> {
        self.vus.lock().expect("verrou").push((
            appareil.id.clone(),
            String::from(compte),
            push.channel().name(),
        ));
        Box::pin(core::future::ready(self.rendu.unwrap_or(Envoi::Transmis)))
    }
}

fn appareil(login: &str, id: &str, abonne: bool) -> ams_config::Device {
    const CLE: [u8; 65] = [
        0x04, 0x6B, 0x17, 0xD1, 0xF2, 0xE1, 0x2C, 0x42, 0x47, 0xF8, 0xBC, 0xE6, 0xE5, 0x63, 0xA4,
        0x40, 0xF2, 0x77, 0x03, 0x7D, 0x81, 0x2D, 0xEB, 0x33, 0xA0, 0xF4, 0xA1, 0x39, 0x45, 0xD8,
        0x98, 0xC2, 0x96, 0x4F, 0xE3, 0x42, 0xE2, 0xFE, 0x1A, 0x7F, 0x9B, 0x8E, 0xE7, 0xEB, 0x4A,
        0x7C, 0x0F, 0x9E, 0x16, 0x2B, 0xCE, 0x33, 0x57, 0x6B, 0x31, 0x5E, 0xCE, 0xCB, 0xB6, 0x40,
        0x68, 0x37, 0xBF, 0x51, 0xF5,
    ];
    ams_config::Device {
        login: String::from(login),
        id: String::from(id),
        name: String::new(),
        public_key: ams_auth::Cle::lire(&CLE).expect("le point générateur"),
        enrolled: 1,
        last_seen: 0,
        push: abonne.then(|| {
            ams_config::Push::new(
                ams_config::PushChannel::Apns,
                "ab".repeat(32),
                Vec::new(),
                Vec::new(),
                1,
            )
            .expect("recevable")
        }),
    }
}

/// Attend que le témoin ait vu `combien` envois, ou échoue au bout de cinq
/// secondes.
async fn attendre(temoin: &Temoin, combien: usize) -> Vec<(String, String, &'static str)> {
    for _ in 0..500 {
        let vus = temoin.vus.lock().expect("verrou").clone();
        if vus.len() >= combien {
            return vus;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    panic!("le témoin n'a pas vu {combien} envois");
}

/// **DE LA REMISE À L'ENVOI** : un signal réveille les appareils abonnés du
/// titulaire et de ses lecteurs — les autres non —, et chacun le compte.
#[tokio::test(flavor = "multi_thread")]
async fn un_signal_reveille_les_appareils_abonnes() {
    let atelier = std::env::temp_dir().join(std::format!("ams-reveil-bout-{}", std::process::id()));
    let appareils = Arc::new(crate::appareils::Appareils::new(
        atelier.join("appareils.bin"),
        std::vec![
            appareil("support", "s1", true),
            appareil("support", "s2", false),
            appareil("paul", "p1", true),
            appareil("autre", "a1", true),
        ],
    ));
    let delegations = Arc::new(crate::delegations::Delegations::new(
        atelier.join("delegations.bin"),
        std::vec![ams_config::Delegation {
            delegate: String::from("paul"),
            owner: String::from("support"),
            rights: ams_config::Rights::READ,
        }],
    ));
    let temoin = Arc::new(Temoin::default());
    let reveil = demarrer(Sources {
        appareils,
        delegations: Some(delegations),
        envoyeur: Arc::clone(&temoin) as Arc<dyn Envoyeur>,
    });
    reveil.signaler("support");
    let mut vus = attendre(&temoin, 2).await;
    vus.sort();
    assert_eq!(
        vus,
        [
            (String::from("p1"), String::from("support"), "apns"),
            (String::from("s1"), String::from("support"), "apns"),
        ]
    );
    let bilan = Bilan {
        prepares: 1,
        transmis: 1,
        echoues: 0,
    };
    assert_eq!(reveil.bilan("support"), bilan);
    assert_eq!(reveil.bilan("paul"), bilan);
    assert_eq!(reveil.bilan("autre"), Bilan::default());
    // Un compte retiré n'a plus de bilan.
    reveil.oublier("support");
    assert_eq!(reveil.bilan("support"), Bilan::default());
    assert_eq!(reveil.bilan("paul"), bilan);
}

/// Un échec se compte comme un échec.
#[tokio::test(flavor = "multi_thread")]
async fn un_echec_se_compte() {
    let atelier =
        std::env::temp_dir().join(std::format!("ams-reveil-echec-{}", std::process::id()));
    let temoin = Arc::new(Temoin {
        vus: Mutex::default(),
        rendu: Some(Envoi::Echec),
    });
    let reveil = demarrer(Sources {
        appareils: Arc::new(crate::appareils::Appareils::new(
            atelier.join("appareils.bin"),
            std::vec![appareil("marie", "m1", true)],
        )),
        delegations: None,
        envoyeur: Arc::clone(&temoin) as Arc<dyn Envoyeur>,
    });
    reveil.signaler("marie");
    let _ = attendre(&temoin, 1).await;
    assert_eq!(
        reveil.bilan("marie"),
        Bilan {
            prepares: 1,
            transmis: 0,
            echoues: 1
        }
    );
}

/// **FILE PLEINE, LE SIGNAL SE PERD SANS RIEN RETENIR** — et se compte.
#[tokio::test(flavor = "multi_thread")]
async fn une_file_pleine_perd_sans_bloquer() {
    let (emetteur, _recepteur) = tokio::sync::mpsc::channel(1);
    let reveil = Reveil {
        file: emetteur,
        bilans: Mutex::default(),
        perdus: std::sync::atomic::AtomicU64::new(0),
    };
    reveil.signaler("a");
    reveil.signaler("b");
    reveil.signaler("c");
    assert_eq!(reveil.perdus.load(std::sync::atomic::Ordering::Relaxed), 2);
}

/// Sans transport, un réveil se prépare et ne se transmet pas.
#[test]
fn sans_transport_rien_ne_part() {
    let push = ams_config::Push::new(
        ams_config::PushChannel::Fcm,
        String::from("t"),
        Vec::new(),
        Vec::new(),
        1,
    )
    .expect("recevable");
    let x1 = appareil("x", "x1", false);
    assert_eq!(
        pret(super::SansTransport.envoyer(&x1, &push, "x")),
        Envoi::NonTransmis
    );
}

/// Attend un futur déjà prêt, sans ordonnanceur.
fn pret(mut futur: super::EnvoiEnCours<'_>) -> Envoi {
    let mut contexte = core::task::Context::from_waker(core::task::Waker::noop());
    match futur.as_mut().poll(&mut contexte) {
        core::task::Poll::Ready(envoi) => envoi,
        core::task::Poll::Pending => panic!("un futur prêt ne se fait pas attendre"),
    }
}

/// **UN ABONNEMENT PÉRIMÉ SE RETIRE**, et se compte comme un échec.
#[tokio::test(flavor = "multi_thread")]
async fn un_abonnement_perime_se_retire() {
    let atelier =
        std::env::temp_dir().join(std::format!("ams-reveil-perime-{}", std::process::id()));
    std::fs::create_dir_all(&atelier).expect("répertoire");
    let appareils = Arc::new(crate::appareils::Appareils::new(
        atelier.join("appareils.bin"),
        std::vec![appareil("marie", "m1", true)],
    ));
    let temoin = Arc::new(Temoin {
        vus: Mutex::default(),
        rendu: Some(Envoi::Perime),
    });
    let reveil = demarrer(Sources {
        appareils: Arc::clone(&appareils),
        delegations: None,
        envoyeur: Arc::clone(&temoin) as Arc<dyn Envoyeur>,
    });
    reveil.signaler("marie");
    let _ = attendre(&temoin, 1).await;
    for _ in 0..500 {
        if appareils
            .du_compte("marie")
            .iter()
            .all(|fiche| fiche.push.is_none())
        {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert!(
        appareils
            .du_compte("marie")
            .iter()
            .all(|fiche| fiche.push.is_none())
    );
    assert_eq!(reveil.bilan("marie").echoues, 1);
    let _ = std::fs::remove_dir_all(&atelier);
}

/// **CHAQUE CANAL À SON ENVOYEUR**, et un canal sans envoyeur n'est pas
/// transmis.
#[test]
fn l_aiguillage_confie_chaque_canal_au_sien() {
    let web = Arc::new(Temoin {
        vus: Mutex::default(),
        rendu: Some(Envoi::Transmis),
    });
    let apple = Arc::new(Temoin {
        vus: Mutex::default(),
        rendu: Some(Envoi::Echec),
    });
    let aiguillage = super::Aiguillage {
        web_push: Some(Arc::clone(&web) as Arc<dyn Envoyeur>),
        apns: Some(Arc::clone(&apple) as Arc<dyn Envoyeur>),
        fcm: None,
    };
    let sous = |canal, jeton: &str, cle: Vec<u8>, auth: Vec<u8>| {
        ams_config::Push::new(canal, String::from(jeton), cle, auth, 1).expect("recevable")
    };
    let cle = ams_push::vapid_public_key(&[3; 32])
        .expect("une clef")
        .to_vec();
    let x = appareil("x", "x1", false);
    let web_push = sous(
        ams_config::PushChannel::WebPush,
        "https://p.example.com/a",
        cle,
        std::vec![1; 16],
    );
    let apns = sous(
        ams_config::PushChannel::Apns,
        &"ab".repeat(32),
        Vec::new(),
        Vec::new(),
    );
    let fcm = sous(
        ams_config::PushChannel::Fcm,
        "jeton",
        Vec::new(),
        Vec::new(),
    );
    assert_eq!(
        pret(aiguillage.envoyer(&x, &web_push, "x")),
        Envoi::Transmis
    );
    assert_eq!(pret(aiguillage.envoyer(&x, &apns, "x")), Envoi::Echec);
    assert_eq!(pret(aiguillage.envoyer(&x, &fcm, "x")), Envoi::NonTransmis);
    assert_eq!(web.vus.lock().expect("verrou").len(), 1);
    assert_eq!(apple.vus.lock().expect("verrou").len(), 1);
}
