// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! **Cible : le côté ÉMETTEUR de SMTP** — ce qu'un serveur nous répond, et ce
//! que nous lui écrivons.
//!
//! # Deux surfaces, et la première est nouvelle dans ce dépôt
//!
//! Jusqu'ici, tout venait à ce serveur. Émettre inverse la relation : **le
//! serveur auquel on remet est désigné par le destinataire**, c'est-à-dire par
//! quiconque publie un `MX`. Ses réponses sont donc une entrée hostile, et la
//! session cliente qui les lit décide de ce qu'on fait du message.
//!
//! La seconde surface est le corps qu'on émet, et le point-farcissage qui
//! l'empêche de se terminer tout seul.
//!
//! # Les propriétés
//!
//! 1. **Rien ne panique**, quels que soient les octets.
//! 2. **Une réponse délimitée se relit** : si `reply_len` rend une longueur,
//!    `Reply::parse` accepte exactement ces octets-là — et la longueur ne
//!    dépasse jamais ce qui a été fourni.
//! 3. **`Done` EST TERMINAL** : une session qui a conclu ne repart pas. Sans
//!    cela, un pair bavard pourrait faire remettre deux fois le même message.
//! 4. **UN CORPS FARCI NE PEUT PAS SE TERMINER TOUT SEUL** : la seule ligne au
//!    point est celle qu'on écrit à la fin. C'est la contrebande SMTP, et c'est
//!    la propriété qui compte le plus ici.
//! 5. **Le farcissage ne dépend pas du découpage** : couper le corps en deux
//!    n'importe où donne exactement le même résultat.
//! 6. **AUCUNE COMMANDE ÉCRITE NE PORTE DE FIN DE LIGNE PRÉMATURÉE** : ce qu'on
//!    met sur le fil est UNE ligne, close par un seul `CRLF` final.
//! 7. **CE QU'ON RETIENT D'UN REFUS EST RENDABLE** : de l'ASCII imprimable, sans
//!    fin de ligne, et borné. C'est ce qui protège le rapport que nous
//!    composerons ensuite.
//!
//! # LA SEPTIÈME GARDE UN DOCUMENT QUE NOUS SIGNONS
//!
//! Le texte d'un refus vient d'un serveur qu'on n'a pas choisi — c'est le
//! destinataire qui a désigné son `MX` — et il ressort dans le `Diagnostic-Code`
//! d'un rapport que NOUS composons, que NOUS remettons, et que le client de
//! notre utilisateur lira comme un document officiel. Un `CRLF` glissé dedans y
//! écrirait un champ de statut à notre place.
//!
//! `Reply::parse` laisse d'ailleurs passer les octets HAUTS — des serveurs
//! mettent des accents dans leur bannière —, que le composeur de rapport refuse.
//! Sans filtre, un pair qui refuse en français ferait échouer la composition
//! ENTIÈRE du rapport, et le déposant n'apprendrait alors plus rien.
//!
//! # LA SIXIÈME PROPRIÉTÉ EST NOUVELLE, ET ELLE VISE LE DÉPOSANT
//!
//! Depuis RFC 3461, ce que le déposant a demandé du sort de son message — son
//! `ENVID`, son `ORCPT` — repart dans NOS commandes vers le saut suivant. Ce
//! sont des valeurs qu'il choisit, et un `CRLF` glissé dedans écrirait des
//! commandes à notre place sur notre propre connexion sortante : le déposant
//! commanderait en notre nom le serveur de quelqu'un d'autre.
//!
//! Elles sont donc soumises HOSTILES ici. Deux défenses les portent —
//! `SmtpClient::new` refuse ce qui n'est pas de l'ASCII visible, et
//! `encode_xtext` échappe ce que §4 réserve —, et la propriété ne sait pas
//! laquelle a joué : elle ne regarde que le fil.

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use ams_proto_smtp::{Limits, Reply, Stuffer, reply_len, stuffed_max};
use ams_session::{
    CLIENT_COMMAND_MAX, ClientConfig, ClientDsn, ClientReport, ClientStep, SmtpClient,
};

/// Ce qu'on soumet.
#[derive(Arbitrary, Debug)]
struct Entree<'a> {
    /// Ce que le serveur d'en face répond, bout à bout.
    reponses: &'a [u8],
    /// Le corps du message à émettre.
    corps: &'a [u8],
    /// Où le couper, pour éprouver l'indépendance au découpage.
    coupure: u16,
    /// Exige-t-on le chiffrement ?
    exige_tls: bool,
    /// L'identifiant d'enveloppe du déposant (RFC 3461 §4.4). **VIENT DE LUI.**
    envid: &'a [u8],
    /// Ce que le premier destinataire avait demandé (§4.1, §4.2).
    premier: Demande<'a>,
    /// Ce que le second avait demandé — les deux peuvent différer.
    second: Demande<'a>,
}

/// Ce qu'un destinataire demande du sort de son message.
#[derive(Arbitrary, Debug)]
struct Demande<'a> {
    never: bool,
    on_success: bool,
    /// L'adresse d'origine, telle que le déposant l'a écrite. **VIENT DE LUI.**
    original: &'a [u8],
}

impl<'a> Demande<'a> {
    fn en_rapport(&self) -> ClientReport<'a> {
        ClientReport {
            never: self.never,
            on_success: self.on_success,
            original: self.original,
        }
    }
}

/// PROPRIÉTÉ 6 : ce qu'on vient d'écrire est UNE ligne, et une seule.
///
/// Un `CR` ou un `LF` ailleurs qu'à la toute fin ouvrirait une commande de plus
/// sur notre propre connexion sortante.
fn une_seule_ligne(ecrit: &[u8]) {
    if ecrit.is_empty() {
        return;
    }
    assert!(
        ecrit.ends_with(b"\r\n"),
        "une commande qui ne se termine pas : {:?}",
        String::from_utf8_lossy(ecrit)
    );
    let corps = &ecrit[..ecrit.len() - 2];
    assert!(
        !corps.contains(&b'\r') && !corps.contains(&b'\n'),
        "une fin de ligne PRÉMATURÉE : {:?}",
        String::from_utf8_lossy(ecrit)
    );
}

fuzz_target!(|entree: Entree<'_>| {
    // ── La session cliente, nourrie de ce qu'on lui répond ──────────────────
    let destinataires: &[&[u8]] = &[b"marie@eux.test", b"jean@eux.test"];
    let rapports = [entree.premier.en_rapport(), entree.second.en_rapport()];
    // **UNE CONFIGURATION REFUSÉE N'EST PAS UN ÉCHEC DE LA CIBLE** : c'est la
    // première des deux défenses qui a joué, et il n'y a plus rien à éprouver.
    let Ok(mut client) = SmtpClient::new(ClientConfig {
        name: b"mail.nous.test",
        sender: b"",
        recipients: destinataires,
        require_tls: entree.exige_tls,
        dsn: Some(ClientDsn {
            envelope_id: entree.envid,
            reports: &rapports,
        }),
    }) else {
        return;
    };

    let mut reste = entree.reponses;
    let mut conclu = false;
    let mut sortie = [0_u8; CLIENT_COMMAND_MAX];
    while let Ok(Some(longueur)) = reply_len(reste, &Limits::DEFAULT) {
        // PROPRIÉTÉ 2 : la longueur ne dépasse pas ce qu'on a fourni, et le bloc
        // qu'elle délimite se relit.
        assert!(longueur <= reste.len());
        let bloc = &reste[..longueur];
        let reponse = Reply::parse(bloc, &Limits::DEFAULT)
            .expect("un bloc délimité par `reply_len` doit se relire");
        // Toutes les lignes portent le même code : c'est ce qui interdit à un
        // bloc de se lire différemment selon l'implémentation.
        for ligne in bloc.split(|octet| *octet == b'\n') {
            if ligne.len() >= 3 {
                assert_eq!(
                    &ligne[..3],
                    reponse.code().value().to_string().as_bytes(),
                    "deux codes dans un même bloc"
                );
            }
        }

        let Ok(geste) = client.on_reply(&reponse, &mut sortie) else {
            break;
        };
        // PROPRIÉTÉ 6 : ce qui part sur le fil est UNE ligne.
        match geste {
            ClientStep::Send(n) | ClientStep::Done { sent: n, .. } => {
                une_seule_ligne(sortie.get(..n).unwrap_or_default());
            }
            ClientStep::Secure | ClientStep::SendBody => {}
        }
        if let ClientStep::Done { .. } = geste {
            conclu = true;
            // PROPRIÉTÉ 3 : `Done` est terminal. Une session qui repartirait
            // pourrait faire remettre deux fois le même message.
            assert!(
                client.on_reply(&reponse, &mut sortie).is_err(),
                "une session conclue a répondu de nouveau"
            );
            break;
        }
        if let ClientStep::Secure = geste {
            // Après le chiffrement, on se represente — et pas avant.
            assert!(client.on_reply(&reponse, &mut sortie).is_err());
            if let Ok(ClientStep::Send(n)) = client.on_secured(&mut sortie) {
                une_seule_ligne(sortie.get(..n).unwrap_or_default());
            }
        }
        reste = &reste[longueur..];
    }
    let _ = conclu;

    // ── 7. CE QU'ON RETIENT D'UN REFUS EST RENDABLE ─────────────────────────
    //
    // La règle est celle du composeur de rapport : de l'ASCII imprimable, et
    // l'espace. Un octet de plus, et c'est le rapport entier qui ne se compose
    // pas — donc un expéditeur qui n'apprend rien.
    let dit = client.diagnostic();
    assert!(
        dit.iter()
            .all(|octet| octet.is_ascii_graphic() || *octet == b' '),
        "un octet que le rapport ne saura pas écrire : {dit:?}"
    );
    assert!(
        dit.len() <= ams_session::DIAGNOSTIC_MAX,
        "{} octets retenus",
        dit.len()
    );
    // **L'ÉTAT RETENU S'ACCORDE TOUJOURS AVEC LE CODE** (§3.2 de RFC 3463) : un
    // `550 4.x.x` ferait réessayer cinq jours ce qu'un pair a refusé pour de
    // bon. La propriété ne s'exprime qu'ici, parce que c'est ici qu'on a les
    // deux.
    if let Some(statut) = client.peer_status() {
        assert!(
            matches!(statut.class(), 2 | 4 | 5),
            "un état hors des trois classes de §3"
        );
    }

    // ── Le corps qu'on émet ─────────────────────────────────────────────────
    let mut entier = vec![0_u8; stuffed_max(entree.corps.len())];
    let mut plume = Stuffer::new();
    let Ok(ecrits) = plume.push(entree.corps, &mut entier) else {
        return;
    };
    let Ok(fin) = plume.finish(&mut entier[ecrits..]) else {
        return;
    };
    entier.truncate(ecrits + fin);

    // PROPRIÉTÉ 4 : LA SEULE LIGNE AU POINT EST LA DERNIÈRE.
    let terminaisons = entier
        .windows(5)
        .filter(|fenetre| *fenetre == b"\r\n.\r\n")
        .count();
    let commence_par_le_point = entier.starts_with(b".\r\n");
    assert!(
        terminaisons + usize::from(commence_par_le_point) == 1,
        "le corps farci porte {terminaisons} terminaison(s) : il peut se terminer tout seul"
    );
    assert!(entier.ends_with(b".\r\n"));

    // PROPRIÉTÉ 5 : le découpage ne change rien.
    let coupure = usize::from(entree.coupure).min(entree.corps.len());
    let (avant, apres) = entree.corps.split_at(coupure);
    let mut morcele = vec![0_u8; stuffed_max(entree.corps.len())];
    let mut plume = Stuffer::new();
    let un = plume.push(avant, &mut morcele).expect("le tampon suffit");
    let deux = plume
        .push(apres, &mut morcele[un..])
        .expect("le tampon suffit");
    let trois = plume
        .finish(&mut morcele[un + deux..])
        .expect("le tampon suffit");
    morcele.truncate(un + deux + trois);
    assert_eq!(morcele, entier, "le découpage a changé le résultat");
});
