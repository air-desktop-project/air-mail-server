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

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use ams_proto_smtp::{Limits, Reply, Stuffer, reply_len, stuffed_max};
use ams_session::{CLIENT_COMMAND_MAX, ClientConfig, ClientStep, SmtpClient};

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
}

fuzz_target!(|entree: Entree<'_>| {
    // ── La session cliente, nourrie de ce qu'on lui répond ──────────────────
    let destinataires: &[&[u8]] = &[b"marie@eux.test", b"jean@eux.test"];
    let mut client = SmtpClient::new(ClientConfig {
        name: b"mail.nous.test",
        sender: b"",
        recipients: destinataires,
        require_tls: entree.exige_tls,
    })
    .expect("cette configuration-là est toujours acceptable");

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
            let _ = client.on_secured(&mut sortie);
        }
        reste = &reste[longueur..];
    }
    let _ = conclu;

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
