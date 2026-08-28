//! Ce qu'une commande SMTP acceptée doit tenir, quelles que soient les bornes.

use ams_proto_smtp::{ClientId, Command, Limits, Parameters, Path};

/// Vérifie tout ce que `Command::parse` a promis en rendant `Ok`.
pub fn verifier(ligne: &[u8], commande: &Command<'_>, limits: &Limits) {
    // 1. LA LIGNE EST BORNÉE, ET SE TERMINE PROPREMENT.
    assert!(ligne.len() <= limits.max_command_octets, "ligne hors borne");
    assert!(ligne.ends_with(b"\r\n"), "ligne acceptée sans CRLF final");

    // 2. AUCUN CR NI LF ISOLÉ N'A SURVÉCU.
    //
    // La propriété qui ferme la contrebande SMTP : un octet de fin de ligne
    // ambigu qui passerait laisserait le serveur suivant voir DEUX commandes là
    // où celui-ci n'en a vu qu'une.
    let contenu = ligne.strip_suffix(b"\r\n").unwrap_or_default();
    assert!(
        !contenu.contains(&b'\r') && !contenu.contains(&b'\n'),
        "fin de ligne isolée acceptée : {contenu:?}"
    );

    match commande {
        // 3. LES DEUX CÔTÉS DE L'ENVELOPPE N'ADMETTENT PAS LA MÊME CHOSE.
        //
        // `<>` ne peut venir que d'un `MAIL`, `<Postmaster>` que d'un `RCPT`.
        // Les confondre ferait accepter un message qui ne va nulle part, ou un
        // avis de non-remise qui en provoquerait un autre.
        Command::Mail {
            reverse_path,
            parameters,
        } => {
            assert_ne!(
                *reverse_path,
                Path::Postmaster,
                "`<Postmaster>` accepté en expéditeur"
            );
            verifier_chemin(reverse_path, limits);
            verifier_parametres(parameters, limits);
        }
        Command::Rcpt {
            forward_path,
            parameters,
        } => {
            assert_ne!(*forward_path, Path::Null, "`<>` accepté en destinataire");
            verifier_chemin(forward_path, limits);
            verifier_parametres(parameters, limits);
        }
        Command::Ehlo(id) => verifier_identite(id, limits),
        Command::Helo(domaine) => {
            assert!(!domaine.is_empty(), "domaine `HELO` vide");
            assert!(
                domaine.len() <= limits.max_domain_octets,
                "domaine hors borne"
            );
            // 4. `HELO` N'ADMET PAS DE LITTÉRAL D'ADRESSE (RFC 5321 §4.1.1.1).
            assert!(
                !domaine.starts_with(b"["),
                "littéral d'adresse accepté en `HELO` : {domaine:?}"
            );
        }
        Command::Auth {
            mechanism,
            initial_response,
        } => {
            // 5. LE MÉCANISME SASL EST CONFORME (RFC 4422 §3.1).
            assert!(
                (1..=20).contains(&mechanism.len()),
                "mécanisme de longueur {} accepté",
                mechanism.len()
            );
            assert!(
                mechanism.iter().all(|&b| b.is_ascii_uppercase()
                    || b.is_ascii_digit()
                    || b == b'-'
                    || b == b'_'),
                "mécanisme hors alphabet : {mechanism:?}"
            );
            if let Some(reponse) = initial_response {
                assert!(!reponse.is_empty(), "réponse initiale vide acceptée");
            }
        }
        _ => {}
    }
}

/// Un chemin accepté respecte ses bornes, et ne porte pas de route source.
fn verifier_chemin(chemin: &Path<'_>, limits: &Limits) {
    let Path::Mailbox(boite) = chemin else {
        return;
    };
    let locale = boite.local_part().as_bytes();
    assert!(!locale.is_empty(), "partie locale vide acceptée");
    assert!(
        locale.len() <= limits.max_local_part_octets,
        "partie locale hors borne"
    );
    // 6. UNE ROUTE SOURCE NE PASSE JAMAIS — elle commencerait par `@`.
    assert!(locale[0] != b'@', "route source acceptée : {locale:?}");
    verifier_identite(&boite.domain(), limits);
}

/// Un domaine accepté est non vide, borné, et distingué d'un littéral.
fn verifier_identite(id: &ClientId<'_>, limits: &Limits) {
    let octets = id.as_bytes();
    assert!(!octets.is_empty(), "domaine vide accepté");
    assert!(
        octets.len() <= limits.max_domain_octets,
        "domaine hors borne"
    );
    match id {
        // 7. LA DISTINCTION DOMAINE / LITTÉRAL TIENT AUX OCTETS.
        ClientId::AddressLiteral(brut) => {
            assert!(
                brut.starts_with(b"[") && brut.ends_with(b"]"),
                "littéral sans crochets : {brut:?}"
            );
        }
        ClientId::Domain(brut) => {
            assert!(
                !brut.starts_with(b"["),
                "domaine qui ressemble à un littéral : {brut:?}"
            );
            assert!(!brut.contains(&b'@'), "domaine portant un `@` : {brut:?}");
        }
    }
}

/// Les paramètres acceptés sont bornés en nombre, et bien formés.
fn verifier_parametres(parametres: &Parameters<'_>, limits: &Limits) {
    let mut vus = 0_usize;
    for parametre in *parametres {
        vus = vus.saturating_add(1);
        let mot_cle = parametre.keyword();
        assert!(!mot_cle.is_empty(), "mot-clé vide accepté");
        assert!(
            mot_cle[0].is_ascii_alphanumeric(),
            "mot-clé qui ne commence pas par une lettre ou un chiffre : {mot_cle:?}"
        );
        // 8. UNE VALEUR PRÉSENTE N'EST JAMAIS VIDE, ET NE PORTE PAS DE `=`.
        //
        // Un `=` de plus scinderait le paramètre autrement selon l'implémentation.
        if let Some(valeur) = parametre.value() {
            assert!(!valeur.is_empty(), "valeur vide acceptée : {mot_cle:?}");
            assert!(
                !valeur.contains(&b'=') && !valeur.contains(&b' '),
                "valeur hors alphabet : {valeur:?}"
            );
        }
    }
    assert!(
        vus <= limits.max_parameters,
        "plus de paramètres que la borne"
    );
}
