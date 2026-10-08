// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! `air-mail-admin asl enroll <code>` : lier une clé neuve à cette machine.
//!
//! # CE QUE LE CODE EST, ET CE QU'IL N'EST PAS
//!
//! Un code court, affiché par l'application, **à usage unique et valable
//! quelques minutes**. Il n'ouvre qu'une opération — lier une clé —, et le
//! justificatif durable est la clé elle-même, que personne n'a jamais
//! transmise : elle est générée ICI, et sa moitié privée ne quitte pas ce
//! disque. Il n'y a **aucun secret partagé** à poser (contrainte C14 du dépôt
//! `air-service-locator`).
//!
//! # L'ORDRE DES REFUS N'EST PAS INDIFFÉRENT
//!
//! Le code se périme en quelques minutes. Tout ce qui peut se refuser **sans
//! réseau** se refuse donc AVANT d'ouvrir une connexion : la configuration, le
//! répertoire d'état, une fiche déjà présente, et la forme du code lui-même. Un
//! refus après l'aller-retour coûterait un retour dans l'application pour
//! demander un code neuf — et celui qu'on vient de griller ne vaut plus rien.
//!
//! # LE PROPRIÉTAIRE DU FICHIER VIENT DU RÉPERTOIRE
//!
//! La fiche porte la moitié privée de la clé. Elle doit être lisible par
//! l'utilisateur qui fait tourner le serveur, **et par lui seul**. Lancée en
//! `root` — ce qui est le cas ordinaire sur un MX —, cette commande écrirait
//! sinon un fichier que le serveur ne pourrait pas lire : il refuserait de
//! s'annoncer, et rien d'évident ne le dirait. C'est exactement le piège qui a
//! déjà donné un `535` muet sur le magasin de mots de passe applicatifs.
//!
//! **Le fichier appartient donc à qui possède le répertoire où il vit** (choix
//! de Thierry, 2026-10-08). Le répertoire doit exister avant — créé en 0700 au
//! nom du serveur, comme les quatre autres magasins le sont par le
//! déploiement —, et cette commande refuse plutôt que de le créer : elle
//! devrait alors inventer un propriétaire, et c'est précisément ce qu'on
//! cherche à ne pas faire.

use std::os::unix::fs::MetadataExt as _;
use std::path::Path;
use std::process::ExitCode;

use ams_quic_dial::Appel;

/// Combien d'octets d'entropie une identité de machine demande.
const GRAINE_OCTETS: usize = ams_asl::GRAINE_OCTETS;

/// Combien de temps on laisse à un annuaire pour répondre, en tout.
///
/// **CE N'EST PAS LE DÉLAI D'UNE REQUÊTE** : `ams-quic-dial` en a déjà un par
/// poignée de main et par réponse. Celui-ci borne la TOURNÉE — l'ensemble des
/// annuaires essayés — pour qu'une commande lancée à la main rende la main,
/// même si les deux racines se taisent.
const TOURNEE_MS: u128 = 30_000;

/// Lie une clé neuve à cette machine, auprès d'un annuaire.
pub fn enroler(config: &Path, code: &str) -> ExitCode {
    match enroler_ou_dire(config, code) {
        Ok(dit) => {
            println!("{dit}");
            ExitCode::SUCCESS
        }
        Err(quoi) => {
            eprintln!("air-mail-admin : {quoi}");
            ExitCode::FAILURE
        }
    }
}

/// Ce que l'enrôlement fait, ou la raison pour laquelle il ne l'a pas fait.
fn enroler_ou_dire(config: &Path, code: &str) -> Result<String, String> {
    // ── 1. CE QUI SE REFUSE SANS RÉSEAU, D'ABORD ────────────────────────────
    let octets = std::fs::read(config)
        .map_err(|erreur| format!("configuration `{}` : {erreur}", config.display()))?;
    let configuration = ams_config::decode(&octets)
        .map_err(|erreur| format!("configuration `{}` : {erreur}", config.display()))?;

    if configuration.asl.state.is_empty() {
        return Err(format!(
            "`{}` ne dit pas où vit l'identité de cette machine. Posez-la :\n    \
             air-mail-admin config write {} … --asl-state /var/lib/air-mail/asl",
            config.display(),
            config.display()
        ));
    }
    let etat = Path::new(&configuration.asl.state);

    // **LE RÉPERTOIRE DOIT EXISTER, ET C'EST LUI QUI DIT LE PROPRIÉTAIRE.**
    let details = std::fs::metadata(etat).map_err(|erreur| {
        format!(
            "répertoire d'état `{}` : {erreur}\n\
             Créez-le au nom de l'utilisateur qui fait tourner le serveur — c'est \
             de LUI que la fiche héritera :\n    \
             install -d -m 0700 -o air-mail -g air-mail {}",
            etat.display(),
            etat.display()
        )
    })?;
    if !details.is_dir() {
        return Err(format!("`{}` n'est pas un répertoire", etat.display()));
    }

    let fiche = etat.join(ams_asl::fiche::NOM_DU_FICHIER);
    if fiche.exists() {
        return Err(format!(
            "`{}` existe déjà — cette machine est enrôlée, et réenrôler jetterait \
             la clé que l'annuaire connaît : ses services disparaîtraient de \
             l'annuaire sans que personne ne l'ait demandé. Écartez cette fiche \
             vous-même si vous voulez vraiment en lier une neuve.",
            fiche.display()
        ));
    }

    // **LA FORME DU CODE SE JUGE AVANT DE L'EMPLOYER.** Un code mal recopié
    // refusé par l'annuaire coûterait l'aller-retour, et le code est périssable.
    asl_cle::CodeEnrolement::analyser(code)
        .map_err(|_| format!("`{code}` n'est pas un code d'enrôlement"))?;

    let cibles = cibles(&configuration.asl.directories)?;

    // ── 2. LA CLÉ, TIRÉE DU NOYAU ───────────────────────────────────────────
    //
    // **ELLE EST GÉNÉRÉE ICI, ET SA MOITIÉ PRIVÉE NE SORTIRA PAS.** L'annuaire
    // ne connaîtra que la moitié publique.
    let graine = du_noyau::<GRAINE_OCTETS>()?;
    let enrolement = asl_client::Enrolement::nouveau(graine);

    // ── 3. LA TOURNÉE ───────────────────────────────────────────────────────
    let executeur = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|erreur| format!("l'exécuteur ne se monte pas : {erreur}"))?;

    let depart = std::time::Instant::now();
    let mut refus = Vec::new();
    for (adresse, identite) in &cibles {
        if depart.elapsed().as_millis() >= TOURNEE_MS {
            refus.push(String::from("le temps imparti à la tournée est écoulé"));
            break;
        }
        match executeur.block_on(demander(*adresse, *identite, &enrolement, code)) {
            Ok(enrolee) => {
                let identite = enrolement
                    .nommee(enrolee.0)
                    .map_err(|_| String::from("l'annuaire n'a pas nommé une machine"))?;
                poser_la_fiche(&fiche, &details, identite.machine(), enrolee.1, &graine)?;
                return Ok(dire(&fiche, identite.machine(), enrolee.1, *adresse));
            }
            // **ON ESSAIE LE SUIVANT, ET ON GARDE LA RAISON.** Une racine muette
            // ne doit pas faire échouer un enrôlement que l'autre servirait ;
            // mais si les deux refusent, l'exploitant a droit aux deux raisons.
            Err(quoi) => refus.push(format!("{adresse} : {quoi}")),
        }
    }

    Err(format!(
        "aucun annuaire n'a enrôlé cette machine. Ce que chacun a dit :\n    {}",
        refus.join("\n    ")
    ))
}

/// Demande l'enrôlement à CET annuaire.
///
/// Rend la machine, et le compte quand l'annuaire le nomme.
async fn demander(
    adresse: std::net::SocketAddr,
    identite: asl_id::Identifiant,
    enrolement: &asl_client::Enrolement,
    code: &str,
) -> Result<(asl_id::Identifiant, Option<asl_id::Identifiant>), String> {
    let confiance = ams_tls::asl_config(&[identite])
        .map_err(|erreur| format!("la confiance ne se monte pas : {erreur}"))?;

    // **L'ALÉA VIENT DU NOYAU** : §5.2 de RFC 9001 dérive les clés `Initial` de
    // l'identifiant de connexion, et un identifiant devinable les rendrait
    // devinables. Une fermeture, parce que `ouvrir` en veut une partageable.
    let alea = || du_noyau::<16>().unwrap_or([0; 16]);

    // **L'`:authority` EST L'IDENTITÉ ATTENDUE, ET ELLE NE PROUVE RIEN.** C'est
    // un en-tête, non une règle de confiance : ce qui est jugé est le
    // certificat. Y mettre le `n-…` donne simplement un nom lisible à ce qu'on
    // vise, là où ASL interdit de résoudre un nom.
    let autorite = identite.texte();
    let mut appel = Appel::ouvrir(
        adresse,
        ams_tls::nom_de_serveur(adresse),
        autorite.as_str(),
        confiance,
        &alea,
    )
    .await
    .map_err(|quoi| format!("{quoi}"))?;

    // **LA LIAISON DE CANAL LIE LA PREUVE À CETTE CONNEXION-CI** (RFC 8446
    // §7.5). Sans elle, une preuve captée ailleurs vaudrait ici.
    let liaison = asl_cle::LiaisonDeCanal::depuis_octets(
        appel
            .exporter(asl_client::ETIQUETTE_LIAISON, None)
            .map_err(|quoi| format!("{quoi}"))?,
    );

    let defi = appel
        .requete("GET", "/v1/defi", &[], &[])
        .await
        .map_err(|quoi| format!("défi : {quoi}"))?;
    if defi.statut.value() != 200 {
        return Err(format!("défi : l'annuaire répond {}", defi.statut.value()));
    }
    // **LA LONGUEUR EXACTE, ET NON « AU MOINS »** : un défi plus court complété
    // de zéros serait un défi plus faible que ce que son nom promet.
    let defi: [u8; asl_cle::DEFI_OCTETS] = defi
        .corps
        .try_into()
        .map_err(|_| String::from("défi : la longueur n'est pas celle attendue"))?;

    let corps = enrolement
        .corps(code, &asl_cle::Defi::depuis_octets(defi), &liaison)
        .map_err(|_| String::from("le code ne se compose pas"))?;

    let reponse = appel
        .requete(
            "POST",
            "/v1/enrolement",
            &[(b"content-type", b"application/octet-stream")],
            &corps,
        )
        .await
        .map_err(|quoi| format!("enrôlement : {quoi}"))?;

    // La fermeture est annoncée : l'annuaire distingue un départ d'une coupure.
    let _ = appel.fermer().await;

    match reponse.statut.value() {
        200 => lire_l_enrolee(&reponse.corps),
        // **LE SENS DES DEUX REFUS SE DIT**, parce qu'ils ne se corrigent pas
        // de la même façon : l'un demande un code neuf, l'autre un autre code.
        403 => Err(String::from(
            "l'annuaire refuse ce code : il a déjà servi, ou il est périmé \
             (quelques minutes). Demandez-en un neuf dans l'application.",
        )),
        404 => Err(String::from(
            "l'annuaire ne connaît pas ce code : vérifiez ce que l'application affiche",
        )),
        autre => Err(format!("l'annuaire répond {autre}")),
    }
}

/// Lit `{"machine":"m-…","proprietaire":"u-…"}`.
///
/// **LE COMPTE EST FACULTATIF**, et son absence n'est pas une faute : un
/// annuaire d'avant 0.3.0 ne le rend pas, et `GET /v1/moi` l'apprendra.
fn lire_l_enrolee(
    corps: &[u8],
) -> Result<(asl_id::Identifiant, Option<asl_id::Identifiant>), String> {
    let mut lecteur = ams_api::Reader::new(corps);
    let mut machine = None;
    let mut proprietaire = None;
    let mut attendu: Option<&'static str> = None;

    while let Ok(Some(evenement)) = lecteur.read() {
        match evenement {
            ams_api::Event::Key(clef) => {
                attendu = match clef.as_plain() {
                    Some("machine") => Some("machine"),
                    Some("proprietaire") => Some("proprietaire"),
                    _ => None,
                };
            }
            ams_api::Event::Text(texte) => {
                if let (Some(champ), Some(lu)) = (attendu, texte.as_plain()) {
                    let identifiant = asl_id::Identifiant::analyser(lu).ok();
                    if champ == "machine" {
                        machine = identifiant;
                    } else {
                        proprietaire = identifiant;
                    }
                }
                attendu = None;
            }
            _ => attendu = None,
        }
    }

    machine
        .map(|machine| (machine, proprietaire))
        .ok_or_else(|| String::from("la réponse de l'annuaire ne nomme aucune machine"))
}

/// Les annuaires à essayer, dans l'ordre.
///
/// **VIDE PREND LES RACINES EMBARQUÉES**, et aucun nom n'est résolu : leurs
/// adresses et leurs identités vivent dans la bibliothèque, et ASL fonctionne
/// sans DNS (C20). Un locateur qui n'est pas une adresse littérale est donc
/// sauté — c'est un nom, et nous n'en résolvons pas.
fn cibles(declares: &[String]) -> Result<Vec<(std::net::SocketAddr, asl_id::Identifiant)>, String> {
    if declares.is_empty() {
        let mut cibles = Vec::new();
        for racine in &asl_racines::RACINES {
            let Some(identite) = racine.identite() else {
                continue;
            };
            for locateur in racine.locateurs {
                if let Ok(adresse) = locateur.parse() {
                    cibles.push((adresse, identite));
                }
            }
        }
        if cibles.is_empty() {
            return Err(String::from(
                "aucune racine embarquée n'a d'adresse littérale : cette version \
                 du binaire ne sait joindre aucun annuaire",
            ));
        }
        return Ok(cibles);
    }

    let mut cibles = Vec::new();
    for declare in declares {
        let (hote, identite) = declare.split_once('=').ok_or_else(|| {
            format!(
                "`{declare}` ne dit pas d'identité : la forme est `hôte:port=n-…`, et \
                 l'identité est la SEULE chose qui soit jugée — un `hôte:port` seul \
                 ne serait cru par rien"
            )
        })?;
        let adresse = hote
            .parse()
            .map_err(|_| format!("`{hote}` n'est pas une adresse : ASL ne résout aucun nom"))?;
        let identite = asl_id::Identifiant::analyser_genre(asl_id::Genre::Annuaire, identite)
            .map_err(|_| format!("`{identite}` n'est pas l'identifiant d'un annuaire"))?;
        cibles.push((adresse, identite));
    }
    Ok(cibles)
}

/// Écrit la fiche, et la donne au propriétaire du répertoire.
fn poser_la_fiche(
    fiche: &Path,
    repertoire: &std::fs::Metadata,
    machine: asl_id::Identifiant,
    compte: Option<asl_id::Identifiant>,
    graine: &[u8; GRAINE_OCTETS],
) -> Result<(), String> {
    let mut place = [0_u8; ams_asl::FICHE_OCTETS_MAX];
    let combien = ams_asl::ecrire_une_fiche(machine, compte, graine, &mut place)
        .map_err(|quoi| format!("la fiche ne s'écrit pas : {quoi}"))?;

    // `ams_fichier::poser` écrit en 0600, par renommage atomique.
    ams_fichier::poser(fiche, place.get(..combien).unwrap_or_default())
        .map_err(|erreur| format!("`{}` : {erreur}", fiche.display()))?;

    // **ET ELLE CHANGE DE MAIN.** Voir l'en-tête de ce module : lancée en root,
    // cette commande écrirait sinon un fichier que le serveur ne pourrait pas
    // lire. Le propriétaire est celui du répertoire, qui a été posé par le
    // déploiement.
    donner(fiche, repertoire.uid(), repertoire.gid())
}

/// `chown`, et la raison de son échec quand il échoue.
///
/// **UN ÉCHEC N'EST PAS FATAL SI RIEN NE CHANGE** : lancée par l'utilisateur du
/// serveur lui-même, la fiche lui appartient déjà, et `chown` vers son propre
/// compte réussit. Lancée par un tiers qui n'est ni root ni le propriétaire, il
/// échoue — et il faut le dire, parce que le serveur ne lira pas ce fichier.
fn donner(fiche: &Path, uid: u32, gid: u32) -> Result<(), String> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt as _;

    let chemin = CString::new(fiche.as_os_str().as_bytes())
        .map_err(|_| format!("`{}` porte un octet nul", fiche.display()))?;
    // SAFETY : `chown` lit un chemin terminé par un nul — celui que `CString`
    // garantit — et deux entiers. Il ne touche à aucune mémoire que nous
    // possédons, et son échec se lit dans son code de retour.
    if unsafe { libc::chown(chemin.as_ptr(), uid, gid) } != 0 {
        let erreur = std::io::Error::last_os_error();
        return Err(format!(
            "`{}` est écrite, mais elle n'a pas pu changer de main ({erreur}). \
             LE SERVEUR NE POURRA PAS LA LIRE tant qu'elle ne lui appartient pas :\n    \
             chown {uid}:{gid} {}",
            fiche.display(),
            fiche.display()
        ));
    }
    Ok(())
}

/// Tire `N` octets du noyau.
fn du_noyau<const N: usize>() -> Result<[u8; N], String> {
    use std::io::Read as _;
    let mut octets = [0_u8; N];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut source| source.read_exact(&mut octets))
        .map_err(|erreur| format!("/dev/urandom : {erreur}"))?;
    Ok(octets)
}

/// Ce qu'on dit à qui vient d'enrôler sa machine.
fn dire(
    fiche: &Path,
    machine: asl_id::Identifiant,
    compte: Option<asl_id::Identifiant>,
    annuaire: std::net::SocketAddr,
) -> String {
    let mut dit = format!(
        "cette machine est {} — enrôlée par l'annuaire {annuaire}\n\
         sa clé vit dans `{}`, en 0600 : ne la copiez pas sur une autre machine, \
         enrôlez-la, c'est gratuit",
        machine.texte().as_str(),
        fiche.display()
    );
    match compte {
        Some(compte) => {
            dit.push_str(&format!(
                "\nelle agit pour le compte {}",
                compte.texte().as_str()
            ));
        }
        None => dit.push_str(
            "\nl'annuaire n'a pas nommé le compte : ce n'est pas une faute, il le \
             rendra à la première connexion",
        ),
    }
    dit.push_str(
        "\n\nRIEN N'EST ENCORE ANNONCÉ. Déclarez ce que les clients doivent joindre :\n    \
         air-mail-admin config write … --asl-announce air-mail-imaps=tcp:993",
    );
    dit
}
