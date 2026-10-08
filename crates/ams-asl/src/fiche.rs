// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! La fiche d'identité d'une machine : ce qu'elle porte, et ce qui s'en déduit.
//!
//! # CE FORMAT N'EST PAS LE NÔTRE, ET C'EST TOUT CE QUI COMPTE
//!
//! Il est celui qu'écrit `asl enroll`, et il vit chez l'utilisateur
//! (`~/.config/asl/identite`, ou le répertoire que `--state` nomme). Une
//! machine peut donc être enrôlée par l'utilitaire `asl` et servie par ce
//! serveur, ou l'inverse — **à condition que les deux lectures soient la
//! même**.
//!
//! Elles le sont, dans le détail, et chaque détail est là pour une raison que
//! quelqu'un a déjà rencontrée :
//!
//! - **les commentaires et les lignes vides sont sautés** ; la fiche en porte
//!   trois, qui disent de ne pas recopier la clé ailleurs ;
//! - **une ligne sans `=` est sautée**, et non refusée ;
//! - **la dernière occurrence gagne** — c'est ce que fait une boucle qui écrase
//!   —, et non la première ;
//! - **un `compte =` illisible est IGNORÉ, pas refusé.** Il ne sert qu'à
//!   l'affichage : la machine s'authentifie avec sa clé, et le compte lui est
//!   rendu par l'annuaire. Le refuser empêcherait de démarrer pour une ligne
//!   décorative.
//!
//! Une divergence sur l'un de ces points ferait que le même fichier voudrait
//! dire deux choses, et que la panne se verrait un jour, chez un seul des deux
//! programmes.
//!
//! # CE QUI N'EST PAS ICI, PARCE QUE C'EST UNE ENTRÉE-SORTIE
//!
//! **Le mode du fichier.** `asl` refuse de lire une fiche que le groupe ou les
//! autres peuvent lire — « une clé lisible par d'autres n'est plus une clé » —
//! et ce serveur doit refuser de même. Mais interroger un `stat` est une
//! entrée-sortie (C1) : le contrôle appartient à l'appelant, et il est nommé
//! ici pour qu'il ne s'oublie pas.
//!
//! # LA CLÉ EST DÉRIVÉE, JAMAIS STOCKÉE
//!
//! La fiche porte trente-deux octets d'entropie, et `asl-client` en dérive la
//! paire Ed25519. Y ranger aussi la clé dérivée ferait deux copies du même
//! secret, dont une que rien ne vérifie — et le jour où elles divergeraient,
//! c'est la mauvaise qu'on signerait avec.

use core::fmt::Write as _;

use asl_client::Identite;
use asl_id::{Genre, Identifiant};

use crate::{Ecrivain, Faute};

/// Le nom du fichier, sous le répertoire d'état.
///
/// **IL EST CELUI D'`asl`**, et il ne se choisit pas : les deux programmes
/// lisent le même fichier.
pub const NOM_DU_FICHIER: &str = "identite";

/// Combien d'octets d'entropie la fiche porte.
pub const GRAINE_OCTETS: usize = 32;

/// Ce qu'une fiche écrite occupe au plus.
///
/// Trois lignes de commentaire, `machine`, `compte` et `graine` : la mesure
/// vient de la plus longue fiche possible, arrondie au-dessus. Un tampon de
/// cette taille ne déborde jamais, et [`ecrire_une_fiche`] refuse plutôt que de
/// tronquer si l'appelant en donne un plus petit.
pub const FICHE_OCTETS_MAX: usize = 512;

/// Ce qu'une fiche dit, une fois lue.
///
/// **NI `Clone` NI `Copy`, ET CE N'EST PAS NOTRE CHOIX** : `asl_client::Identite`
/// ne l'est pas non plus, délibérément. Une clé privée qui se copie se copie
/// une fois de trop, et la copie de trop est celle qu'on oublie de détruire.
#[derive(Debug)]
pub struct Fiche {
    /// De quoi s'authentifier : la machine et sa clé.
    pub identite: Identite,
    /// Le compte pour lequel cette machine agit, **quand la fiche le porte**.
    ///
    /// `None` n'est pas une faute : un annuaire d'avant 0.3.0 ne le rendait pas
    /// à l'enrôlement, et `GET /v1/moi` l'apprend de toute façon.
    pub compte: Option<Identifiant>,
}

/// Lit une fiche d'identité.
///
/// # Errors
///
/// [`Faute::SansMachine`], [`Faute::PasUneMachine`], [`Faute::SansGraine`],
/// [`Faute::GraineIllisible`].
pub fn lire_une_fiche(contenu: &str) -> Result<Fiche, Faute> {
    let mut machine = None;
    let mut graine = None;
    let mut compte = None;

    for ligne in contenu.lines() {
        let ligne = ligne.trim();
        if ligne.is_empty() || ligne.starts_with('#') {
            continue;
        }
        // **UNE LIGNE SANS `=` EST SAUTÉE**, et non refusée : c'est ce que fait
        // `asl`, et un refus ferait échouer la lecture sur une ligne que
        // quelqu'un a ajoutée à la main sans y penser.
        let Some((clef, valeur)) = ligne.split_once('=') else {
            continue;
        };
        match clef.trim() {
            "machine" => machine = Some(valeur.trim()),
            "graine" => graine = Some(valeur.trim()),
            "compte" => compte = Some(valeur.trim()),
            _ => {}
        }
    }

    // **L'ORDRE DES TROIS REFUS N'EST PAS INDIFFÉRENT.** Le compte d'abord,
    // parce qu'il ne refuse rien ; puis la machine, puis la graine — c'est
    // l'ordre dans lequel un lecteur humain regarderait le fichier, et donc
    // l'ordre dans lequel les messages lui serviront.
    let compte =
        compte.and_then(|texte| Identifiant::analyser_genre(Genre::Utilisateur, texte).ok());

    let machine = machine.ok_or(Faute::SansMachine)?;
    let machine =
        Identifiant::analyser_genre(Genre::Machine, machine).map_err(|_| Faute::PasUneMachine)?;

    let graine = graine.ok_or(Faute::SansGraine)?;
    let graine = depuis_hexa(graine).ok_or(Faute::GraineIllisible)?;

    // **CECI NE PEUT PAS ÉCHOUER, ET UN `?` OUVRIRAIT UNE BRANCHE MORTE.**
    // `Identite::nouvelle` ne refuse qu'un identifiant qui n'est pas celui
    // d'une machine, et `analyser_genre(Genre::Machine, …)` vient de le
    // garantir. Une variante de faute pour ce cas serait un chemin que rien ne
    // peut emprunter — et le 100 % de couverture (C2) l'aurait dit.
    let identite =
        Identite::nouvelle(machine, graine).expect("`analyser_genre` a déjà exigé une machine");
    Ok(Fiche { identite, compte })
}

/// Écrit une fiche d'identité, et rend combien d'octets elle occupe.
///
/// # ELLE ÉCRIT LA FICHE ENTIÈRE, TOUJOURS
///
/// Ajouter une ligne à un fichier existant donnerait deux écritures possibles
/// du même contenu — et la lecture ci-dessus prend la DERNIÈRE occurrence, si
/// bien qu'une ligne ajoutée au-dessus serait silencieusement ignorée. Le
/// fichier se réécrit donc en entier, comme `asl` le fait.
///
/// **LES TROIS LIGNES DE COMMENTAIRE SONT DU CONTENU**, pas de l'ornement :
/// elles sont ce qu'un administrateur lit s'il ouvre ce fichier, et ce qui lui
/// dit de ne pas le recopier sur une autre machine.
///
/// # Errors
///
/// [`Faute::TamponTropCourt`].
pub fn ecrire_une_fiche(
    machine: Identifiant,
    compte: Option<Identifiant>,
    graine: &[u8; GRAINE_OCTETS],
    vers: &mut [u8],
) -> Result<usize, Faute> {
    let mut ecrivain = Ecrivain::neuf(vers);

    // `write!` ne peut échouer que par notre propre écrivain, qui retient le
    // débordement et rend `Ok` : le résultat global est donc toujours `Ok`, et
    // c'est `fini()` qui tranche.
    let _ = write!(
        ecrivain,
        "# asl — l'identité de cette machine.\n\
         #\n\
         # LA MOITIÉ PRIVÉE D'UNE PAIRE DE CLÉS. Elle n'a jamais quitté ce disque,\n\
         # et elle ne le doit pas : l'annuaire ne connaît que la moitié publique.\n\
         # Ne la copiez pas sur une autre machine — enrôlez-la, c'est gratuit.\n\
         machine = {}\n",
        machine.texte().as_str()
    );
    if let Some(compte) = compte {
        let _ = writeln!(ecrivain, "compte = {}", compte.texte().as_str());
    }
    let _ = ecrivain.write_str("graine = ");
    for octet in graine {
        let _ = write!(ecrivain, "{octet:02x}");
    }
    let _ = ecrivain.write_char('\n');

    ecrivain.fini()
}

/// Soixante-quatre caractères hexadécimaux vers trente-deux octets.
///
/// **MINUSCULES ET MAJUSCULES**, parce qu'un fichier écrit à la main peut
/// porter les unes ou les autres, et que refuser les majuscules ferait échouer
/// la lecture pour une raison qu'aucun message ne rendrait évidente.
///
/// **LA LONGUEUR EST EXACTE** : ni plus courte, ni plus longue. Accepter plus
/// court dériverait une clé d'une entropie plus faible que celle qu'on croit
/// avoir, ce qui est exactement la panne qu'on ne verrait pas.
fn depuis_hexa(texte: &str) -> Option<[u8; GRAINE_OCTETS]> {
    let octets = texte.as_bytes();
    if octets.len() != GRAINE_OCTETS.saturating_mul(2) {
        return None;
    }
    // **ON TIRE D'UN ITÉRATEUR, ON N'INDEXE PAS.** La première écriture faisait
    // `octets.get(rang * 2)?`, et ce `?` était du CODE MORT : la longueur vient
    // d'être vérifiée exacte, donc l'index existe toujours. Le 100 % de
    // couverture (C2) l'a dit, et c'est exactement ce qu'il existe pour dire —
    // une branche que rien ne peut emprunter est une branche que personne n'a
    // éprouvée et que tout le monde croit sûre.
    //
    // Ici, chaque `?` ne porte plus qu'une seule cause : ce caractère n'est pas
    // hexadécimal. Et les deux se rencontrent — un chiffre fautif en position
    // paire, un autre en position impaire.
    let mut graine = [0_u8; GRAINE_OCTETS];
    let mut chiffres = octets.iter();
    for place in &mut graine {
        let haut = chiffres.next().copied().and_then(chiffre)?;
        let bas = chiffres.next().copied().and_then(chiffre)?;
        *place = haut.saturating_mul(16).saturating_add(bas);
    }
    Some(graine)
}

/// Un chiffre hexadécimal vers sa valeur.
const fn chiffre(octet: u8) -> Option<u8> {
    match octet {
        b'0'..=b'9' => Some(octet.saturating_sub(b'0')),
        b'a'..=b'f' => Some(octet.saturating_sub(b'a').saturating_add(10)),
        b'A'..=b'F' => Some(octet.saturating_sub(b'A').saturating_add(10)),
        _ => None,
    }
}
