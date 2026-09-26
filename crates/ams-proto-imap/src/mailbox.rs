// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Ce qu'un nom de boîte a le droit d'être (RFC 9051 §5.1).
//!
//! # C'EST ICI QUE LE NOM DEVIENT DANGEREUX
//!
//! Tant qu'une seule boîte existait, un nom de boîte était comparé à une
//! constante et ne devenait jamais un morceau de chemin. `CREATE` change cela :
//! **le nom vient du client et finit dans un nom de répertoire**. C'est la
//! frontière la plus délicate du serveur, et elle se tient ici, en un seul
//! endroit, avec des règles qu'on peut lire.
//!
//! La RFC autorise beaucoup plus que ce qui suit — de l'UTF-8, des points, des
//! caractères que le système de fichiers accepte mal. **Ce serveur en accepte
//! moins, et le dit** : un nom qu'on ne saurait pas transcrire sans risque est
//! refusé, pas transformé. Transformer, c'est rendre au client un nom qui n'est
//! pas celui qu'il a demandé, et lui faire chercher longtemps.
//!
//! # Les règles, et ce que chacune ferme
//!
//! - **Non vide, et pas plus long que ce qu'on retient.** Un nom qui ne tient
//!   pas dans les tampons de la session serait tronqué, donc un autre nom.
//! - **Découpé sur `/`, sans composant vide.** `a//b` et `/a` n'ont pas de sens,
//!   et `a/` est admis mais ignoré (§6.3.4 le prévoit pour les boîtes qui ne
//!   portent que des filles).
//! - **Pas de `.` du tout.** C'est ce qui ferme `..`, donc la remontée de
//!   répertoire — et c'est aussi le séparateur que Maildir++ emploie sur le
//!   disque : un point dans un nom y fabriquerait un niveau de hiérarchie que
//!   personne n'a demandé.
//! - **Pas de contrôle ni de `DEL`**, et pas de `\`, `%`, `*`, `"`, ni `:`. Les
//!   premiers feraient écrire au client une réponse de notre part ; `%` et `*`
//!   sont les jokers de `LIST` ; les autres cassent soit le protocole, soit le
//!   nom de fichier Maildir.
//! - **De l'UTF-8 VALIDE**, vérifié sur le nom entier : une suite mal formée
//!   deviendrait un répertoire qu'on ne saurait ni relire ni rendre.
//! - **Une profondeur bornée.** Sans quoi un client choisirait la longueur des
//!   chemins que le serveur fabrique.
//!
//! # L'ESPACE DES BOÎTES D'AUTRUI : `Partagés/<titulaire>/<boîte>`
//!
//! Une boîte qu'un autre compte nous a déléguée se nomme sous [`SHARED_ROOT`]
//! (RFC 2342, l'espace « Other Users »). **Le composant du titulaire est un
//! login, pas un répertoire** : il ne devient jamais un chemin — le magasin le
//! cherche dans la table des comptes —, et c'est pourquoi lui seul admet le
//! point, que `thierry.delhaise` porte. Il ne peut pas en commencer un, ce qui
//! ferme `.` et `..` comme partout. Ce qui suit est un nom de boîte ordinaire,
//! sous les règles ordinaires.

/// La plus grande longueur d'un nom de boîte, séparateurs compris.
pub const MAILBOX_NAME_MAX: usize = 255;

/// La plus grande longueur d'un composant.
pub const MAILBOX_COMPONENT_MAX: usize = 64;

/// Le plus grand nombre de niveaux.
pub const MAILBOX_DEPTH_MAX: usize = 8;

/// Le séparateur de hiérarchie que ce serveur annonce.
pub const MAILBOX_SEPARATOR: u8 = b'/';

/// La racine de l'espace des boîtes d'autrui, en UTF-8.
///
/// **Un nom fixe, et en français** : c'est celui que les clients affichent, et
/// les comptes de ce serveur parlent français. Un client rev1 le reçoit en
/// UTF-7 modifié (`Partag&AOk-s`), comme tout nom accentué.
pub const SHARED_ROOT: &str = "Partagés";

/// Ce qu'un nom de l'espace partagé désigne.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SharedName<'n> {
    /// `Partagés` lui-même : un nœud, qui ne s'ouvre pas.
    Root,
    /// `Partagés/<titulaire>` : un nœud aussi.
    Owner(&'n [u8]),
    /// `Partagés/<titulaire>/<boîte>` : la boîte `<boîte>` du titulaire.
    Mailbox {
        /// Le login du titulaire.
        owner: &'n [u8],
        /// Le nom de la boîte, tel que le titulaire la nomme.
        name: &'n [u8],
    },
}

/// Découpe un nom de l'espace partagé, ou rend `None` pour un nom personnel.
///
/// **Seule l'écriture exacte de [`SHARED_ROOT`] ouvre l'espace**, casse
/// comprise : ce n'est pas `INBOX`, dont §5.1 veut la casse indifférente. Le
/// `/` final est ignoré, comme partout. Ce découpage ne VÉRIFIE rien — c'est
/// [`mailbox_name_is_safe`] qui le fait.
#[must_use]
pub fn shared_name(nom: &[u8]) -> Option<SharedName<'_>> {
    decouper(mailbox_name_trimmed(nom))
}

/// Le découpage lui-même, SANS retirer de `/` final : la règle de sûreté en a
/// déjà retiré un, et en retirer un second ferait passer `Partagés/x//`.
fn decouper(nom: &[u8]) -> Option<SharedName<'_>> {
    let reste = nom.strip_prefix(SHARED_ROOT.as_bytes())?;
    if reste.is_empty() {
        return Some(SharedName::Root);
    }
    let reste = reste.strip_prefix(&[MAILBOX_SEPARATOR])?;
    Some(
        match reste.iter().position(|octet| *octet == MAILBOX_SEPARATOR) {
            None => SharedName::Owner(reste),
            Some(rang) => SharedName::Mailbox {
                owner: reste.get(..rang).unwrap_or_default(),
                name: reste.get(rang.saturating_add(1)..).unwrap_or_default(),
            },
        },
    )
}

/// Ce nom peut-il devenir un chemin sans danger ?
///
/// **Un `/` final est ignoré** : §6.3.4 l'admet, et il ne change pas la boîte
/// désignée.
///
/// Sous [`SHARED_ROOT`], le composant du titulaire admet le point — il ne
/// devient jamais un chemin —, et la boîte qui suit, si elle est nommée, suit
/// les règles ordinaires. `INBOX` y est admise sous toutes ses casses, comme
/// ailleurs.
#[must_use]
pub fn mailbox_name_is_safe(nom: &[u8]) -> bool {
    let nom = nom.strip_suffix(&[MAILBOX_SEPARATOR]).unwrap_or(nom);
    if nom.is_empty() || nom.len() > MAILBOX_NAME_MAX {
        return false;
    }
    match decouper(nom) {
        None => nom_personnel_sur(nom),
        Some(SharedName::Root) => true,
        Some(SharedName::Owner(titulaire)) => titulaire_sur(titulaire),
        Some(SharedName::Mailbox { owner, name }) => {
            titulaire_sur(owner)
                && (name.eq_ignore_ascii_case(b"INBOX") || nom_personnel_sur(name))
                && nom.split(|octet| *octet == MAILBOX_SEPARATOR).count() <= MAILBOX_DEPTH_MAX
        }
    }
}

/// Le composant du titulaire : un login, qui peut porter des points mais ne
/// peut pas en commencer un.
fn titulaire_sur(titulaire: &[u8]) -> bool {
    !titulaire.is_empty()
        && titulaire.len() <= MAILBOX_COMPONENT_MAX
        && titulaire.first() != Some(&b'.')
        && core::str::from_utf8(titulaire).is_ok()
        && titulaire == titulaire.trim_ascii()
        && titulaire
            .iter()
            .all(|octet| *octet == b'.' || octet_admis(*octet))
}

/// Un nom personnel — qui DEVIENT un chemin, sous les règles entières.
///
/// La longueur totale est déjà bornée par l'appelant : un nom intérieur est plus
/// court que le nom entier.
fn nom_personnel_sur(nom: &[u8]) -> bool {
    if nom.is_empty() {
        return false;
    }
    // **DE L'UTF-8 VALIDE, ET SUR LE NOM ENTIER** : §5.1 de RFC 9051 le veut, et
    // une suite d'octets mal formée deviendrait un nom de répertoire qu'on ne
    // saurait pas relire — ni rendre au client dans une réponse.
    if core::str::from_utf8(nom).is_err() {
        return false;
    }
    let mut composants = 0_usize;
    for composant in nom.split(|octet| *octet == MAILBOX_SEPARATOR) {
        composants = composants.saturating_add(1);
        if composants > MAILBOX_DEPTH_MAX
            || composant.is_empty()
            || composant.len() > MAILBOX_COMPONENT_MAX
            || !composant.iter().all(|octet| octet_admis(*octet))
        {
            return false;
        }
        // Un composant fait d'espaces ne se voit pas, et deux d'entre eux ne se
        // distinguent pas.
        if composant.trim_ascii().is_empty() || composant != composant.trim_ascii() {
            return false;
        }
    }
    true
}

/// Le nom, privé de son `/` final s'il en a un.
#[must_use]
pub fn mailbox_name_trimmed(nom: &[u8]) -> &[u8] {
    nom.strip_suffix(&[MAILBOX_SEPARATOR]).unwrap_or(nom)
}

/// Cet octet a-t-il le droit de figurer dans un composant ?
///
/// # L'UTF-8 PASSE, ET C'EST §5.1 QUI L'EXIGE
///
/// Cette règle refusait tout octet au-delà de `0x7E`, au motif qu'un nom finit
/// dans une réponse. **Le motif était juste, sa portée trop large** : un octet
/// d'UTF-8 n'est pas un vecteur d'injection — ce qui l'est, ce sont les
/// contrôles, le guillemet et la barre oblique inverse, qui ferment une chaîne
/// citée. Refuser l'UTF-8, c'était annoncer `IMAP4rev2` et refuser ce que §5.1
/// de RFC 9051 rend obligatoire.
///
/// La VALIDITÉ de l'UTF-8, elle, ne se vérifie pas octet par octet : c'est
/// [`mailbox_name_is_safe`] qui l'examine sur le nom entier.
fn octet_admis(octet: u8) -> bool {
    // Les contrôles C0 et `DEL` : ce sont eux qui feraient écrire au client une
    // réponse de notre part.
    if octet < 0x20 || octet == 0x7F {
        return false;
    }
    !matches!(octet, b'.' | b'\\' | b'%' | b'*' | b'"' | b':' | b'/')
}

#[cfg(test)]
mod tests;
