// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Le catalogue : **la table de routage rendue énumérable**, pour la décrire.
//!
//! # POURQUOI UNE TABLE DE PLUS, ET POURQUOI ELLE N'EN EST PAS UNE
//!
//! [`crate::route::designer`] sait reconnaître un chemin ; elle ne sait pas les
//! réciter. Un `match` qui va du chemin vers la ressource ne se parcourt pas à
//! l'envers, et décrire une API demande justement l'envers : la liste de ce
//! qu'elle sert.
//!
//! Ce module ne redit donc PAS ce que l'autre décide. Il porte, par ressource,
//! les deux seules choses que le routage ne contient pas — **le gabarit du
//! chemin** et **une phrase qui dit à quoi il sert** — et laisse tout le reste
//! se lire sur le type : les méthodes par [`Resource::allowed`], le droit par
//! [`Resource::scope`].
//!
//! # ET IL NE PEUT PAS DÉRIVER
//!
//! Deux gardes, et c'est la raison d'être de ce découpage :
//!
//!   1. [`Resource::rang`] est un `match` exhaustif. **Ajouter une ressource
//!      sans lui donner de rang ne compile pas.**
//!   2. Un essai exige que les rangs du catalogue soient exactement
//!      `0..CATALOGUE.len()`, chacun une fois. Une ressource oubliée, ou écrite
//!      deux fois, échoue.
//!
//! Et un troisième essai instancie chaque gabarit, le passe à
//! [`crate::route::resolve`], et exige la ressource de même rang : **un gabarit
//! qui mentirait sur ce que le routage accepte ne passerait pas.**

use crate::route::Resource;

/// Ce qu'une ressource expose d'elle-même pour être DÉCRITE.
#[derive(Debug, Clone, Copy)]
pub struct Entree {
    /// Le gabarit du chemin, ses paramètres entre accolades.
    ///
    /// C'est la forme qu'OpenAPI attend, et celle que les gabarits de
    /// `designer` ne portent pas : elle n'existe nulle part ailleurs.
    pub gabarit: &'static str,
    /// Un exemplaire, pour lire les méthodes et la portée SUR LE TYPE.
    ///
    /// **CE N'EST PAS UNE VALEUR UTILE** : ses champs sont des témoins, choisis
    /// pour qu'un essai puisse instancier le gabarit. Ce qui compte est sa
    /// variante.
    pub exemplaire: Resource<'static>,
    /// Ce que cette ressource sert, en une phrase.
    pub resume: &'static str,
}

/// Tout ce que cette API sert, dans l'ordre des rangs.
pub const CATALOGUE: &[Entree] = &[
    Entree {
        gabarit: "/v1/tokens",
        exemplaire: Resource::Tokens,
        resume: "Échanger des identifiants contre un jeton. N'exige aucune portée : c'est là qu'on en obtient.",
    },
    Entree {
        gabarit: "/v1/tokens/current",
        exemplaire: Resource::CurrentToken,
        resume: "Révoquer le jeton présenté.",
    },
    Entree {
        gabarit: "/v1/sessions/challenge",
        exemplaire: Resource::SessionChallenge,
        resume: "Obtenir un défi à signer. Émis pour n'importe quel couple compte-appareil, connu ou non, pour ne pas être un oracle d'énumération.",
    },
    Entree {
        gabarit: "/v1/sessions",
        exemplaire: Resource::Sessions,
        resume: "Ouvrir une session avec la clef d'un appareil : un défi signé au lieu d'un mot de passe, et le même jeton en retour.",
    },
    Entree {
        gabarit: "/v1/devices",
        exemplaire: Resource::Devices,
        resume: "Enrôler un appareil. C'est l'invitation scellée, dans le corps, qui autorise — pas un jeton.",
    },
    Entree {
        gabarit: "/v1/invitations",
        exemplaire: Resource::Invitations,
        resume: "Frapper une invitation d'enrôlement. Geste d'exploitant.",
    },
    Entree {
        gabarit: "/v1/me/password",
        exemplaire: Resource::OwnPassword,
        resume: "Changer son propre mot de passe. L'actuel est exigé dans le corps : sans cela, un jeton volé deviendrait un vol de compte.",
    },
    Entree {
        gabarit: "/v1/me/devices",
        exemplaire: Resource::OwnDevices,
        resume: "Ses appareils. Le POST est l'appairage croisé, et exige un défi signé par un appareil déjà enrôlé.",
    },
    Entree {
        gabarit: "/v1/me/devices/{id}",
        exemplaire: Resource::OwnDevice { id: "ap" },
        resume: "Révoquer un de ses appareils. Le compte de qui appelle entre dans la recherche.",
    },
    Entree {
        gabarit: "/v1/me/push",
        exemplaire: Resource::OwnPush,
        resume: "Son abonnement aux notifications poussées.",
    },
    Entree {
        gabarit: "/v1/me/app-passwords",
        exemplaire: Resource::OwnAppPasswords,
        resume: "Ses mots de passe applicatifs. Le secret n'est rendu qu'à la création.",
    },
    Entree {
        gabarit: "/v1/me/app-passwords/{id}",
        exemplaire: Resource::OwnAppPassword { id: "mp" },
        resume: "Révoquer un mot de passe applicatif.",
    },
    Entree {
        gabarit: "/v1/me/delegations",
        exemplaire: Resource::OwnDelegations,
        resume: "Les boîtes d'autrui auxquelles on a accès.",
    },
    Entree {
        gabarit: "/v1/me/audit",
        exemplaire: Resource::OwnAudit,
        resume: "Son journal d'audit. Il se lit, et c'est tout.",
    },
    Entree {
        gabarit: "/v1/mailboxes",
        exemplaire: Resource::Mailboxes,
        resume: "Les boîtes du compte.",
    },
    Entree {
        gabarit: "/v1/mailboxes/{boite}",
        exemplaire: Resource::Mailbox { boite: "INBOX" },
        resume: "Une boîte et son état. PUT la crée, DELETE la supprime.",
    },
    Entree {
        gabarit: "/v1/mailboxes/{boite}/messages",
        exemplaire: Resource::Messages { boite: "INBOX" },
        resume: "Les messages qu'elle porte. Le POST y dépose un message.",
    },
    Entree {
        gabarit: "/v1/mailboxes/{boite}/messages/{uid}",
        exemplaire: Resource::Message {
            boite: "INBOX",
            uid: 1,
        },
        resume: "Un message : enveloppe et structure. PATCH en json-patch+json pour ses drapeaux.",
    },
    Entree {
        gabarit: "/v1/mailboxes/{boite}/messages/{uid}/raw",
        exemplaire: Resource::MessageRaw {
            boite: "INBOX",
            uid: 1,
        },
        resume: "Le message tel qu'il est arrivé. Une ressource à part, et non une négociation de contenu.",
    },
    Entree {
        gabarit: "/v1/mailboxes/{boite}/messages/{uid}/parts/{partie}",
        exemplaire: Resource::MessagePart {
            boite: "INBOX",
            uid: 1,
            partie: "1",
        },
        resume: "Une partie MIME, numérotée comme §6.4.5 de RFC 9051.",
    },
    Entree {
        gabarit: "/v1/mailboxes/{boite}/changes",
        exemplaire: Resource::Changes { boite: "INBOX" },
        resume: "Ce qui a changé depuis un point. `?since=<modseq>` est exigé ; un curseur trop vieux rend 410.",
    },
    Entree {
        gabarit: "/v1/mailboxes/{boite}/search",
        exemplaire: Resource::Search { boite: "INBOX" },
        resume: "Une recherche. Un POST, pour que les critères ne soient pas journalisés par les intermédiaires.",
    },
    Entree {
        gabarit: "/v1/mailboxes/{boite}/copy",
        exemplaire: Resource::Copy { boite: "INBOX" },
        resume: "Copier des messages vers une autre boîte. Un geste, pas un état.",
    },
    Entree {
        gabarit: "/v1/mailboxes/{boite}/move",
        exemplaire: Resource::Move { boite: "INBOX" },
        resume: "Déplacer des messages vers une autre boîte.",
    },
    Entree {
        gabarit: "/v1/drafts",
        exemplaire: Resource::Drafts,
        resume: "Créer un brouillon à partir du corps seul : un message se soumet corps d'abord.",
    },
    Entree {
        gabarit: "/v1/drafts/{id}",
        exemplaire: Resource::Draft { id: "br" },
        resume: "Un brouillon : son état, ou son abandon.",
    },
    Entree {
        gabarit: "/v1/drafts/{id}/attachments",
        exemplaire: Resource::DraftAttachments { id: "br" },
        resume: "Déclarer une pièce jointe à ce brouillon.",
    },
    Entree {
        gabarit: "/v1/drafts/{id}/attachments/{n}",
        exemplaire: Resource::DraftAttachment { id: "br", piece: 1 },
        resume: "Poser le contenu d'une pièce jointe. Un morceau se pose, il ne se lit pas.",
    },
    Entree {
        gabarit: "/v1/drafts/{id}/send",
        exemplaire: Resource::DraftSend { id: "br" },
        resume: "Composer le message entier et l'envoyer.",
    },
    Entree {
        gabarit: "/v1/drafts/{id}/store",
        exemplaire: Resource::DraftStore { id: "br" },
        resume: "Ranger le brouillon composé dans une boîte. Seule route du groupe en portée `mail`.",
    },
    Entree {
        gabarit: "/v1/submissions",
        exemplaire: Resource::Submissions,
        resume: "Soumettre un message complet, d'un seul coup.",
    },
    Entree {
        gabarit: "/v1/accounts",
        exemplaire: Resource::Accounts,
        resume: "Les comptes. Le POST en crée un.",
    },
    Entree {
        gabarit: "/v1/accounts/{compte}",
        exemplaire: Resource::Account { compte: "ada" },
        resume: "Un compte : son état, sa création par PUT, sa suppression.",
    },
    Entree {
        gabarit: "/v1/accounts/{compte}/password",
        exemplaire: Resource::AccountPassword { compte: "ada" },
        resume: "Imposer un mot de passe. Ne se lit pas : aucune méthode ne rend d'empreinte.",
    },
    Entree {
        gabarit: "/v1/accounts/{compte}/addresses",
        exemplaire: Resource::AccountAddresses { compte: "ada" },
        resume: "Les adresses de ce compte.",
    },
    Entree {
        gabarit: "/v1/accounts/{compte}/delegates",
        exemplaire: Resource::Delegates { compte: "ada" },
        resume: "Qui a accès à la boîte de ce compte.",
    },
    Entree {
        gabarit: "/v1/accounts/{compte}/delegates/{delegue}",
        exemplaire: Resource::Delegate {
            compte: "ada",
            delegue: "bob",
        },
        resume: "Accorder ou retirer une délégation.",
    },
    Entree {
        gabarit: "/v1/accounts/{compte}/devices",
        exemplaire: Resource::AccountDevices { compte: "ada" },
        resume: "Les appareils de ce compte.",
    },
    Entree {
        gabarit: "/v1/accounts/{compte}/devices/{id}",
        exemplaire: Resource::AccountDevice {
            compte: "ada",
            id: "ap",
        },
        resume: "Révoquer l'appareil d'un compte.",
    },
    Entree {
        gabarit: "/v1/accounts/{compte}/audit",
        exemplaire: Resource::AccountAudit { compte: "ada" },
        resume: "Le journal d'audit de ce compte.",
    },
    Entree {
        gabarit: "/v1/domains",
        exemplaire: Resource::Domains,
        resume: "Les domaines que ce serveur héberge.",
    },
    Entree {
        gabarit: "/v1/bans",
        exemplaire: Resource::Bans,
        resume: "Les bannissements en cours.",
    },
    Entree {
        gabarit: "/v1/bans/{source}",
        exemplaire: Resource::Ban {
            source: "198.51.100.7",
        },
        resume: "Lever un bannissement.",
    },
    Entree {
        gabarit: "/v1/health",
        exemplaire: Resource::Health,
        resume: "L'état de ce serveur.",
    },
    Entree {
        gabarit: "/v1/metrics",
        exemplaire: Resource::Metrics,
        resume: "Ses compteurs.",
    },
    Entree {
        gabarit: "/v1/openapi.json",
        exemplaire: Resource::OpenApi,
        resume: "Ce document même : ce que cette API fait. N'exige aucun jeton — découvrir n'est pas utiliser.",
    },
];

#[cfg(test)]
mod tests;
