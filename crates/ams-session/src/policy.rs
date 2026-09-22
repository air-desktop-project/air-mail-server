//! La décision que la session ne prend pas.

use ams_proto_smtp::Path;
use ams_sasl::Credentials;

/// Ce qu'un serveur décide d'un destinataire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecipientVerdict {
    /// Accepté.
    Accept,
    /// Refusé **définitivement** : la boîte n'existe pas, ou n'accepte rien.
    RejectPermanent,
    /// Refusé **pour l'instant** : réessayer plus tard a un sens.
    RejectTemporary,
    /// Ce serveur ne relaie pas vers ce destinataire.
    ///
    /// Distinct de [`RecipientVerdict::RejectPermanent`] alors que les deux
    /// rendent `550` : un expéditeur légitime qui se trompe de serveur doit
    /// pouvoir le comprendre sans lire les journaux d'en face.
    RelayDenied,
}

/// Qui vérifie des identifiants.
///
/// # Pourquoi ce trait est SÉPARÉ de [`Policy`]
///
/// POP3 authentifie et ne relaie rien : lui imposer une politique de
/// destinataires l'obligerait à écrire une méthode qui n'a aucun sens chez lui,
/// et une méthode sans usage finit par être remplie n'importe comment. SMTP, lui,
/// a besoin des deux — d'où [`Policy`], qui exige celui-ci.
pub trait Authenticator {
    /// Ces identifiants ouvrent-ils une session ?
    ///
    /// # Pourquoi CELUI-CI a un défaut alors que les destinataires n'en ont pas
    ///
    /// Ce n'est pas une inconséquence, c'est le SENS du défaut qui diffère. Pour
    /// les destinataires, le seul défaut concevable serait « accepter », c'est-à-
    /// dire un relais ouvert : il n'y en a donc pas. Ici, le défaut REFUSE, et un
    /// défaut qui refuse ne peut ouvrir aucune porte. Une politique qui oublie
    /// d'implémenter cette méthode alors que sa configuration annonce `AUTH`
    /// obtient un serveur où personne ne peut se connecter — c'est bruyant,
    /// immédiat, et sans danger.
    ///
    /// # Ce qu'elle doit faire, et ce qu'elle ne doit pas
    ///
    /// La comparaison du mot de passe doit être **à temps constant** : une
    /// comparaison qui s'arrête au premier octet différent se mesure, et se
    /// mesure d'autant mieux qu'on peut la répéter. Les identifiants arrivent
    /// **tels que le pair les a envoyés** — ni normalisés, ni validés en UTF-8
    /// (voir [`ams_sasl`] pour ce que SASLprep aurait changé).
    ///
    /// Pure : pas de requête à un annuaire, pas de lecture de fichier. Une
    /// décision qui attend est une décision qu'un pair peut faire attendre.
    fn authenticate(&self, credentials: &Credentials<'_>) -> bool {
        let _ = credentials;
        false
    }

    /// Le NOM DE COMPTE que cette identité désigne, écrit dans `sortie`.
    ///
    /// # POURQUOI CETTE MÉTHODE EXISTE
    ///
    /// Depuis le 2026-09-22, un compte s'authentifie sous deux formes : son nom
    /// nu — `jean` — et n'importe laquelle de ses adresses — `jean@narro.ch` —,
    /// parce que c'est ce que Dovecot acceptait et donc ce que portent les
    /// clients de tous ceux qui migrent. Mais **l'identité authentifiée devient
    /// ensuite le nom de la BOÎTE** : la retenir telle que le pair l'a écrite
    /// donnerait un répertoire `jean@narro.ch` à côté de `jean`, et le compte
    /// relèverait une boîte vide.
    ///
    /// La session appelle donc ceci juste après un succès, et retient ce qui en
    /// sort. Rend combien d'octets ont été écrits.
    ///
    /// **LE DÉFAUT RECOPIE L'IDENTITÉ**, ce qui est juste pour toute politique
    /// qui n'accepte que le nom nu — y compris les doublures des bancs.
    fn canonical_login(&self, identity: &[u8], sortie: &mut [u8]) -> usize {
        let longueur = identity.len().min(sortie.len());
        sortie
            .get_mut(..longueur)
            .unwrap_or_default()
            .copy_from_slice(identity.get(..longueur).unwrap_or_default());
        longueur
    }

    /// La première réponse de SCRAM : le `server-first` de RFC 5802 §3.
    ///
    /// Reçoit le `client-first` ENTIER — en-tête GS2 compris, parce que la
    /// politique doit savoir si le pair a lié le canal — et écrit dans `sortie`
    /// un `r=…,s=…,i=…`. Rend combien d'octets, et le `client-first-bare` que
    /// la session devra retenir.
    ///
    /// # UN COMPTE INCONNU RÉPOND COMME UN AUTRE
    ///
    /// §7 le demande : refuser tout de suite rendrait le magasin énumérable
    /// sans connaître un seul mot de passe. La politique rend donc un sel
    /// FACTICE mais stable, et n'échoue qu'à la preuve. `None` ne veut pas dire
    /// « compte inconnu » : il veut dire **SCRAM n'est pas servi ici**, ou le
    /// message est mal formé.
    ///
    /// Le défaut ne sert pas SCRAM. Une politique qui ne l'implémente pas
    /// obtient un serveur qui ne l'annonce pas — c'est cohérent, et silencieux.
    fn scram_first(&self, client_first: &[u8], sortie: &mut [u8]) -> Option<ScramFirst> {
        let _ = (client_first, sortie);
        None
    }

    /// La conclusion : vérifie la preuve et écrit le `server-final` (`v=…`).
    ///
    /// Reçoit les trois parts du `AuthMessage` de §3 — le `client-first-bare`
    /// et le `server-first` que la session a retenus, et le `client-final`
    /// entier, dont la politique retirera la preuve.
    ///
    /// Rend le nombre d'octets écrits dans `sortie` quand la preuve est juste,
    /// et `None` autrement. **Aucune distinction entre « compte inconnu » et
    /// « preuve fausse »** : les séparer apprendrait à qui tâtonne lequel des
    /// deux il a touché.
    fn scram_final(
        &self,
        bare: &[u8],
        first: &[u8],
        client_final: &[u8],
        sortie: &mut [u8],
    ) -> Option<usize> {
        let _ = (bare, first, client_final, sortie);
        None
    }
}

/// Ce que [`Authenticator::scram_first`] rend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScramFirst {
    /// Combien d'octets de `server-first` ont été écrits.
    pub ecrits: usize,
    /// Où commence le `client-first-bare` dans le `client-first` reçu.
    ///
    /// **UN RANG, ET NON UNE COPIE** : la session tient déjà le message, et le
    /// recopier ici demanderait un second tampon pour rien.
    pub debut_bare: usize,
}

impl<T: Authenticator + ?Sized> Authenticator for &T {
    fn authenticate(&self, credentials: &Credentials<'_>) -> bool {
        (**self).authenticate(credentials)
    }

    fn canonical_login(&self, identity: &[u8], sortie: &mut [u8]) -> usize {
        (**self).canonical_login(identity, sortie)
    }

    fn scram_first(&self, client_first: &[u8], sortie: &mut [u8]) -> Option<ScramFirst> {
        (**self).scram_first(client_first, sortie)
    }

    fn scram_final(
        &self,
        bare: &[u8],
        first: &[u8],
        client_final: &[u8],
        sortie: &mut [u8],
    ) -> Option<usize> {
        (**self).scram_final(bare, first, client_final, sortie)
    }
}

/// Qui décide des destinataires.
///
/// # Pourquoi ce trait existe, et pourquoi il n'est pas facultatif
///
/// Un serveur qui accepterait tout destinataire est un **relais ouvert**, que C6
/// exclut. La session ne prend pas cette décision — elle n'en a pas les moyens,
/// n'ayant ni table de domaines ni comptes — et elle ne l'invente donc pas : elle
/// **exige** qu'on la lui fournisse. On ne peut pas construire une session sans
/// politique, et c'est ce qui rend le relais ouvert inexprimable plutôt
/// qu'improbable.
///
/// # La décision doit être PURE, et rendue immédiatement
///
/// Pas d'entrée-sortie : ni requête LDAP, ni base de données, ni résolution DNS.
/// C1 l'interdit, et ce n'est pas la seule raison — une décision qui attend est
/// une décision qu'un pair peut faire attendre, et cent connexions qui attendent
/// ensemble sont un déni de service.
pub trait Policy: Authenticator {
    /// Ce destinataire est-il acceptable ?
    ///
    /// Appelé une fois par `RCPT TO:`, avec le chemin **déjà validé**
    /// grammaticalement.
    ///
    /// # `submitter` EST CE QUI SÉPARE UN RELAIS D'UN RELAIS OUVERT
    ///
    /// Il vaut `true` quand la session s'est authentifiée, et lui seul autorise
    /// une politique à accepter un destinataire qui n'est pas d'ici. La session
    /// le sait — elle a conduit l'`AUTH` — et la politique ne peut pas le
    /// deviner : elle est PARTAGÉE par toutes les connexions, et n'a aucun état
    /// propre à celle-ci.
    ///
    /// Le lui faire déduire d'autre chose serait la façon d'ouvrir un relais
    /// sans s'en apercevoir. C'est pourquoi il est un argument, et non un champ
    /// que quelqu'un pourrait oublier de mettre à jour.
    ///
    /// **L'authentification n'est annoncée que sous chiffrement**, si bien qu'un
    /// `true` implique une session chiffrée. Ce n'est pas vérifié ici : ce refus
    /// est tenu par la session, à un seul endroit.
    fn accepts_recipient(&self, forward_path: &Path<'_>, submitter: bool) -> RecipientVerdict;
}

/// Une référence partagée est une politique.
///
/// Une boucle qui sert mille connexions n'a qu'UNE table de domaines : sans cette
/// implémentation, chaque session en exigerait une copie, ou l'appelant devrait
/// écrire ce même relais à la main.
impl<T: Policy + ?Sized> Policy for &T {
    fn accepts_recipient(&self, forward_path: &Path<'_>, submitter: bool) -> RecipientVerdict {
        (**self).accepts_recipient(forward_path, submitter)
    }
}

#[cfg(test)]
mod tests {
    use super::{Authenticator, Policy, RecipientVerdict, ScramFirst};
    use ams_proto_smtp::Path;
    use ams_sasl::Credentials;

    /// Une politique qui rend toujours le même verdict, **et n'implémente pas
    /// `authenticate`** : c'est tout l'objet de l'un des tests ci-dessous.
    struct Toujours(RecipientVerdict);

    /// Elle n'implémente PAS `authenticate` : c'est tout l'objet de l'un des
    /// tests ci-dessous.
    impl Authenticator for Toujours {}

    impl Policy for Toujours {
        fn accepts_recipient(
            &self,
            _forward_path: &Path<'_>,
            _submitter: bool,
        ) -> RecipientVerdict {
            self.0
        }
    }

    /// Des identifiants qui seraient justes, si quelqu'un les connaissait.
    const IDENTIFIANTS: Credentials<'static> = Credentials {
        authorization_identity: b"",
        authentication_identity: b"jean",
        password: b"ouvre-toi",
    };

    /// Interroge l'authentification **par générique**, pour la même raison.
    fn authentifier<P: Authenticator>(politique: P) -> bool {
        politique.authenticate(&IDENTIFIANTS)
    }

    #[test]
    fn le_defaut_refuse_tout_le_monde() {
        // UNE POLITIQUE QUI N'IMPLÉMENTE RIEN N'OUVRE RIEN. C'est ce qui rend ce
        // défaut acceptable là où celui des destinataires ne le serait pas :
        // celui-ci ne peut ouvrir aucune porte, il ne peut que les fermer toutes.
        assert!(!authentifier(Toujours(RecipientVerdict::Accept)));
    }

    #[test]
    fn une_reference_partagee_authentifie_comme_sa_cible() {
        // Sans l'implémentation générique, une politique passée par référence
        // retomberait sur le défaut — c'est-à-dire refuserait tout le monde,
        // en silence, alors que sa cible sait ouvrir.
        struct Ouvre;
        impl Authenticator for Ouvre {
            fn authenticate(&self, credentials: &Credentials<'_>) -> bool {
                credentials.authentication_identity == b"jean"
            }
        }
        impl Policy for Ouvre {
            fn accepts_recipient(
                &self,
                _forward_path: &Path<'_>,
                _submitter: bool,
            ) -> RecipientVerdict {
                RecipientVerdict::Accept
            }
        }
        let politique = Ouvre;
        assert!(authentifier(&politique));
        assert!(authentifier(Ouvre));
        // Et la MÊME référence sert les deux méthodes : c'est ce qu'une boucle
        // qui partage une table de domaines entre mille sessions demande.
        assert_eq!(interroger(&politique), RecipientVerdict::Accept);
    }

    /// Interroge une politique **par générique**.
    ///
    /// L'appel direct sur une référence ne prouverait rien : l'auto-déréférence
    /// irait chercher l'implémentation concrète, et l'implémentation générique
    /// resterait morte. Il faut que `P` VAILLE `&Toujours` pour l'emprunter.
    fn interroger<P: Policy>(politique: P) -> RecipientVerdict {
        politique.accepts_recipient(&Path::Null, false)
    }

    /// Interroge SCRAM **par générique**, pour la raison déjà dite : un appel
    /// direct sur une référence irait chercher l'implémentation concrète, et le
    /// relais de `&T` resterait mort.
    fn tenter_scram<P: Authenticator>(politique: P) -> (Option<ScramFirst>, Option<usize>) {
        let mut sortie = [0_u8; 64];
        let premier = politique.scram_first(b"n,,n=jean,r=abc", &mut sortie);
        let dernier = politique.scram_final(
            b"n=jean,r=abc",
            b"r=abcdef,s=c2Vs,i=4096",
            b"c=biws,r=abcdef,p=AAAA",
            &mut sortie,
        );
        (premier, dernier)
    }

    #[test]
    fn le_defaut_ne_sert_pas_scram_et_la_reference_non_plus() {
        // **`None` NE VEUT PAS DIRE « COMPTE INCONNU »**, il veut dire « SCRAM
        // n'est pas servi ici » : la session ne l'annonce alors pas, et le
        // refuse si un client l'essaie quand même. Une politique qui oublie ces
        // deux méthodes obtient un serveur en `PLAIN` seul — cohérent, et
        // silencieux.
        let politique = Toujours(RecipientVerdict::Accept);
        let (premier, dernier) = tenter_scram(&politique);
        assert!(premier.is_none() && dernier.is_none());
        // Et par valeur, puisque c'est le même défaut des deux côtés.
        let (premier, dernier) = tenter_scram(Toujours(RecipientVerdict::Accept));
        assert!(premier.is_none() && dernier.is_none());
    }

    #[test]
    fn le_nom_canonique_par_defaut_recopie_l_identite() {
        // Le défaut convient à toute politique qui n'accepte que le nom nu ; une
        // politique qui accepte aussi les adresses le remplace. **LA RECOPIE SE
        // BORNE À LA SORTIE** : un nom plus long que le tampon est tronqué, et
        // non écrit à côté.
        fn canonique<P: Authenticator>(politique: P, identite: &[u8], place: &mut [u8]) -> usize {
            politique.canonical_login(identite, place)
        }
        let politique = Toujours(RecipientVerdict::Accept);
        let mut place = [0_u8; 16];
        let taille = canonique(&politique, b"jean", &mut place);
        assert_eq!(place.get(..taille), Some(&b"jean"[..]));
        let mut etroite = [0_u8; 2];
        let taille = canonique(Toujours(RecipientVerdict::Accept), b"jean", &mut etroite);
        assert_eq!(etroite.get(..taille), Some(&b"je"[..]));
    }

    #[test]
    fn une_reference_partagee_est_une_politique() {
        let politique = Toujours(RecipientVerdict::RelayDenied);
        assert_eq!(interroger(&politique), RecipientVerdict::RelayDenied);
        // Et la politique elle-même en est une, évidemment.
        assert_eq!(
            interroger(Toujours(RecipientVerdict::Accept)),
            RecipientVerdict::Accept
        );
    }
}
