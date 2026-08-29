//! Ce qu'un serveur annonce et ce qu'il borne.

use ams_proto_smtp::{ClientId, Limits};

use crate::Error;

/// Ce que la boucle qui pilote la session sait réellement faire.
///
/// # Annoncer ce qu'on ne sait pas faire est un mensonge coûteux
///
/// Une session n'exécute ni la poignée de main TLS ni l'échange SASL : elle les
/// **délègue**. Si l'appelant ne sait pas les conduire, les annoncer dans l'`EHLO`
/// ferait envoyer un mot de passe à un serveur qui n'a pas de quoi le protéger, ou
/// attendre un chiffrement qui ne viendra pas.
///
/// Le défaut est donc **tout à `false`** : un serveur n'offre que ce que quelqu'un
/// a explicitement déclaré savoir faire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Capabilities {
    /// L'appelant sait conduire une poignée de main TLS.
    pub starttls: bool,
    /// L'appelant sait conduire un échange SASL.
    pub auth: bool,
}

/// Ce que la session fait du verdict SPF.
///
/// # Trois états, et pas un interrupteur
///
/// « SPF activé » ne dit pas ce qu'on fait d'un `fail`, et c'est pourtant la
/// seule question qui compte. Un interrupteur à deux positions obligerait à
/// choisir entre *ne rien vérifier* et *refuser tout de suite* — alors qu'un
/// administrateur qui met SPF en service veut d'abord REGARDER : une politique
/// mal écrite chez un partenaire refuserait du courrier légitime, et il vaut
/// mieux le découvrir dans un journal que dans un appel téléphonique.
///
/// Le défaut est [`SenderPolicy::Ignore`], pour la même raison que
/// [`Capabilities`] est tout à `false` : **la session ne demande que ce que
/// quelqu'un a déclaré savoir faire.** Une session qui réclamerait une
/// résolution DNS à une boucle qui n'en fait pas attendrait pour rien.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SenderPolicy {
    /// SPF n'est pas vérifié. La session ne demande rien à personne.
    #[default]
    Ignore,
    /// La boucle vérifie, la session RETIENT le verdict, et n'oppose rien.
    ///
    /// C'est l'état où l'on découvre ce qu'une politique refuserait avant de la
    /// laisser refuser.
    Observe,
    /// Un `fail` est refusé (`550`), une panne de résolution ajournée (`451`).
    Enforce,
}

/// Ce dont une session SMTP a besoin pour exister.
///
/// # Ce qui n'est PAS réglable, et pourquoi
///
/// **`AUTH` hors TLS n'est pas un réglage.** C6 l'exclut, et un interrupteur qui
/// permettrait de le rétablir finirait par être basculé « juste pour un test ».
/// La session refuse `AUTH` avant TLS, toujours, et il n'y a pas de champ pour en
/// décider autrement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Config<'a> {
    domain: &'a [u8],
    max_recipients: usize,
    max_message_octets: u64,
    limits: Limits,
    capabilities: Capabilities,
    sender_policy: SenderPolicy,
}

impl<'a> Config<'a> {
    /// Construit une configuration, en validant le domaine du serveur.
    ///
    /// `domain` franchit la **même** grammaire que celui d'un client
    /// ([`ClientId::parse`]) : deux validateurs pour une seule grammaire
    /// finissent par diverger.
    ///
    /// # Errors
    ///
    /// [`Error::ServerDomainInvalid`] si `domain` n'est pas un domaine.
    pub fn new(
        domain: &'a [u8],
        max_recipients: usize,
        max_message_octets: u64,
        limits: Limits,
    ) -> Result<Self, Error> {
        // Un littéral d'adresse serait grammaticalement valide ici, et c'est
        // pourtant un serveur qui ne sait pas comment il s'appelle. On l'accepte :
        // la RFC 5321 §4.1.3 le prévoit pour les hôtes sans nom, et le refuser
        // ferait échouer un démarrage que rien n'oblige à échouer.
        // Le domaine du SERVEUR est borné à 255 octets quoi qu'en dise la
        // configuration : c'est notre propre nom, il tient dans la bannière que
        // la session prépare une fois pour toutes, et rien n'oblige à le laisser
        // grandir avec une borne pensée pour les pairs.
        let bornes_du_serveur = Limits {
            max_domain_octets: limits.max_domain_octets.min(255),
            ..limits
        };
        ClientId::parse(domain, &bornes_du_serveur).map_err(Error::ServerDomainInvalid)?;
        Ok(Self {
            domain,
            max_recipients,
            max_message_octets,
            limits,
            capabilities: Capabilities::default(),
            sender_policy: SenderPolicy::default(),
        })
    }

    /// Déclare ce que l'appelant sait conduire.
    ///
    /// Sans cet appel, la session n'annonce **ni `STARTTLS` ni `AUTH`**, et les
    /// refuse : c'est le seul défaut qui ne mente pas.
    #[must_use]
    pub fn with_capabilities(mut self, capabilities: Capabilities) -> Self {
        self.capabilities = capabilities;
        self
    }

    /// Ce que l'appelant sait conduire.
    #[must_use]
    pub fn capabilities(&self) -> Capabilities {
        self.capabilities
    }

    /// Déclare ce que la session doit faire du verdict SPF.
    ///
    /// Sans cet appel, elle **ne demande aucune vérification** : c'est le seul
    /// défaut qui ne suppose rien de la boucle.
    #[must_use]
    pub fn with_sender_policy(mut self, sender_policy: SenderPolicy) -> Self {
        self.sender_policy = sender_policy;
        self
    }

    /// Ce que la session fait du verdict SPF.
    #[must_use]
    pub fn sender_policy(&self) -> SenderPolicy {
        self.sender_policy
    }

    /// Le nom que le serveur annonce.
    #[must_use]
    pub fn domain(&self) -> &'a [u8] {
        self.domain
    }

    /// Le nombre maximal de destinataires par transaction.
    ///
    /// La RFC 5321 §4.5.3.1.8 fixe **100 comme minimum à accepter** ; en faire un
    /// maximum est un choix, et c'est celui de C7.
    #[must_use]
    pub fn max_recipients(&self) -> usize {
        self.max_recipients
    }

    /// La taille maximale d'un message, annoncée par `SIZE` (RFC 1870).
    #[must_use]
    pub fn max_message_octets(&self) -> u64 {
        self.max_message_octets
    }

    /// Les bornes du décodeur de commandes.
    #[must_use]
    pub fn limits(&self) -> &Limits {
        &self.limits
    }
}

#[cfg(test)]
mod tests {
    use super::{Capabilities, Config, SenderPolicy};
    use crate::Error;
    use ams_proto_smtp::Limits;

    #[test]
    fn une_configuration_ordinaire_se_construit() {
        let config = Config::new(b"mail.example.com", 100, 10_485_760, Limits::DEFAULT)
            .expect("configurable");
        assert_eq!(config.domain(), b"mail.example.com");
        assert_eq!(config.max_recipients(), 100);
        assert_eq!(config.max_message_octets(), 10_485_760);
        assert_eq!(config.limits(), &Limits::DEFAULT);
        // Le défaut n'annonce rien : un serveur n'offre que ce que quelqu'un a
        // déclaré savoir faire.
        assert_eq!(config.capabilities(), Capabilities::default());
        assert!(!config.capabilities().starttls);
        assert!(!config.capabilities().auth);
    }

    #[test]
    fn les_capacites_se_declarent_explicitement() {
        let config = Config::new(b"example.com", 1, 1, Limits::DEFAULT)
            .expect("configurable")
            .with_capabilities(Capabilities {
                starttls: true,
                auth: false,
            });
        assert!(config.capabilities().starttls);
        assert!(!config.capabilities().auth);
        assert!(!std::format!("{:?}", config.capabilities()).is_empty());
        assert_ne!(
            config.capabilities(),
            Capabilities {
                starttls: true,
                auth: true
            }
        );
    }

    #[test]
    fn un_litteral_d_adresse_est_un_nom_de_serveur_licite() {
        // RFC 5321 §4.1.3 : c'est ce que fait un hôte qui n'a pas de nom.
        assert!(Config::new(b"[192.0.2.1]", 100, 1024, Limits::DEFAULT).is_ok());
    }

    #[test]
    fn un_domaine_de_serveur_invalide_empeche_de_demarrer() {
        // Un serveur qui se nomme mal le fait dans CHAQUE bannière : le
        // découvrir en production coûte plus cher que de refuser de démarrer.
        assert_eq!(
            Config::new(b"-pas-un-domaine-", 100, 1024, Limits::DEFAULT),
            Err(Error::ServerDomainInvalid(
                ams_proto_smtp::Error::MalformedDomain
            ))
        );
    }

    #[test]
    fn une_configuration_se_copie_et_se_debogue() {
        let config = Config::new(b"example.com", 1, 1, Limits::DEFAULT).expect("configurable");
        let copie = config;
        assert_eq!(copie.domain(), config.domain());
        assert!(!std::format!("{config:?}").is_empty());
    }

    #[test]
    fn sans_declaration_aucune_verification_n_est_demandee() {
        // La session ne réclame que ce que quelqu'un a déclaré savoir faire :
        // demander une résolution DNS à une boucle qui n'en fait pas ferait
        // attendre pour rien.
        let config = Config::new(b"exemple.test", 10, 1024, Limits::DEFAULT).expect("valide");
        assert_eq!(config.sender_policy(), SenderPolicy::Ignore);
        assert_eq!(SenderPolicy::default(), SenderPolicy::Ignore);

        for politique in [
            SenderPolicy::Ignore,
            SenderPolicy::Observe,
            SenderPolicy::Enforce,
        ] {
            let regle = config.with_sender_policy(politique);
            assert_eq!(regle.sender_policy(), politique);
            assert!(!std::format!("{politique:?}").is_empty());
        }
        assert_ne!(SenderPolicy::Observe, SenderPolicy::Enforce);
    }
}
