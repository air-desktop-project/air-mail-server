//! Ce qu'un serveur annonce et ce qu'il borne.

use ams_proto_smtp::{ClientId, Limits};

use crate::Error;

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
        })
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
    use super::Config;
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
}
