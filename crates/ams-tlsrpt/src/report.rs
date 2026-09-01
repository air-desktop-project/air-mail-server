//! Le rapport lui-même : du JSON, écrit sans allouer (§4 de RFC 8460).
//!
//! # POURQUOI UN ÉCRIVAIN INCRÉMENTAL
//!
//! Un rapport porte une ligne par politique et une par type d'échec. Les
//! rassembler avant d'écrire demanderait une structure dont la taille suit ce
//! qu'on a observé — c'est-à-dire ce que des tiers ont fait —, et C3 interdit
//! qu'une entrée dicte la mémoire. On écrit donc au fil de l'eau, dans un tampon
//! que l'appelant a dimensionné.
//!
//! C'est la même forme que l'écrivain de rapports DMARC, et pour la même raison.
//!
//! # CE QU'UNE CHAÎNE JSON NE DOIT PAS PORTER
//!
//! Un guillemet ou une barre oblique inverse écrirait une structure à notre
//! place, dans un fichier qu'on compose et qu'on remet nous-mêmes. Les valeurs
//! viennent en partie de tiers : le nom d'un serveur `MX`, une politique qu'un
//! domaine a publiée. **On refuse plutôt que d'échapper** — un rapport qu'on ne
//! sait pas écrire ne vaut pas la peine d'être deviné.

use crate::Error;

/// D'où venait la politique appliquée (§4.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyType {
    /// Un `TLSA` (DANE, RFC 7672).
    Tlsa,
    /// Une politique MTA-STS (RFC 8461).
    Sts,
    /// Aucune : la remise était opportuniste.
    NoPolicyFound,
}

impl PolicyType {
    /// Le mot exact que §4.4 emploie.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Tlsa => "tlsa",
            Self::Sts => "sts",
            Self::NoPolicyFound => "no-policy-found",
        }
    }
}

/// Pourquoi une session a échoué (§4.3).
///
/// **LES MOTS SONT CEUX DE LA RFC, PAS LES NÔTRES.** Un rapport se lit par une
/// machine à l'autre bout, qui ne connaît que ceux-là.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResultType {
    /// Le pair n'a pas annoncé `STARTTLS`.
    StarttlsNotSupported,
    /// La poignée de main a échoué.
    ValidationFailure,
    /// Aucun `TLSA` n'a été satisfait.
    ValidationFailureDane,
    /// Le serveur n'est pas dans la politique MTA-STS.
    StsPolicyInvalid,
    /// La politique MTA-STS n'a pas pu être récupérée.
    StsPolicyFetchError,
    /// Le certificat ne porte pas le nom attendu.
    CertificateHostMismatch,
    /// Le certificat est expiré.
    CertificateExpired,
    /// Le certificat ne remonte à aucune autorité connue.
    CertificateNotTrusted,
}

impl ResultType {
    /// Le mot exact que §4.3 emploie.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::StarttlsNotSupported => "starttls-not-supported",
            Self::ValidationFailure => "validation-failure",
            Self::ValidationFailureDane => "dane-required",
            Self::StsPolicyInvalid => "sts-policy-invalid",
            Self::StsPolicyFetchError => "sts-policy-fetch-error",
            Self::CertificateHostMismatch => "certificate-host-mismatch",
            Self::CertificateExpired => "certificate-expired",
            Self::CertificateNotTrusted => "certificate-not-trusted",
        }
    }
}

/// L'en-tête d'un rapport (§4.1).
#[derive(Debug, Clone, Copy)]
pub struct Report<'a> {
    /// Le nom sous lequel ce receveur se présente.
    pub organization_name: &'a str,
    /// L'adresse à laquelle le joindre à propos d'un rapport.
    pub contact_info: &'a str,
    /// Ce qui distingue ce rapport des autres.
    pub report_id: &'a str,
    /// Le début de la période, en secondes depuis l'époque.
    pub start: u64,
    /// Sa fin.
    pub end: u64,
}

/// Une politique rapportée (§4.4).
#[derive(Debug, Clone, Copy)]
pub struct Policy<'a, 'm> {
    /// D'où elle venait.
    pub policy_type: PolicyType,
    /// Le domaine dont c'est la politique.
    pub policy_domain: &'a str,
    /// Les lignes de la politique, telles qu'elle les portait.
    ///
    /// Vide pour `no-policy-found`, qui n'en a aucune.
    pub policy_strings: &'m [&'a str],
    /// Les serveurs que la politique nomme.
    pub mx_hosts: &'m [&'a str],
}

/// Le décompte d'une politique (§4.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Summary {
    /// Sessions qui ont abouti.
    pub successful: u64,
    /// Sessions qui ont échoué.
    pub failed: u64,
}

/// Un échec, détaillé (§4.3).
#[derive(Debug, Clone, Copy)]
pub struct Failure<'a> {
    /// Pourquoi.
    pub result_type: ResultType,
    /// Notre adresse d'émission.
    ///
    /// **ELLE EST FACULTATIVE, ET ON L'ÉCRIT TOUT DE MÊME** : le destinataire la
    /// connaît déjà — c'est nous qui l'avons appelé — et elle lui permet de
    /// corréler avec ses propres journaux, ce qu'il attend d'un diagnostic.
    pub sending_mta_ip: &'a str,
    /// Le serveur qu'on cherchait à joindre.
    pub receiving_mx_hostname: &'a str,
    /// Combien de sessions ont échoué ainsi.
    pub failed_session_count: u64,
}

/// Un rapport en cours d'écriture.
pub struct Writing<'a> {
    plume: Plume<'a>,
    /// Combien de politiques ont été écrites.
    politiques: usize,
    /// Une politique est-elle ouverte, et combien d'échecs porte-t-elle ?
    echecs: Option<usize>,
}

/// Ouvre un rapport : l'en-tête, et le tableau des politiques.
///
/// # Errors
///
/// [`Error::NotPrintable`] si une valeur porte un octet qu'on refuse d'écrire
/// dans du JSON, [`Error::BufferTooSmall`] si `out` ne suffit pas.
pub fn begin<'b>(out: &'b mut [u8], report: &Report<'_>) -> Result<Writing<'b>, Error> {
    let mut plume = Plume::neuve(out);
    plume.pousser(b"{\"organization-name\":")?;
    plume.chaine(report.organization_name)?;
    plume.pousser(b",\"date-range\":{\"start-datetime\":")?;
    plume.horodatage(report.start)?;
    plume.pousser(b",\"end-datetime\":")?;
    plume.horodatage(report.end)?;
    plume.pousser(b"},\"contact-info\":")?;
    plume.chaine(report.contact_info)?;
    plume.pousser(b",\"report-id\":")?;
    plume.chaine(report.report_id)?;
    plume.pousser(b",\"policies\":[")?;
    Ok(Writing {
        plume,
        politiques: 0,
        echecs: None,
    })
}

impl<'a> Writing<'a> {
    /// Ouvre une politique, avec son décompte.
    ///
    /// # Errors
    ///
    /// Comme [`begin`].
    pub fn policy(&mut self, policy: &Policy<'_, '_>, summary: &Summary) -> Result<(), Error> {
        self.fermer_la_politique()?;
        if self.politiques > 0 {
            self.plume.pousser(b",")?;
        }
        self.politiques = self.politiques.saturating_add(1);
        self.plume.pousser(b"{\"policy\":{\"policy-type\":")?;
        self.plume.chaine(policy.policy_type.name())?;
        self.plume.pousser(b",\"policy-domain\":")?;
        self.plume.chaine(policy.policy_domain)?;
        if !policy.policy_strings.is_empty() {
            self.plume.pousser(b",\"policy-string\":")?;
            self.plume.liste(policy.policy_strings)?;
        }
        if !policy.mx_hosts.is_empty() {
            self.plume.pousser(b",\"mx-host\":")?;
            self.plume.liste(policy.mx_hosts)?;
        }
        self.plume
            .pousser(b"},\"summary\":{\"total-successful-session-count\":")?;
        self.plume.nombre(summary.successful)?;
        self.plume.pousser(b",\"total-failure-session-count\":")?;
        self.plume.nombre(summary.failed)?;
        self.plume.pousser(b"},\"failure-details\":[")?;
        self.echecs = Some(0);
        Ok(())
    }

    /// Ajoute un échec à la politique ouverte.
    ///
    /// **SANS POLITIQUE OUVERTE, IL N'Y A RIEN À DÉTAILLER**, et l'appel est
    /// sans effet : un échec qui flotterait hors d'une politique n'aurait aucun
    /// sens pour qui le lit.
    ///
    /// # Errors
    ///
    /// Comme [`begin`].
    pub fn failure(&mut self, failure: &Failure<'_>) -> Result<(), Error> {
        let Some(combien) = self.echecs else {
            return Ok(());
        };
        if combien > 0 {
            self.plume.pousser(b",")?;
        }
        self.echecs = Some(combien.saturating_add(1));
        self.plume.pousser(b"{\"result-type\":")?;
        self.plume.chaine(failure.result_type.name())?;
        self.plume.pousser(b",\"sending-mta-ip\":")?;
        self.plume.chaine(failure.sending_mta_ip)?;
        self.plume.pousser(b",\"receiving-mx-hostname\":")?;
        self.plume.chaine(failure.receiving_mx_hostname)?;
        self.plume.pousser(b",\"failed-session-count\":")?;
        self.plume.nombre(failure.failed_session_count)?;
        self.plume.pousser(b"}")?;
        Ok(())
    }

    /// Ferme le rapport, et rend ce qui a été écrit.
    ///
    /// # Errors
    ///
    /// Comme [`begin`].
    pub fn finish(mut self) -> Result<&'a [u8], Error> {
        self.fermer_la_politique()?;
        self.plume.pousser(b"]}")?;
        Ok(self.plume.fini())
    }

    /// Ferme la politique ouverte, s'il y en a une.
    fn fermer_la_politique(&mut self) -> Result<(), Error> {
        if self.echecs.take().is_some() {
            self.plume.pousser(b"]}")?;
        }
        Ok(())
    }
}

/// Combien de chiffres décimaux `valeur` occupe.
fn largeur_de(valeur: u64) -> usize {
    let mut combien = 1_usize;
    let mut reste = valeur;
    while reste >= 10 {
        reste /= 10;
        combien = combien.saturating_add(1);
    }
    combien
}

/// De quoi écrire dans un tampon, sans jamais déborder.
struct Plume<'a> {
    sortie: &'a mut [u8],
    ecrits: usize,
}

impl<'a> Plume<'a> {
    fn neuve(sortie: &'a mut [u8]) -> Self {
        Self { sortie, ecrits: 0 }
    }

    fn pousser(&mut self, morceau: &[u8]) -> Result<(), Error> {
        let fin = self.ecrits.saturating_add(morceau.len());
        let place = self
            .sortie
            .get_mut(self.ecrits..fin)
            .ok_or(Error::BufferTooSmall)?;
        place.copy_from_slice(morceau);
        self.ecrits = fin;
        Ok(())
    }

    /// Une chaîne JSON, guillemets compris.
    ///
    /// **ON REFUSE PLUTÔT QUE D'ÉCHAPPER.** Une valeur qui porterait un
    /// guillemet, une barre oblique inverse ou un caractère de contrôle
    /// écrirait une structure à notre place ; l'échapper marcherait, mais
    /// laisserait ce rapport porter des octets qu'on n'a pas voulus.
    fn chaine(&mut self, valeur: &str) -> Result<(), Error> {
        if !valeur
            .bytes()
            .all(|octet| octet.is_ascii_graphic() || octet == b' ')
            || valeur.contains('"')
            || valeur.contains('\\')
        {
            return Err(Error::NotPrintable);
        }
        self.pousser(b"\"")?;
        self.pousser(valeur.as_bytes())?;
        self.pousser(b"\"")
    }

    /// Un tableau de chaînes.
    fn liste(&mut self, valeurs: &[&str]) -> Result<(), Error> {
        self.pousser(b"[")?;
        for (rang, valeur) in valeurs.iter().enumerate() {
            if rang > 0 {
                self.pousser(b",")?;
            }
            self.chaine(valeur)?;
        }
        self.pousser(b"]")
    }

    /// Un entier.
    fn nombre(&mut self, valeur: u64) -> Result<(), Error> {
        let largeur = largeur_de(valeur);
        let mut chiffres = [b'0'; 20];
        // La tranche fait exactement `largeur` octets, et `rev()` écrit des
        // unités vers le poids fort sans qu'aucun index ne soit calculé.
        let place = chiffres.get_mut(..largeur).unwrap_or_default();
        let mut reste = valeur;
        for octet in place.iter_mut().rev() {
            *octet = b'0'.saturating_add(u8::try_from(reste % 10).unwrap_or(0));
            reste /= 10;
        }
        self.pousser(chiffres.get(..largeur).unwrap_or_default())
    }

    /// Un horodatage `date-time` de RFC 3339, entre guillemets.
    ///
    /// **§4.1 EXIGE CETTE FORME**, et non un nombre de secondes : un rapport
    /// dont les dates ne se lisent pas est un rapport qu'on jette.
    ///
    /// Le calendrier vient de `ams-mime`, qui l'écrit déjà pour les dates de
    /// message : **deux crates qui compteraient les jours différemment
    /// finiraient par ne pas dater la même chose de la même façon.**
    fn horodatage(&mut self, secondes: u64) -> Result<(), Error> {
        let mut place = [0_u8; ams_mime::RFC3339_MAX];
        // `RFC3339_MAX` est, PAR DÉFINITION, la place que cet horodatage
        // demande : l'écriture ne peut pas manquer, et `unwrap_or_default`
        // porte cette certitude plutôt qu'une garde que rien n'atteindrait.
        let ecrit = ams_mime::write_rfc3339(secondes, &mut place).unwrap_or_default();
        self.pousser(b"\"")?;
        self.pousser(ecrit)?;
        self.pousser(b"\"")
    }

    fn fini(self) -> &'a [u8] {
        // `pousser` n'a jamais écrit au-delà de `ecrits`.
        self.sortie.get(..self.ecrits).unwrap_or_default()
    }
}

#[cfg(test)]
mod tests;
