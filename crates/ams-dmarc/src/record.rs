//! L'enregistrement `_dmarc` (RFC 7489 §6.3).

use crate::Error;
use crate::alignment::Alignment;
use crate::evaluate::Verdict;
use crate::tag::{Tag, Tags};

/// Ce qu'un domaine demande qu'on fasse d'un message non aligné (§6.3, `p=`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Policy {
    /// Rien — mais qu'on le lui rapporte.
    ///
    /// **C'est une politique, pas une absence de politique.** Un domaine qui
    /// publie `p=none` demande des rapports avant de durcir : lui refuser du
    /// courrier reviendrait à décider à sa place.
    #[default]
    None,
    /// Traiter le message comme suspect — le classer, l'étiqueter.
    Quarantine,
    /// Le refuser.
    Reject,
}

impl Policy {
    /// Lit un `p=` ou un `sp=`.
    ///
    /// # Errors
    ///
    /// [`Error::UnknownPolicy`]. **On ne se rabat pas sur `none`** : une
    /// politique qu'on ne comprend pas n'est pas une absence de politique, et
    /// choisir à la place de celui qui l'a écrite est exactement ce que DMARC
    /// existe pour éviter.
    pub fn parse(valeur: &[u8]) -> Result<Self, Error> {
        if valeur.eq_ignore_ascii_case(b"none") {
            return Ok(Self::None);
        }
        if valeur.eq_ignore_ascii_case(b"quarantine") {
            return Ok(Self::Quarantine);
        }
        if valeur.eq_ignore_ascii_case(b"reject") {
            return Ok(Self::Reject);
        }
        Err(Error::UnknownPolicy)
    }

    /// Le mot, tel qu'il s'écrit dans un enregistrement.
    #[must_use]
    pub fn name(self) -> &'static [u8] {
        match self {
            Self::None => b"none",
            Self::Quarantine => b"quarantine",
            Self::Reject => b"reject",
        }
    }
}

/// Quand un domaine veut un rapport d'échec (§6.3, `fo=`).
///
/// # Quatre demandes, et elles se cumulent
///
/// La valeur est une liste séparée par des deux-points : `fo=1:d:s` demande les
/// trois. Ce n'est pas un choix entre quatre modes, c'est un ensemble.
///
/// **Le défaut est le plus étroit**, et c'est voulu : sans `fo=`, un domaine ne
/// reçoit un rapport que si RIEN n'a réussi. Un domaine qui veut davantage le
/// demande — et un receveur qui en enverrait davantage sans qu'on le lui demande
/// enverrait du courrier que personne n'attend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FailureOptions {
    /// `0` : quand **aucun** mécanisme n'a produit de réussite alignée.
    pub all_failed: bool,
    /// `1` : quand **l'un** des deux n'a pas produit de réussite alignée.
    pub any_failed: bool,
    /// `d` : quand une signature DKIM était fausse, alignée ou non.
    pub dkim_broken: bool,
    /// `s` : quand SPF a rendu autre chose que `pass`, aligné ou non.
    pub spf_broken: bool,
}

impl Default for FailureOptions {
    fn default() -> Self {
        // §6.3 : en l'absence de `fo=`, c'est `0`.
        Self {
            all_failed: true,
            any_failed: false,
            dkim_broken: false,
            spf_broken: false,
        }
    }
}

impl FailureOptions {
    /// Lit un `fo=`.
    ///
    /// # Errors
    ///
    /// [`Error::UnknownFailureOption`] si une valeur n'est ni `0`, ni `1`, ni
    /// `d`, ni `s`. **On ne se rabat pas sur le défaut** : un domaine qui
    /// demande quelque chose qu'on ne comprend pas ne demande pas « ce qui était
    /// prévu par défaut », et lui envoyer autre chose que ce qu'il a écrit est
    /// exactement ce qu'on évite partout ailleurs ici.
    pub fn parse(valeur: &[u8]) -> Result<Self, Error> {
        let mut options = Self {
            all_failed: false,
            any_failed: false,
            dkim_broken: false,
            spf_broken: false,
        };
        // `split` rend toujours au moins un morceau, fût-il vide : un `fo=`
        // sans valeur tombe donc dans le bras qui refuse, sans qu'on ait à
        // écrire une garde de plus pour le cas vide.
        for morceau in valeur.split(|octet| *octet == b':') {
            let morceau = morceau.trim_ascii();
            match morceau {
                b"0" => options.all_failed = true,
                b"1" => options.any_failed = true,
                b"d" | b"D" => options.dkim_broken = true,
                b"s" | b"S" => options.spf_broken = true,
                _ => return Err(Error::UnknownFailureOption),
            }
        }
        Ok(options)
    }

    /// Un rapport d'échec est-il demandé pour ce message ?
    ///
    /// `dkim` et `spf` disent si chaque mécanisme a produit une réussite
    /// **alignée** ; `dkim_broken` et `spf_broken` disent s'il a échoué en
    /// lui-même, alignement mis à part.
    #[must_use]
    pub fn wants(self, dkim: Verdict, spf: Verdict, dkim_broken: bool, spf_broken: bool) -> bool {
        let aucun = dkim == Verdict::Fail && spf == Verdict::Fail;
        let au_moins_un = dkim == Verdict::Fail || spf == Verdict::Fail;
        (self.all_failed && aucun)
            || (self.any_failed && au_moins_un)
            || (self.dkim_broken && dkim_broken)
            || (self.spf_broken && spf_broken)
    }
}

/// La forme demandée pour les rapports d'échec (§6.3, `rf=`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ReportFormat {
    /// `afrf` — RFC 6591, la seule forme définie.
    #[default]
    Afrf,
}

impl ReportFormat {
    /// Lit un `rf=`.
    ///
    /// # Errors
    ///
    /// [`Error::UnknownReportFormat`]. Une seule forme est définie ; en
    /// composer une autre au jugé donnerait un document que le destinataire ne
    /// saurait pas lire, et qu'il jetterait sans le dire.
    pub fn parse(valeur: &[u8]) -> Result<Self, Error> {
        for morceau in valeur.split(|octet| *octet == b':') {
            if !morceau.trim_ascii().eq_ignore_ascii_case(b"afrf") {
                return Err(Error::UnknownReportFormat);
            }
        }
        Ok(Self::Afrf)
    }
}

/// Un enregistrement DMARC, lu et vérifié dans sa cohérence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Record<'a> {
    /// `p=` — ce qu'on demande pour le domaine lui-même.
    pub policy: Policy,
    /// `sp=` — ce qu'on demande pour ses sous-domaines, si c'est autre chose.
    ///
    /// Absent, les sous-domaines suivent `p=` (§6.3).
    pub subdomain_policy: Option<Policy>,
    /// `adkim=` — comment le domaine signataire doit s'aligner.
    pub dkim_alignment: Alignment,
    /// `aspf=` — comment le domaine de l'enveloppe doit s'aligner.
    pub spf_alignment: Alignment,
    /// `pct=` — sur quelle part des messages appliquer la politique.
    pub percent: u8,
    /// `rua=` — où envoyer les rapports agrégés, tel quel.
    pub aggregate_reports: Option<&'a [u8]>,
    /// `ruf=` — où envoyer les rapports d'échec, tel quel.
    pub failure_reports: Option<&'a [u8]>,
    /// `ri=` — l'intervalle demandé entre deux rapports agrégés, en secondes.
    pub report_interval: u32,
    /// `fo=` — quand ce domaine veut un rapport d'échec.
    pub failure_options: FailureOptions,
    /// `rf=` — sous quelle forme il le veut.
    pub failure_format: ReportFormat,
}

impl<'a> Record<'a> {
    /// Lit un enregistrement.
    ///
    /// # Ce qui le fait écarter
    ///
    /// - **`v=DMARC1` absent ou pas en premier.** §6.3 l'exige, et c'est ce qui
    ///   permet de distinguer un enregistrement DMARC d'un `TXT` qui parle
    ///   d'autre chose sans lire le reste.
    /// - **`p=` absent.** Un enregistrement qui ne demande rien n'est pas une
    ///   politique (§6.6.3).
    /// - **Une valeur qu'on ne comprend pas.** Appliquer « ce qu'on en a
    ///   compris » ferait rejeter du courrier au nom d'une politique que
    ///   personne n'a écrite.
    ///
    /// # Errors
    ///
    /// Voir [`Error`]. Toutes valent « pas de politique » pour l'appelant.
    pub fn parse(txt: &'a [u8]) -> Result<Self, Error> {
        let mut etiquettes = Tags::new(txt);
        // LA VERSION VIENT EN PREMIER, et c'est vérifié comme tel.
        let premiere = etiquettes.next().ok_or(Error::NotDmarc)??;
        if !premiere.name.eq_ignore_ascii_case(b"v")
            || !premiere.value.eq_ignore_ascii_case(b"DMARC1")
        {
            return Err(Error::NotDmarc);
        }

        let mut politique: Option<Policy> = None;
        let mut sous_politique: Option<Policy> = None;
        let mut alignement_dkim: Option<Alignment> = None;
        let mut alignement_spf: Option<Alignment> = None;
        let mut pourcentage: Option<u8> = None;
        let mut agreges: Option<&[u8]> = None;
        let mut echecs: Option<&[u8]> = None;
        let mut intervalle: Option<u32> = None;
        let mut options: Option<FailureOptions> = None;
        let mut forme: Option<ReportFormat> = None;

        for etiquette in etiquettes {
            let Tag { name, value } = etiquette?;
            // Les noms d'étiquette sont insensibles à la casse (§6.4).
            match () {
                () if name.eq_ignore_ascii_case(b"p") => {
                    poser(&mut politique, Policy::parse(value)?)?;
                }
                () if name.eq_ignore_ascii_case(b"sp") => {
                    poser(&mut sous_politique, Policy::parse(value)?)?;
                }
                () if name.eq_ignore_ascii_case(b"adkim") => {
                    poser(&mut alignement_dkim, Alignment::parse(value)?)?;
                }
                () if name.eq_ignore_ascii_case(b"aspf") => {
                    poser(&mut alignement_spf, Alignment::parse(value)?)?;
                }
                () if name.eq_ignore_ascii_case(b"pct") => {
                    poser(&mut pourcentage, pourcent(value)?)?;
                }
                () if name.eq_ignore_ascii_case(b"rua") => poser(&mut agreges, value)?,
                () if name.eq_ignore_ascii_case(b"ruf") => poser(&mut echecs, value)?,
                () if name.eq_ignore_ascii_case(b"ri") => poser(&mut intervalle, nombre(value)?)?,
                () if name.eq_ignore_ascii_case(b"fo") => {
                    poser(&mut options, FailureOptions::parse(value)?)?;
                }
                () if name.eq_ignore_ascii_case(b"rf") => {
                    poser(&mut forme, ReportFormat::parse(value)?)?;
                }
                // §6.3 : les étiquettes inconnues s'ignorent.
                () => {}
            }
        }

        Ok(Self {
            policy: politique.ok_or(Error::MissingPolicy)?,
            subdomain_policy: sous_politique,
            dkim_alignment: alignement_dkim.unwrap_or_default(),
            spf_alignment: alignement_spf.unwrap_or_default(),
            // Le défaut est 100 : sans `pct=`, la politique s'applique à tout.
            percent: pourcentage.unwrap_or(100),
            aggregate_reports: agreges,
            failure_reports: echecs,
            // Le défaut est 86 400 secondes, soit un jour (§6.3).
            report_interval: intervalle.unwrap_or(86_400),
            failure_options: options.unwrap_or_default(),
            failure_format: forme.unwrap_or_default(),
        })
    }

    /// La politique qui s'applique à un message, selon d'où il vient.
    ///
    /// Un message dont le `From:` est un **sous-domaine** de celui qui publie
    /// suit `sp=` s'il existe, et `p=` sinon (§6.3). Sans cette distinction, un
    /// domaine qui protège ses sous-domaines autrement que lui-même ne serait
    /// pas entendu.
    #[must_use]
    pub fn applicable(&self, sur_un_sous_domaine: bool) -> Policy {
        match (sur_un_sous_domaine, self.subdomain_policy) {
            (true, Some(sienne)) => sienne,
            _ => self.policy,
        }
    }
}

/// Pose une valeur, ou dit qu'elle l'était déjà.
fn poser<T>(place: &mut Option<T>, valeur: T) -> Result<(), Error> {
    if place.is_some() {
        return Err(Error::DuplicateTag);
    }
    *place = Some(valeur);
    Ok(())
}

/// Lit un pourcentage : un entier de 0 à 100.
fn pourcent(valeur: &[u8]) -> Result<u8, Error> {
    let total = nombre(valeur).map_err(|_| Error::MalformedPercent)?;
    u8::try_from(total)
        .ok()
        .filter(|part| *part <= 100)
        .ok_or(Error::MalformedPercent)
}

/// Lit un entier décimal.
fn nombre(valeur: &[u8]) -> Result<u32, Error> {
    if valeur.is_empty() {
        return Err(Error::MalformedInterval);
    }
    let mut total = 0_u32;
    for octet in valeur {
        if !octet.is_ascii_digit() {
            return Err(Error::MalformedInterval);
        }
        let chiffre = u32::from(octet.wrapping_sub(b'0'));
        // Un débordement n'est pas une grande valeur : un intervalle qui
        // repartirait de zéro ferait demander des rapports à chaque seconde.
        total = total
            .checked_mul(10)
            .and_then(|dizaines| dizaines.checked_add(chiffre))
            .ok_or(Error::MalformedInterval)?;
    }
    Ok(total)
}

/// La longueur d'un nom de politique : `_dmarc.` et un domaine.
pub const POLICY_NAME_MAX: usize = 7 + 255;

/// Écrit le nom où se cherche la politique d'un domaine (§6.6.3).
///
/// # La recherche a DEUX temps, et l'appelant les conduit
///
/// On cherche d'abord sous le domaine du `From:`. S'il n'y a rien, on recommence
/// sous son **domaine organisationnel** — et c'est alors `sp=` qui s'applique,
/// puisque le message vient d'un sous-domaine. Cette fonction écrit un nom ; le
/// second appel, s'il faut, appartient à celui qui résout.
///
/// # Errors
///
/// [`Error::DomainTooLong`] ou [`Error::BufferTooSmall`].
pub fn policy_name<'b>(domaine: &[u8], sortie: &'b mut [u8]) -> Result<&'b [u8], Error> {
    if domaine.len() > 255 {
        return Err(Error::DomainTooLong);
    }
    let fin = domaine.len().saturating_add(7);
    let place = sortie.get_mut(..fin).ok_or(Error::BufferTooSmall)?;
    let (prefixe, reste) = place.split_at_mut(7);
    prefixe.copy_from_slice(b"_dmarc.");
    reste.copy_from_slice(domaine);
    sortie.get(..fin).ok_or(Error::BufferTooSmall)
}

#[cfg(test)]
mod tests;
