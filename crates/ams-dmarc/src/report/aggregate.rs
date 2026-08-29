//! Le rapport agrégé (RFC 7489 §7.2 et annexe C), **composé sans allouer**.
//!
//! # À quoi sert un rapport, et pourquoi il faut l'écrire
//!
//! Un domaine qui publie `p=none` demande à voir avant de durcir : *qui émet en
//! mon nom, et est-ce que cela s'aligne ?* Sans rapports, il durcit à l'aveugle
//! — et durcir à l'aveugle veut dire qu'un jour son propre courrier légitime,
//! celui d'un prestataire oublié, se met à être refusé partout. **C'est la
//! raison pour laquelle tant de domaines restent à `p=none` pour toujours.**
//!
//! Le rapport est un dénombrement, pas une copie : on n'y met jamais un
//! message, seulement combien il en est venu de telle adresse, et ce qu'on en a
//! conclu. Une journée d'un domaine tient en quelques lignes.
//!
//! # CE QUI ENTRE ICI VIENT DU RÉSEAU
//!
//! Le `header_from` est ce que le message prétendait ; l'adresse d'enveloppe est
//! ce que le pair a dicté. Les recopier tels quels dans du XML serait rouvrir,
//! au format d'à côté, la faille qu'on ferme partout ailleurs : un `<` bien
//! placé, et celui qu'on rapporte écrit le rapport.
//!
//! Deux règles, et aucune n'est facultative :
//!
//! 1. **Tout octet hors de l'ASCII imprimable fait REFUSER le rapport.** Pas de
//!    remplacement silencieux : un rapport dont on ne sait pas ce qu'il dit ne
//!    vaut pas mieux que pas de rapport.
//! 2. **Les cinq octets qui ont un sens en XML** — `&`, `<`, `>`, `"` et `'` —
//!    sortent sous forme d'entités.
//!
//! # Le tampon est celui de l'appelant, et il peut ne pas suffire
//!
//! C1 : cette crate n'alloue pas. [`begin`] écrit dans le tampon qu'on lui
//! donne, et rend [`Error::BufferTooSmall`] quand il déborde — à l'appelant de
//! recommencer plus grand. Un rapport d'une journée pour un domaine ordinaire
//! tient dans quelques kibioctets ; ce n'est pas une raison pour le supposer.

use core::net::IpAddr;

use crate::alignment::Alignment;
use crate::record::Policy;
use crate::{Error, Verdict};

/// Qui a composé ce rapport, et sur quelle période (§7.2, `ReportMetadataType`).
#[derive(Debug, Clone, Copy)]
pub struct Metadata<'a> {
    /// Le nom du receveur qui rapporte.
    pub org_name: &'a [u8],
    /// L'adresse à laquelle le joindre.
    pub email: &'a [u8],
    /// De quoi le joindre autrement, s'il y a lieu.
    pub extra_contact: Option<&'a [u8]>,
    /// L'identifiant du rapport, unique chez celui qui l'émet.
    pub report_id: &'a [u8],
    /// Le début de la période, en secondes depuis l'époque.
    pub begin: u64,
    /// Sa fin.
    pub end: u64,
}

/// La politique telle qu'elle a été LUE (§7.2, `PolicyPublishedType`).
///
/// **C'est ce qu'on a vu, pas ce qu'on croit qu'il fallait.** Le domaine
/// compare ce champ à ce qu'il a publié : s'ils diffèrent, c'est que sa zone ne
/// dit pas ce qu'il pense, et c'est précisément ce qu'il veut apprendre.
#[derive(Debug, Clone, Copy)]
pub struct Published<'a> {
    /// Le domaine dont la politique a été appliquée.
    pub domain: &'a [u8],
    /// `adkim=`.
    pub dkim_alignment: Alignment,
    /// `aspf=`.
    pub spf_alignment: Alignment,
    /// `p=`.
    pub policy: Policy,
    /// `sp=`, s'il était là.
    pub subdomain_policy: Option<Policy>,
    /// `pct=`.
    pub percent: u8,
}

/// Ce que DKIM a rendu pour une signature (§7.2, `DKIMResultType`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DkimAuthResult {
    /// Le message ne portait pas de signature.
    None,
    /// Une signature a été vérifiée.
    Pass,
    /// Une signature était fausse.
    Fail,
    /// Une signature refusée par politique locale.
    Policy,
    /// Ni vraie ni fausse.
    Neutral,
    /// La clé n'a pas pu être atteinte.
    TempError,
    /// La signature était irrecevable.
    PermError,
}

impl DkimAuthResult {
    fn name(self) -> &'static [u8] {
        match self {
            Self::None => b"none",
            Self::Pass => b"pass",
            Self::Fail => b"fail",
            Self::Policy => b"policy",
            Self::Neutral => b"neutral",
            Self::TempError => b"temperror",
            Self::PermError => b"permerror",
        }
    }
}

/// Ce que SPF a rendu (§7.2, `SPFResultType`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpfAuthResult {
    /// Le domaine ne publie rien.
    None,
    /// Il ne se prononce pas.
    Neutral,
    /// L'adresse était autorisée.
    Pass,
    /// Elle ne l'était pas.
    Fail,
    /// Elle ne l'était pas, mais le domaine n'insiste pas.
    SoftFail,
    /// La résolution a échoué passagèrement.
    TempError,
    /// L'enregistrement est irrecevable.
    PermError,
}

impl SpfAuthResult {
    fn name(self) -> &'static [u8] {
        match self {
            Self::None => b"none",
            Self::Neutral => b"neutral",
            Self::Pass => b"pass",
            Self::Fail => b"fail",
            Self::SoftFail => b"softfail",
            Self::TempError => b"temperror",
            Self::PermError => b"permerror",
        }
    }
}

/// Laquelle des deux identités SPF a été vérifiée (§7.2, `SPFDomainScope`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpfScope {
    /// Le nom annoncé au `HELO` — c'est le cas de l'expéditeur nul.
    Helo,
    /// L'expéditeur d'enveloppe.
    MailFrom,
}

impl SpfScope {
    fn name(self) -> &'static [u8] {
        match self {
            Self::Helo => b"helo",
            Self::MailFrom => b"mfrom",
        }
    }
}

/// Une signature DKIM et ce qu'elle a donné.
#[derive(Debug, Clone, Copy)]
pub struct DkimAuth<'a> {
    /// Le domaine signataire (`d=`).
    pub domain: &'a [u8],
    /// Le sélecteur (`s=`), s'il est connu.
    pub selector: Option<&'a [u8]>,
    /// Le résultat.
    pub result: DkimAuthResult,
}

/// L'évaluation SPF et ce qu'elle a donné.
#[derive(Debug, Clone, Copy)]
pub struct SpfAuth<'a> {
    /// Le domaine vérifié.
    pub domain: &'a [u8],
    /// Laquelle des deux identités.
    pub scope: SpfScope,
    /// Le résultat.
    pub result: SpfAuthResult,
}

/// Une ligne du rapport : tous les messages qui se ressemblaient (§7.2).
///
/// # Ce qui fait qu'une ligne est UNE ligne
///
/// Deux messages se comptent ensemble quand tout ce qui figure ici est le
/// même — même source, même conclusion, mêmes identifiants. C'est ce qui fait
/// tenir une journée en quelques lignes, et c'est aussi ce qui garantit qu'un
/// rapport ne dit rien d'un message en particulier.
#[derive(Debug, Clone, Copy)]
pub struct Row<'a> {
    /// L'adresse d'où le courrier est venu.
    pub source_ip: IpAddr,
    /// Combien de messages.
    pub count: u32,
    /// Ce qu'on a FAIT — qui n'est pas toujours ce qui était demandé, `pct=`
    /// pouvant en dispenser. Les trois mots sont ceux de [`Policy`], et le
    /// rapport les écrit de la même façon.
    pub disposition: Policy,
    /// DKIM s'alignait-il ?
    pub dkim: Verdict,
    /// SPF s'alignait-il ?
    pub spf: Verdict,
    /// Le domaine du `From:`.
    pub header_from: &'a [u8],
    /// Le domaine de l'enveloppe, s'il y en avait un.
    pub envelope_from: Option<&'a [u8]>,
    /// Le destinataire d'enveloppe, si on le rapporte.
    pub envelope_to: Option<&'a [u8]>,
    /// Les signatures examinées.
    pub dkim_auth: &'a [DkimAuth<'a>],
    /// L'évaluation SPF. **Elle n'est pas optionnelle** : SPF rend toujours un
    /// verdict, fût-il `none`, et le schéma en attend un.
    pub spf_auth: SpfAuth<'a>,
}

/// Un rapport ouvert, en attente de ses lignes.
///
/// # Pourquoi l'ordre est dans les types
///
/// L'en-tête d'un rapport précède ses lignes, qui précèdent sa fermeture. Rien
/// n'oblige un appelant à s'en souvenir : [`begin`] est la seule façon d'obtenir
/// un `Records`, et [`Records::finish`] le consomme. **Une séquence fautive ne
/// compile pas** — c'est mieux qu'une garde qu'il faudrait tester.
#[derive(Debug)]
pub struct Records<'a> {
    plume: Plume<'a>,
    lignes: usize,
}

/// Ouvre un rapport : la déclaration XML, les métadonnées, la politique lue.
///
/// # Errors
///
/// [`Error::NotPrintable`] si une valeur porte un octet hors de l'ASCII
/// imprimable, [`Error::BufferTooSmall`] si `out` ne suffit pas.
pub fn begin<'b>(
    out: &'b mut [u8],
    metadata: &Metadata<'_>,
    published: &Published<'_>,
) -> Result<Records<'b>, Error> {
    let mut plume = Plume::neuve(out);
    plume.pousser(b"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<feedback>\n")?;
    plume.pousser(b"  <version>1.0</version>\n")?;

    plume.pousser(b"  <report_metadata>\n")?;
    plume.champ(b"    ", b"org_name", metadata.org_name)?;
    plume.champ(b"    ", b"email", metadata.email)?;
    if let Some(autre) = metadata.extra_contact {
        plume.champ(b"    ", b"extra_contact_info", autre)?;
    }
    plume.champ(b"    ", b"report_id", metadata.report_id)?;
    plume.pousser(b"    <date_range>\n")?;
    plume.nombre(b"      ", b"begin", metadata.begin)?;
    plume.nombre(b"      ", b"end", metadata.end)?;
    plume.pousser(b"    </date_range>\n  </report_metadata>\n")?;

    plume.pousser(b"  <policy_published>\n")?;
    plume.champ(b"    ", b"domain", published.domain)?;
    plume.champ(b"    ", b"adkim", published.dkim_alignment.name())?;
    plume.champ(b"    ", b"aspf", published.spf_alignment.name())?;
    plume.champ(b"    ", b"p", published.policy.name())?;
    if let Some(sienne) = published.subdomain_policy {
        plume.champ(b"    ", b"sp", sienne.name())?;
    }
    plume.nombre(b"    ", b"pct", u64::from(published.percent))?;
    plume.pousser(b"  </policy_published>\n")?;

    Ok(Records { plume, lignes: 0 })
}

impl<'a> Records<'a> {
    /// Ajoute une ligne.
    ///
    /// # Errors
    ///
    /// Comme [`begin`].
    pub fn record(&mut self, row: &Row<'_>) -> Result<(), Error> {
        self.plume.pousser(b"  <record>\n    <row>\n")?;
        self.plume.pousser(b"      <source_ip>")?;
        self.plume.adresse(row.source_ip)?;
        self.plume.pousser(b"</source_ip>\n")?;
        self.plume
            .nombre(b"      ", b"count", u64::from(row.count))?;
        self.plume.pousser(b"      <policy_evaluated>\n")?;
        self.plume
            .champ(b"        ", b"disposition", row.disposition.name())?;
        self.plume
            .champ(b"        ", b"dkim", mot_du_verdict(row.dkim))?;
        self.plume
            .champ(b"        ", b"spf", mot_du_verdict(row.spf))?;
        self.plume
            .pousser(b"      </policy_evaluated>\n    </row>\n")?;

        self.plume.pousser(b"    <identifiers>\n")?;
        if let Some(vers) = row.envelope_to {
            self.plume.champ(b"      ", b"envelope_to", vers)?;
        }
        if let Some(depuis) = row.envelope_from {
            self.plume.champ(b"      ", b"envelope_from", depuis)?;
        }
        self.plume
            .champ(b"      ", b"header_from", row.header_from)?;
        self.plume.pousser(b"    </identifiers>\n")?;

        self.plume.pousser(b"    <auth_results>\n")?;
        for signature in row.dkim_auth {
            self.plume.pousser(b"      <dkim>\n")?;
            self.plume.champ(b"        ", b"domain", signature.domain)?;
            if let Some(selecteur) = signature.selector {
                self.plume.champ(b"        ", b"selector", selecteur)?;
            }
            self.plume
                .champ(b"        ", b"result", signature.result.name())?;
            self.plume.pousser(b"      </dkim>\n")?;
        }
        self.plume.pousser(b"      <spf>\n")?;
        self.plume
            .champ(b"        ", b"domain", row.spf_auth.domain)?;
        self.plume
            .champ(b"        ", b"scope", row.spf_auth.scope.name())?;
        self.plume
            .champ(b"        ", b"result", row.spf_auth.result.name())?;
        self.plume
            .pousser(b"      </spf>\n    </auth_results>\n  </record>\n")?;

        self.lignes = self.lignes.saturating_add(1);
        Ok(())
    }

    /// Ferme le rapport et rend ce qui a été écrit.
    ///
    /// # UN RAPPORT SANS LIGNE N'EST PAS UN RAPPORT
    ///
    /// L'annexe C exige au moins un `record`. Un rapport vide ne serait pas
    /// « rien à signaler » : il serait un document invalide, que le destinataire
    /// jettera sans le dire. Mieux vaut ne pas l'envoyer, et le savoir ici.
    ///
    /// # Errors
    ///
    /// [`Error::EmptyReport`] si aucune ligne n'a été ajoutée,
    /// [`Error::BufferTooSmall`] si `out` ne suffit pas.
    pub fn finish(mut self) -> Result<&'a [u8], Error> {
        if self.lignes == 0 {
            return Err(Error::EmptyReport);
        }
        self.plume.pousser(b"</feedback>\n")?;
        Ok(self.plume.fini())
    }
}

/// Le mot qu'un verdict prend dans `policy_evaluated` (§7.2).
fn mot_du_verdict(verdict: Verdict) -> &'static [u8] {
    match verdict {
        Verdict::Pass => b"pass",
        Verdict::Fail => b"fail",
    }
}

/// De quoi écrire du XML dans le tampon d'autrui.
#[derive(Debug)]
struct Plume<'a> {
    out: &'a mut [u8],
    ecrits: usize,
    /// Ce qui a fait échouer une écriture passée par `core::fmt`, qui ne rend
    /// qu'une erreur sans cause.
    faute: Option<Error>,
}

impl core::fmt::Write for Plume<'_> {
    fn write_str(&mut self, morceau: &str) -> core::fmt::Result {
        match self.pousser(morceau.as_bytes()) {
            Ok(()) => Ok(()),
            Err(cause) => {
                self.faute = Some(cause);
                Err(core::fmt::Error)
            }
        }
    }
}

impl<'a> Plume<'a> {
    fn neuve(out: &'a mut [u8]) -> Self {
        Self {
            out,
            ecrits: 0,
            faute: None,
        }
    }

    fn pousser(&mut self, morceau: &[u8]) -> Result<(), Error> {
        let fin = self.ecrits.saturating_add(morceau.len());
        let place = self
            .out
            .get_mut(self.ecrits..fin)
            .ok_or(Error::BufferTooSmall)?;
        place.copy_from_slice(morceau);
        self.ecrits = fin;
        Ok(())
    }

    /// Un élément `<nom>valeur</nom>`, valeur échappée, précédé de son retrait.
    fn champ(&mut self, retrait: &[u8], nom: &[u8], valeur: &[u8]) -> Result<(), Error> {
        self.pousser(retrait)?;
        self.pousser(b"<")?;
        self.pousser(nom)?;
        self.pousser(b">")?;
        self.echapper(valeur)?;
        self.pousser(b"</")?;
        self.pousser(nom)?;
        self.pousser(b">\n")
    }

    /// Un élément dont la valeur est un nombre — rien à échapper.
    fn nombre(&mut self, retrait: &[u8], nom: &[u8], valeur: u64) -> Result<(), Error> {
        self.pousser(retrait)?;
        self.pousser(b"<")?;
        self.pousser(nom)?;
        self.pousser(b">")?;
        self.formater(format_args!("{valeur}"))?;
        self.pousser(b"</")?;
        self.pousser(nom)?;
        self.pousser(b">\n")
    }

    /// Écrit l'adresse du pair sous la forme de la bibliothèque standard.
    ///
    /// **On emprunte son `Display`** plutôt que d'en écrire un second : la forme
    /// abrégée d'une adresse IPv6 a ses règles (RFC 5952), et deux écritures
    /// d'une même adresse feraient deux lignes là où le rapport en veut une.
    fn adresse(&mut self, source: IpAddr) -> Result<(), Error> {
        self.formater(format_args!("{source}"))
    }

    fn formater(&mut self, morceaux: core::fmt::Arguments<'_>) -> Result<(), Error> {
        match core::fmt::write(self, morceaux) {
            Ok(()) => Ok(()),
            // `fmt::Error` ne dit rien ; la cause, elle, a été retenue.
            Err(_) => Err(self.faute.unwrap_or(Error::BufferTooSmall)),
        }
    }

    /// Écrit une valeur en rendant ses entités, et refuse ce qui n'est pas de
    /// l'ASCII imprimable.
    fn echapper(&mut self, valeur: &[u8]) -> Result<(), Error> {
        for octet in valeur {
            if !octet.is_ascii_graphic() && *octet != b' ' {
                return Err(Error::NotPrintable);
            }
            match *octet {
                b'&' => self.pousser(b"&amp;")?,
                b'<' => self.pousser(b"&lt;")?,
                b'>' => self.pousser(b"&gt;")?,
                b'"' => self.pousser(b"&quot;")?,
                b'\'' => self.pousser(b"&apos;")?,
                _ => self.pousser(core::slice::from_ref(octet))?,
            }
        }
        Ok(())
    }

    fn fini(self) -> &'a [u8] {
        self.out.get(..self.ecrits).unwrap_or_default()
    }
}

#[cfg(test)]
mod tests;
