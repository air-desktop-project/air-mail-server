//! L'en-tête `Authentication-Results` (RFC 8601), composé sans allouer.
//!
//! # POURQUOI CET EN-TÊTE, ALORS QUE `Received-SPF` EXISTE DÉJÀ
//!
//! `Received-SPF` ne dit qu'une chose sur trois. Un serveur qui vérifie SPF,
//! DKIM **et** DMARC n'a aucun moyen normalisé de dire ce qu'il a trouvé — et
//! c'est le seul moyen pour un utilisateur POP3, qui ne voit ni dossier ni
//! mot-clef, de savoir qu'un message a échoué et de le filtrer chez lui.
//!
//! # CE QUI EST ÉCRIT EST CE QU'ON A FAIT, JAMAIS CE QU'ON AURAIT VOULU
//!
//! Un `dkim=pass` écrit sans avoir vérifié serait pire qu'un en-tête absent :
//! c'est un en-tête que les filtres croient. Ce module n'écrit donc que ce que
//! l'appelant lui donne, et l'appelant ne lui donne que ce qu'il a mesuré. Quand
//! rien n'a été vérifié, §2.2 prévoit le mot `none`, et c'est celui-là qu'on
//! écrit.
//!
//! # UN EN-TÊTE QU'ON NE SAIT PAS ÉCRIRE NE S'ÉCRIT PAS
//!
//! Les domaines et les sélecteurs viennent du MESSAGE, c'est-à-dire de
//! n'importe qui. Un `CRLF` glissé dedans écrirait des en-têtes à notre place,
//! dans un en-tête que les filtres du destinataire croient sur parole. On refuse
//! de composer plutôt que d'échapper : le message part alors sans trace, ce qui
//! ne ment sur rien.
//!
//! # CE QUE CE MODULE NE FAIT PAS, ET QUI COMPTE
//!
//! §7.1 demande de RETIRER les `Authentication-Results` déjà présents qui
//! portent notre propre identifiant : sans quoi un pair en fabrique un, et un
//! lecteur naïf le croit. **Ce n'est pas fait ici, et ce n'est pas faisable
//! ici** : la boucle diffuse le message au fil de l'eau, et filtrer son bloc
//! d'en-tête demanderait de le rassembler — exactement ce que C3 refuse.
//!
//! Ce qui protège à la place : le nôtre est TOUJOURS LE PREMIER, écrit avant que
//! le moindre octet du pair n'atteigne la boîte. §5 dit au lecteur de prendre
//! celui du haut, et c'est celui-là.

use crate::Error;

/// Combien de signatures DKIM un en-tête peut rapporter.
///
/// **C'EST UNE BORNE DE C3** : un message peut porter autant de signatures que
/// son auteur en a écrites, et un en-tête qui les rapporterait toutes croîtrait
/// avec ce qu'un tiers décide.
pub const DKIM_MAX: usize = 8;

/// Ce que SPF a rendu (§2.7.2 de RFC 8601).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpfResult {
    /// Rien n'a été vérifié.
    None,
    /// Le domaine ne dit rien de cette adresse.
    Neutral,
    /// L'adresse est autorisée.
    Pass,
    /// Elle ne l'est pas.
    Fail,
    /// Elle ne l'est probablement pas.
    SoftFail,
    /// La résolution a échoué. **Temporaire.**
    TempError,
    /// La politique est illisible. **Définitif.**
    PermError,
}

impl SpfResult {
    /// Le mot exact que §2.7.2 emploie.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Neutral => "neutral",
            Self::Pass => "pass",
            Self::Fail => "fail",
            Self::SoftFail => "softfail",
            Self::TempError => "temperror",
            Self::PermError => "permerror",
        }
    }
}

/// Ce qu'une signature DKIM a rendu (§2.7.1 de RFC 8601).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DkimResult {
    /// Le message n'était pas signé.
    None,
    /// La signature est bonne.
    Pass,
    /// Elle ne l'est pas.
    Fail,
    /// Elle est syntaxiquement valable, mais rejetée par notre politique.
    Policy,
    /// On ne sait pas conclure — un algorithme qu'on ne connaît pas.
    Neutral,
    /// La clé n'a pas pu être récupérée. **Temporaire.**
    TempError,
    /// La signature est illisible. **Définitif.**
    PermError,
}

impl DkimResult {
    /// Le mot exact que §2.7.1 emploie.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Pass => "pass",
            Self::Fail => "fail",
            Self::Policy => "policy",
            Self::Neutral => "neutral",
            Self::TempError => "temperror",
            Self::PermError => "permerror",
        }
    }
}

/// Ce que DMARC a rendu (§2.7.5 de RFC 8601, et RFC 7489).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DmarcResult {
    /// Le domaine ne publie pas de politique.
    None,
    /// Le message est aligné.
    Pass,
    /// Il ne l'est pas.
    Fail,
    /// La résolution a échoué. **Temporaire.**
    TempError,
    /// L'enregistrement est illisible. **Définitif.**
    PermError,
}

impl DmarcResult {
    /// Le mot exact que §2.7.5 emploie.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Pass => "pass",
            Self::Fail => "fail",
            Self::TempError => "temperror",
            Self::PermError => "permerror",
        }
    }
}

/// Sur quelle identité SPF a porté (§2.7.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpfIdentity {
    /// `smtp.mailfrom` — le chemin de retour.
    MailFrom,
    /// `smtp.helo` — le nom annoncé, quand le chemin de retour est nul.
    Helo,
}

impl SpfIdentity {
    /// Le nom de propriété que §2.7.2 emploie.
    #[must_use]
    pub fn property(self) -> &'static str {
        match self {
            Self::MailFrom => "smtp.mailfrom",
            Self::Helo => "smtp.helo",
        }
    }
}

/// Ce qu'une signature DKIM a donné, et de qui elle vient.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DkimSeen<'a> {
    /// Le verdict.
    pub result: DkimResult,
    /// `d=` — le domaine signataire.
    pub domain: &'a [u8],
    /// `s=` — le sélecteur.
    pub selector: &'a [u8],
}

/// Ce que ce serveur a vérifié, et ce qu'il a trouvé.
#[derive(Debug, Clone, Copy)]
pub struct Authentication<'a, 'd> {
    /// L'identifiant de CE serveur — celui qui authentifie l'en-tête lui-même.
    ///
    /// **Sans lui, l'en-tête ne veut rien dire** : un lecteur doit pouvoir
    /// distinguer ce que son propre serveur a écrit de ce qu'un pair prétend.
    pub serv_id: &'a [u8],
    /// Ce que SPF a rendu, sur quelle identité, et pour quel domaine.
    pub spf: Option<(SpfResult, SpfIdentity, &'a [u8])>,
    /// Ce que chaque signature a rendu.
    pub dkim: &'d [DkimSeen<'a>],
    /// Ce que DMARC a rendu, et pour le domaine de quel `From:`.
    pub dmarc: Option<(DmarcResult, &'a [u8])>,
}

/// Ce qu'il faut au plus pour écrire cet en-tête.
#[must_use]
pub fn authres_max(authentication: &Authentication<'_, '_>) -> usize {
    // Le nom du champ, les mots des verdicts, les noms de propriété, les
    // séparateurs et les plis : deux cents octets suffisent, et l'on majore.
    const ENVELOPPE: usize = 256;
    // Ce qu'une signature occupe au plus, hors ses valeurs.
    const PAR_SIGNATURE: usize = 48;
    let signatures = authentication.dkim.iter().fold(0_usize, |total, vue| {
        total
            .saturating_add(PAR_SIGNATURE)
            .saturating_add(vue.domain.len())
            .saturating_add(vue.selector.len())
    });
    ENVELOPPE
        .saturating_add(authentication.serv_id.len())
        .saturating_add(
            authentication
                .spf
                .map_or(0, |(_, _, domaine)| domaine.len()),
        )
        .saturating_add(authentication.dmarc.map_or(0, |(_, domaine)| domaine.len()))
        .saturating_add(signatures)
}

/// Compose l'en-tête, terminé par `CRLF`.
///
/// # Errors
///
/// [`Error::NotPrintable`] si une valeur porte un octet qu'on refuse d'écrire
/// dans un en-tête, [`Error::TooManyFields`] s'il y a plus de [`DKIM_MAX`]
/// signatures, [`Error::BufferTooSmall`] si `sortie` ne suffit pas — voir
/// [`authres_max`].
pub fn write_authres<'b>(
    sortie: &'b mut [u8],
    authentication: &Authentication<'_, '_>,
) -> Result<&'b [u8], Error> {
    if authentication.dkim.len() > DKIM_MAX {
        return Err(Error::TooManyFields { limit: DKIM_MAX });
    }
    if !jeton_recevable(authentication.serv_id) {
        return Err(Error::NotPrintable);
    }
    for vue in authentication.dkim {
        if !jeton_recevable(vue.domain) || !jeton_recevable(vue.selector) {
            return Err(Error::NotPrintable);
        }
    }
    if let Some((_, _, domaine)) = authentication.spf
        && !jeton_recevable(domaine)
    {
        return Err(Error::NotPrintable);
    }
    if let Some((_, domaine)) = authentication.dmarc
        && !jeton_recevable(domaine)
    {
        return Err(Error::NotPrintable);
    }

    let mut ecrits = pousser(sortie, 0, b"Authentication-Results: ")?;
    ecrits = pousser(sortie, ecrits, authentication.serv_id)?;

    // §2.2 : quand RIEN n'a été vérifié, le mot est `none`. Écrire un
    // identifiant seul ne serait pas un en-tête valable.
    if authentication.spf.is_none()
        && authentication.dmarc.is_none()
        && authentication.dkim.is_empty()
    {
        ecrits = pousser(sortie, ecrits, b"; none\r\n")?;
        return sortie.get(..ecrits).ok_or(Error::BufferTooSmall);
    }

    // **CHAQUE RÉSULTAT SUR SA LIGNE**, repliée par un blanc de continuation.
    // §2.2 de RFC 5322 borne une ligne à 998 octets, et huit signatures avec
    // leurs domaines la dépasseraient.
    if let Some((resultat, identite, domaine)) = authentication.spf {
        ecrits = pousser(sortie, ecrits, b";\r\n\tspf=")?;
        ecrits = pousser(sortie, ecrits, resultat.name().as_bytes())?;
        ecrits = pousser(sortie, ecrits, b" ")?;
        ecrits = pousser(sortie, ecrits, identite.property().as_bytes())?;
        ecrits = pousser(sortie, ecrits, b"=")?;
        ecrits = pousser(sortie, ecrits, domaine)?;
    }
    for vue in authentication.dkim {
        ecrits = pousser(sortie, ecrits, b";\r\n\tdkim=")?;
        ecrits = pousser(sortie, ecrits, vue.result.name().as_bytes())?;
        ecrits = pousser(sortie, ecrits, b" header.d=")?;
        ecrits = pousser(sortie, ecrits, vue.domain)?;
        ecrits = pousser(sortie, ecrits, b" header.s=")?;
        ecrits = pousser(sortie, ecrits, vue.selector)?;
    }
    if let Some((resultat, domaine)) = authentication.dmarc {
        ecrits = pousser(sortie, ecrits, b";\r\n\tdmarc=")?;
        ecrits = pousser(sortie, ecrits, resultat.name().as_bytes())?;
        ecrits = pousser(sortie, ecrits, b" header.from=")?;
        ecrits = pousser(sortie, ecrits, domaine)?;
    }
    ecrits = pousser(sortie, ecrits, b"\r\n")?;
    sortie.get(..ecrits).ok_or(Error::BufferTooSmall)
}

/// La place qu'on RÉSERVE en tête d'un message pour cet en-tête.
///
/// # POURQUOI UNE PLACE RÉSERVÉE, ET NON UN MESSAGE RASSEMBLÉ
///
/// Un en-tête de trace doit précéder ce que le pair écrit. Or DKIM ne se juge
/// qu'une fois le CORPS entier lu — son condensat porte dessus — et DMARC en
/// dépend. Le verdict arrive donc APRÈS que le message a été diffusé.
///
/// Rassembler le message pour l'écrire ensuite dans le bon ordre coûterait sa
/// taille en mémoire, par connexion : mille connexions de dix mébioctets, c'est
/// exactement ce que C3 interdit. Le recopier après coup coûterait une seconde
/// écriture disque par message.
///
/// **On réserve donc mille vingt-quatre octets en tête**, et l'on y écrit
/// l'en-tête une fois le verdict connu. Le surcoût est constant, borné, et payé
/// une fois par message plutôt qu'à proportion de sa taille.
///
/// La valeur : deux domaines de deux cent cinquante-trois octets — la borne d'un
/// nom — plus les mots des verdicts et les noms de propriété tiennent sous six
/// cents. Le reste est pour les signatures.
pub const AUTHRES_RESERVE: usize = 1024;

/// Compose l'en-tête en occupant EXACTEMENT `sortie.len()` octets.
///
/// # LE REMPLISSAGE EST UN PLI, PAS UN BOURRAGE
///
/// §3.2.2 de RFC 5322 : une ligne d'en-tête se continue par un `CRLF` suivi d'un
/// blanc. Le remplissage est donc une continuation de ce champ, faite d'espaces
/// — pas un octet qui traîne, et rien qu'un lecteur puisse prendre pour autre
/// chose.
///
/// # CE QUI NE TIENT PAS EST LAISSÉ, ET C'EST DIT
///
/// Les signatures sont la seule partie dont la longueur suit ce qu'un tiers a
/// écrit. Celles qui ne tiennent pas dans la place réservée ne sont pas
/// rapportées — l'alternative serait une place qui croît avec ce qu'un pair
/// décide. SPF et DMARC, eux, tiennent toujours : leurs domaines sont bornés.
///
/// # Errors
///
/// Comme [`write_authres`], plus [`Error::BufferTooSmall`] si `sortie` est trop
/// petite pour même l'en-tête minimal.
pub fn write_authres_padded<'b>(
    sortie: &'b mut [u8],
    authentication: &Authentication<'_, '_>,
) -> Result<&'b [u8], Error> {
    // On compose SANS le `CRLF` final, pour pouvoir replier derrière.
    let mut essai = *authentication;
    loop {
        match mesurer(sortie, &essai) {
            // Il faut la place du pli : `CRLF`, un blanc, et le `CRLF` final.
            Ok(ecrits) if ecrits.saturating_add(5) <= sortie.len() => {
                return Ok(remplir(sortie, ecrits));
            }
            // Trop long, d'un cheveu ou de beaucoup : dans les deux cas, on
            // retire une signature et l'on recommence.
            Ok(_) | Err(Error::BufferTooSmall) => {}
            // **UNE VALEUR QU'ON REFUSE D'ÉCRIRE N'EST PAS UNE QUESTION DE
            // PLACE**, et retirer des signatures n'y changerait rien.
            Err(autre) => return Err(autre),
        }
        // **ON RETIRE UNE SIGNATURE, ET L'ON RECOMMENCE.** C'est la seule partie
        // dont la longueur ne dépend pas de nous.
        let Some((_, reste)) = essai.dkim.split_last() else {
            // Sans signature, il ne reste que SPF et DMARC, qui tiennent
            // toujours : la place offerte est simplement trop petite.
            return Err(Error::BufferTooSmall);
        };
        essai.dkim = reste;
    }
}

/// Écrit l'en-tête sans son `CRLF` final, et rend ce qu'il occupe.
fn mesurer(sortie: &mut [u8], authentication: &Authentication<'_, '_>) -> Result<usize, Error> {
    let ecrit = write_authres(sortie, authentication)?.len();
    // `write_authres` termine toujours par un `CRLF`.
    Ok(ecrit.saturating_sub(2))
}

/// Replie le champ jusqu'à occuper toute la place.
///
/// **AUCUNE GARDE ICI**, et ce n'est pas une négligence : l'appelant a vérifié
/// qu'il reste au moins cinq octets — de quoi ouvrir la continuation et fermer
/// le champ. Les trois écritures ci-dessous ne peuvent donc pas manquer, et une
/// garde qui le dirait serait une garde que rien n'atteindrait.
fn remplir(sortie: &mut [u8], ecrits: usize) -> &[u8] {
    let voulu = sortie.len();
    // D'abord des espaces partout où il reste de la place…
    for octet in sortie.get_mut(ecrits..).unwrap_or_default() {
        *octet = b' ';
    }
    // …puis le pli qui ouvre la continuation…
    for (place, octet) in sortie
        .get_mut(ecrits..)
        .unwrap_or_default()
        .iter_mut()
        .zip(b"\r\n ")
    {
        *place = *octet;
    }
    // …et le terminateur du champ, tout au bout.
    for (place, octet) in sortie
        .get_mut(voulu.saturating_sub(2)..)
        .unwrap_or_default()
        .iter_mut()
        .zip(b"\r\n")
    {
        *place = *octet;
    }
    sortie
}

/// Cette valeur peut-elle s'écrire dans un en-tête ?
///
/// De l'ASCII imprimable **sans espace**, ni vide, et pas plus long qu'un nom de
/// domaine. Un espace couperait la propriété en deux, et un `CRLF` écrirait un
/// en-tête à notre place.
fn jeton_recevable(valeur: &[u8]) -> bool {
    !valeur.is_empty()
        && valeur.len() <= 253
        && valeur.iter().all(u8::is_ascii_graphic)
        // **NI POINT-VIRGULE**, qui sépare les résultats : un domaine qui en
        // porterait un ferait lire deux résultats là où on en écrit un.
        && !valeur.contains(&b';')
}

/// Recopie `morceau`, et rend le nouveau compte.
fn pousser(sortie: &mut [u8], ecrits: usize, morceau: &[u8]) -> Result<usize, Error> {
    let fin = ecrits.saturating_add(morceau.len());
    let place = sortie.get_mut(ecrits..fin).ok_or(Error::BufferTooSmall)?;
    place.copy_from_slice(morceau);
    Ok(fin)
}

#[cfg(test)]
mod tests;
