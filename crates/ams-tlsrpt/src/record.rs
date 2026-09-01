//! L'enregistrement `_smtp._tls.<domaine>` (§3 de RFC 8460).

use crate::Error;

/// Combien de destinations un enregistrement peut nommer.
///
/// **C'EST UNE BORNE DE C3.** L'enregistrement vient du domaine qu'on rapporte,
/// et sans borne il dicterait combien de messages on émet pour lui — c'est-à-dire
/// exactement l'amplification que la vérification de §3 existe pour fermer.
pub const RUA_MAX: usize = 8;

/// La longueur maximale d'une destination.
const URI_MAX: usize = 512;

/// Par où un rapport peut partir (§3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    /// `mailto:` — le rapport part par courrier.
    Mailto,
    /// `https:` — le rapport se POSTE.
    Https,
}

/// Une destination de rapport.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Destination<'a> {
    transport: Transport,
    /// L'adresse ou l'URL, sans son schéma.
    cible: &'a str,
}

impl Destination<'static> {
    /// Une case vide, dont l'appelant garnit sa place.
    ///
    /// **CE N'EST PAS UNE DESTINATION**, et [`parse_record`] n'en rend jamais :
    /// c'est le remplissage d'un tableau que cette crate ne peut pas allouer.
    pub const EMPTY: Self = Self {
        transport: Transport::Mailto,
        cible: "",
    };
}

impl<'a> Destination<'a> {
    /// Par où ce rapport partirait.
    #[must_use]
    pub fn transport(self) -> Transport {
        self.transport
    }

    /// L'adresse de courrier, ou l'URL entière.
    #[must_use]
    pub fn target(self) -> &'a str {
        self.cible
    }

    /// Le domaine de cette destination.
    ///
    /// C'est lui qu'on confronte au domaine rapporté pour savoir s'il faut une
    /// vérification (§3), et lui qu'on interroge pour l'obtenir.
    ///
    /// `None` quand on ne sait pas l'en tirer : la destination est alors
    /// inutilisable, ce qui vaut mieux que de deviner un domaine et d'y envoyer
    /// du courrier.
    #[must_use]
    pub fn domain(self) -> Option<&'a str> {
        match self.transport {
            // `boite@domaine` — le DERNIER `@` sépare, parce qu'une partie
            // locale citée peut en porter.
            Transport::Mailto => self.cible.rsplit_once('@').map(|(_, apres)| apres),
            // `https://autorité/chemin` — l'autorité s'arrête au premier `/`.
            Transport::Https => {
                // Seule `destination` construit un `Https`, et elle a déjà
                // vérifié le préfixe : `unwrap_or_default` porte cette
                // certitude, et l'autorité vide qui suivrait est refusée plus
                // bas de toute façon.
                let apres = self.cible.strip_prefix("https://").unwrap_or_default();
                let autorite = apres.split('/').next().unwrap_or(apres);
                // **NI UTILISATEUR NI PORT** : `https://x@evil.test/` désignerait
                // `evil.test`, et le lire comme `x` ferait vérifier le mauvais
                // domaine. On refuse plutôt que de choisir.
                if autorite.contains('@') || autorite.contains(':') {
                    return None;
                }
                domaine_recevable(autorite).then_some(autorite)
            }
        }
    }
}

/// Lit un enregistrement `_smtp._tls`.
///
/// Les destinations sont écrites dans `place`, dont la longueur borne ce qu'on
/// accepte de lire. **Un enregistrement plus garni que `place` est REFUSÉ**, et
/// non tronqué : un domaine qui nomme deux destinations les veut toutes les
/// deux.
///
/// # Errors
///
/// [`Error::BadRecord`] si `v=TLSRPTv1` manque ou n'est pas en tête, si aucune
/// destination n'est utilisable, ou s'il y en a plus que [`RUA_MAX`].
pub fn parse_record<'a, 'r>(
    txt: &'a str,
    place: &'r mut [Destination<'a>],
) -> Result<&'r [Destination<'a>], Error> {
    let mut champs = txt.split(';').map(str::trim);
    // §3 : `v=TLSRPTv1` VIENT EN PREMIER. `split` rend toujours au moins un
    // morceau : ce premier appel ne peut pas manquer.
    if champs.next().unwrap_or_default() != "v=TLSRPTv1" {
        return Err(Error::BadRecord);
    }

    let mut combien = 0_usize;
    for champ in champs {
        let Some(liste) = champ.strip_prefix("rua=") else {
            // **UNE CLEF QU'ON NE CONNAÎT PAS SE SAUTE** : §3 réserve
            // l'extension, et un champ de demain ne doit pas faire perdre les
            // destinations d'aujourd'hui.
            continue;
        };
        // §3 : les destinations d'un même `rua` sont séparées par des virgules.
        for brute in liste.split(',') {
            let brute = brute.trim();
            let Some(destination) = destination(brute) else {
                // **UNE DESTINATION QU'ON NE SAIT PAS LIRE FAIT TOUT REFUSER.**
                // L'écarter en silence enverrait le rapport à moins de monde que
                // le domaine ne l'a demandé, et rien ne le lui dirait.
                return Err(Error::BadRecord);
            };
            let case = place.get_mut(combien).ok_or(Error::BadRecord)?;
            *case = destination;
            combien = combien.saturating_add(1);
        }
    }

    if combien == 0 || combien > RUA_MAX {
        return Err(Error::BadRecord);
    }
    // `place` a été garni de zéro à `combien` : la découpe ne peut pas manquer.
    Ok(place.get(..combien).unwrap_or_default())
}

/// Ce nom peut-il être un domaine ?
///
/// **UNE DESTINATION SERT DEUX FOIS** : on interroge son domaine pour savoir
/// s'il nous autorise (§3), puis on lui remet le rapport. Un « domaine » qui
/// porte une barre oblique ou une espace ne fait ni l'un ni l'autre, et le
/// laisser passer donnerait une destination qu'on croit joignable.
fn domaine_recevable(domaine: &str) -> bool {
    !domaine.is_empty()
        && domaine.len() <= 253
        && !domaine.starts_with('.')
        && !domaine.ends_with('.')
        && domaine
            .bytes()
            .all(|octet| octet.is_ascii_alphanumeric() || octet == b'-' || octet == b'.')
}

/// Une destination, lue depuis son URI.
fn destination(brute: &str) -> Option<Destination<'_>> {
    if brute.is_empty() || brute.len() > URI_MAX || !brute.is_ascii() {
        return None;
    }
    if let Some(adresse) = brute.strip_prefix("mailto:") {
        // Une adresse de courrier, et rien d'autre : pas d'espace, pas de
        // `CRLF`, une arobase.
        if adresse.is_empty() || !adresse.bytes().all(|octet| octet.is_ascii_graphic()) {
            return None;
        }
        // **ET SON DOMAINE DOIT EN ÊTRE UN.** `mailto:a@b/c` rendait `b/c`
        // comme domaine : de quoi interroger un nom qui n'en est pas un, et
        // remettre à un domaine qui n'existe pas. Trouvé par `fuzz_ams_tlsrpt`.
        let (_, domaine) = adresse.rsplit_once('@')?;
        if !domaine_recevable(domaine) {
            return None;
        }
        return Some(Destination {
            transport: Transport::Mailto,
            cible: adresse,
        });
    }
    if brute.starts_with("https://") {
        if !brute.bytes().all(|octet| octet.is_ascii_graphic()) {
            return None;
        }
        let destination = Destination {
            transport: Transport::Https,
            cible: brute,
        };
        // **UNE URL DONT ON NE SAIT PAS TIRER LE DOMAINE EST INUTILISABLE** :
        // sans lui, on ne saurait ni vérifier la destination ni la joindre.
        destination.domain()?;
        return Some(destination);
    }
    // **`http://` N'EST PAS `https://`** (§3), et le reste non plus.
    None
}

#[cfg(test)]
mod tests;
