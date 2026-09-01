//! La politique elle-même (§3.2 de RFC 8461).

use crate::Error;

/// Combien de motifs `mx` une politique peut porter.
///
/// **C'EST UNE BORNE DE C3.** Le texte vient d'un serveur qu'on ne choisit pas ;
/// sans borne, il dicterait combien de mémoire on lui consacre. Soixante-quatre
/// couvrent large — les plus gros opérateurs en publient une poignée.
pub const MX_MAX: usize = 64;

/// La plus longue valeur de `max_age` que §3.2 permet : un peu plus d'un an.
const MAX_AGE_MAX: u32 = 31_557_600;

/// La plus longue ligne qu'on accepte de lire.
const LINE_MAX: usize = 512;

/// Ce que le domaine demande qu'on fasse de sa politique (§3.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// **`enforce`** : on n'émet pas si le pair ne satisfait pas la politique.
    Enforce,
    /// **`testing`** : on évalue, on consigne, et l'on remet quand même.
    ///
    /// C'est ce que dit un domaine qui s'installe : « ne refusez pas encore ».
    /// L'ignorer priverait l'exploitant de la seule trace qui lui dirait que ses
    /// remises échoueront une fois la politique durcie.
    Testing,
    /// **`none`** : le domaine retire sa politique.
    ///
    /// Ce n'est PAS la même chose qu'une absence de politique : c'est la façon
    /// de dire « oubliez celle que vous avez en cache », et un domaine qui se
    /// retire doit publier ceci pendant au moins `max_age` avant de tout retirer.
    None,
}

/// La politique d'un domaine.
///
/// # ELLE EMPRUNTE SON TEXTE
///
/// Les motifs `mx` sont des tranches du texte, écrites dans une place que
/// l'appelant fournit : cette crate n'alloue pas. Le texte vient d'un serveur
/// qu'on ne choisit pas, et rien ici ne croît avec ce qu'il répond (C3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Policy<'a, 'r> {
    mode: Mode,
    mx: &'r [&'a str],
    max_age: u32,
}

impl<'a, 'r> Policy<'a, 'r> {
    /// Ce que le domaine demande.
    #[must_use]
    pub fn mode(&self) -> Mode {
        self.mode
    }

    /// Les motifs `mx`, dans l'ordre où le domaine les a écrits.
    #[must_use]
    pub fn mx(&self) -> &'r [&'a str] {
        self.mx
    }

    /// Combien de secondes cette politique reste valable après sa récupération.
    #[must_use]
    pub fn max_age(&self) -> u32 {
        self.max_age
    }

    /// Ce nom de serveur est-il permis par la politique ?
    ///
    /// # LE JOKER COUVRE EXACTEMENT UNE ÉTIQUETTE
    ///
    /// §4.1 renvoie à §6.4.3 de RFC 6125 : `*.example.com` couvre
    /// `mx1.example.com` et **pas** `a.b.example.com`. Le laisser couvrir
    /// davantage reviendrait à laisser un sous-domaine délégué à un tiers
    /// recevoir le courrier du domaine entier.
    ///
    /// Le joker n'est permis **qu'en tête**, et il doit couvrir une étiquette
    /// entière : `m*.example.com` n'est pas un motif.
    ///
    /// La comparaison ignore la casse : un nom de domaine n'en a pas.
    #[must_use]
    pub fn allows(&self, host: &str) -> bool {
        self.mx.iter().any(|motif| correspond(motif, host))
    }
}

/// Lit une politique.
///
/// Les motifs `mx` sont écrits dans `place`, dont la longueur borne ce qu'on
/// accepte de lire. **Une politique plus garnie que `place` est REFUSÉE**, et
/// non tronquée : une politique amputée d'un de ses serveurs ferait refuser une
/// remise parfaitement légitime.
///
/// # Errors
///
/// [`Error::BadVersion`], [`Error::BadMode`], [`Error::BadMx`],
/// [`Error::BadMaxAge`], [`Error::Malformed`].
pub fn parse_policy<'a, 'r>(
    texte: &'a str,
    place: &'r mut [&'a str],
) -> Result<Policy<'a, 'r>, Error> {
    let mut version = false;
    let mut mode: Option<Mode> = None;
    let mut max_age: Option<u32> = None;
    let mut combien = 0_usize;

    // §3.2 : les lignes se terminent par `CRLF` ou par `LF`. `lines` défait les
    // deux, et c'est ici la bonne lecture : ce texte n'est pas un protocole de
    // fil, c'est un fichier qu'un humain a écrit.
    for ligne in texte.lines() {
        let ligne = ligne.trim();
        if ligne.is_empty() {
            continue;
        }
        if ligne.len() > LINE_MAX {
            return Err(Error::Malformed);
        }
        let (clef, valeur) = ligne.split_once(':').ok_or(Error::Malformed)?;
        let clef = clef.trim();
        let valeur = valeur.trim();
        match clef {
            // **UNE VERSION QU'ON NE CONNAÎT PAS SE REFUSE**, et ne se devine
            // pas : une politique de demain pourrait dire l'inverse.
            "version" => {
                if valeur != "STSv1" {
                    return Err(Error::BadVersion);
                }
                version = true;
            }
            "mode" => {
                mode = Some(match valeur {
                    "enforce" => Mode::Enforce,
                    "testing" => Mode::Testing,
                    "none" => Mode::None,
                    _ => return Err(Error::BadMode),
                });
            }
            "max_age" => {
                let lue: u32 = valeur.parse().map_err(|_| Error::BadMaxAge)?;
                if lue == 0 || lue > MAX_AGE_MAX {
                    return Err(Error::BadMaxAge);
                }
                max_age = Some(lue);
            }
            "mx" => {
                if !motif_recevable(valeur) {
                    return Err(Error::BadMx);
                }
                let case = place.get_mut(combien).ok_or(Error::BadMx)?;
                *case = valeur;
                combien = combien.saturating_add(1);
            }
            // **UNE CLEF QU'ON NE CONNAÎT PAS SE SAUTE**, et ne fait pas refuser
            // la politique : §3.2 réserve l'extension, et un champ de demain ne
            // doit pas arrêter le courrier d'aujourd'hui.
            _ => {}
        }
    }

    if !version {
        return Err(Error::BadVersion);
    }
    let mode = mode.ok_or(Error::BadMode)?;
    let max_age = max_age.ok_or(Error::BadMaxAge)?;
    let mx = place.get(..combien).unwrap_or_default();
    // **UNE POLITIQUE `none` N'A PAS BESOIN DE `mx`**, et c'est le seul cas :
    // elle dit « oubliez ce que vous aviez », et il n'y a alors rien à permettre.
    if mx.is_empty() && mode != Mode::None {
        return Err(Error::BadMx);
    }
    if combien > MX_MAX {
        return Err(Error::BadMx);
    }
    Ok(Policy { mode, mx, max_age })
}

/// Ce motif est-il écrivable, et lisible ?
///
/// Un nom de domaine, éventuellement précédé de `*.`. Ni vide, ni plus long
/// qu'un nom de domaine, et rien d'autre que des lettres, des chiffres, des
/// tirets et des points.
fn motif_recevable(motif: &str) -> bool {
    let nom = motif.strip_prefix("*.").unwrap_or(motif);
    !nom.is_empty()
        && nom.len() <= 253
        && !nom.starts_with('.')
        && !nom.ends_with('.')
        && nom
            .bytes()
            .all(|octet| octet.is_ascii_alphanumeric() || octet == b'-' || octet == b'.')
}

/// Ce nom correspond-il à ce motif ?
fn correspond(motif: &str, host: &str) -> bool {
    let Some(suffixe) = motif.strip_prefix("*.") else {
        return motif.eq_ignore_ascii_case(host);
    };
    // Le joker couvre EXACTEMENT une étiquette : ce qui reste après elle doit
    // être le suffixe, et l'étiquette elle-même ne doit pas être vide ni porter
    // de point.
    let Some((etiquette, reste)) = host.split_once('.') else {
        return false;
    };
    !etiquette.is_empty() && reste.eq_ignore_ascii_case(suffixe)
}

#[cfg(test)]
mod tests;
