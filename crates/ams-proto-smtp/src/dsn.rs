//! Les paramètres de RFC 3461 — les rapports de remise, demandés par le pair.
//!
//! # CE QUI EST HOSTILE ICI
//!
//! Tout. `ENVID` et `ORCPT` sont recopiés dans un rapport que NOUS composons et
//! que NOUS remettons : ce sont les seules valeurs de cette RFC qui traversent
//! le serveur pour ressortir sous notre nom. Un `CRLF` glissé dedans écrirait
//! des champs de statut à notre place, dans un message que le client de notre
//! utilisateur lira comme un rapport officiel — la même faille que le
//! `Diagnostic-Code` d'un serveur inconnu, par une autre porte.
//!
//! C'est pourquoi §4 les encode en **xtext** : de l'ASCII visible, sans `+` ni
//! `=`, et tout le reste écrit `+XX` en hexadécimal. Le décodage a lieu ici, une
//! fois, et ce qui n'est pas un xtext valable est refusé — pas corrigé.
//!
//! # `NOTIFY=NEVER` EST LE PLUS DANGEREUX DES QUATRE, ET C'EST CONTRE-INTUITIF
//!
//! Il ne demande rien : il demande qu'on se TAISE. Un serveur qui l'accepte sans
//! l'honorer laisse un expéditeur croire qu'il n'aura pas de rapport — et un
//! serveur qui l'honore sans le comprendre se tait quand il aurait dû parler.
//! Les deux erreurs sont silencieuses, ce qui est exactement ce qui les rend
//! coûteuses.

use crate::Error;

/// La plus longue valeur d'`ENVID` (§4.4), une fois décodée.
pub const ENVID_MAX: usize = 100;

/// La plus longue valeur d'`ORCPT` (§4.2), une fois décodée.
///
/// Un type d'adresse, un point-virgule, et une adresse. La borne est celle d'un
/// chemin de RFC 5321 §4.5.3.1, plus la place du type.
pub const ORCPT_MAX: usize = 320;

/// Ce que le pair veut savoir du sort de son message (§4.1).
///
/// # `NEVER` N'EST PAS UN DRAPEAU DE PLUS
///
/// §4.1 l'exige : il ne se combine avec AUCUN autre. « Ne me dis rien, sauf en
/// cas de succès » n'est pas une demande cohérente, et l'accepter reviendrait à
/// choisir soi-même laquelle des deux moitiés honorer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Notify {
    /// Rien, jamais — et rien d'autre avec.
    never: bool,
    success: bool,
    failure: bool,
    delay: bool,
}

impl Notify {
    /// **`FAILURE` SEUL**, ce que §4.1 impose en l'absence du paramètre.
    ///
    /// Une constante plutôt qu'un seul `Default` : un tableau de valeurs par
    /// défaut se construit en `const`, et la session en tient un par
    /// destinataire.
    pub const DEFAUT: Self = Self {
        never: false,
        success: false,
        failure: true,
        delay: false,
    };
}

impl Default for Notify {
    /// **`FAILURE` SEUL**, ce que §4.1 impose en l'absence du paramètre.
    ///
    /// C'est le comportement de SMTP depuis toujours : on ne dit rien quand tout
    /// va bien, et on rend compte d'un échec.
    fn default() -> Self {
        Self::DEFAUT
    }
}

impl Notify {
    /// Le pair demande-t-il qu'on se taise, quoi qu'il arrive ?
    #[must_use]
    pub const fn never(self) -> bool {
        self.never
    }

    /// Un rapport est-il demandé en cas de succès ?
    #[must_use]
    pub const fn on_success(self) -> bool {
        self.success
    }

    /// Un rapport est-il demandé en cas d'échec définitif ?
    #[must_use]
    pub const fn on_failure(self) -> bool {
        self.failure
    }

    /// Un rapport est-il demandé quand la remise tarde ?
    #[must_use]
    pub const fn on_delay(self) -> bool {
        self.delay
    }

    /// Décode la valeur d'un `NOTIFY=` (§4.1).
    ///
    /// # Errors
    ///
    /// [`Error::MalformedParameter`] pour une valeur vide, un mot inconnu, un
    /// mot répété, ou `NEVER` mêlé à un autre.
    pub fn parse(valeur: &[u8]) -> Result<Self, Error> {
        let mut vu = Self {
            never: false,
            success: false,
            failure: false,
            delay: false,
        };
        let mut combien = 0_usize;
        for mot in valeur.split(|octet| *octet == b',') {
            combien = combien.saturating_add(1);
            // Quatre mots au plus : au-delà, il y a forcément une répétition,
            // et la borne évite de parcourir une liste que le pair choisit.
            if combien > 4 {
                return Err(Error::MalformedParameter);
            }
            let place = if mot.eq_ignore_ascii_case(b"NEVER") {
                &mut vu.never
            } else if mot.eq_ignore_ascii_case(b"SUCCESS") {
                &mut vu.success
            } else if mot.eq_ignore_ascii_case(b"FAILURE") {
                &mut vu.failure
            } else if mot.eq_ignore_ascii_case(b"DELAY") {
                &mut vu.delay
            } else {
                return Err(Error::MalformedParameter);
            };
            // **UN MOT RÉPÉTÉ EST UNE FAUTE**, et non un doublon anodin : deux
            // lecteurs pourraient en tirer deux listes différentes.
            if *place {
                return Err(Error::MalformedParameter);
            }
            *place = true;
        }
        // §4.1 : `NEVER` ne se combine avec rien.
        if vu.never && (vu.success || vu.failure || vu.delay) {
            return Err(Error::MalformedParameter);
        }
        // **AUCUNE GARDE POUR « RIEN N'A ÉTÉ VU ».** `split` rend TOUJOURS au
        // moins un morceau, même sur une entrée vide, et ce morceau-là ne
        // correspond à aucun des quatre mots : la boucle a déjà refusé. Une
        // garde que rien n'atteint n'est pas une garde.
        Ok(vu)
    }
}

/// Ce que le pair veut voir revenir dans le rapport (§4.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ret {
    /// Le message entier.
    Full,
    /// Ses en-têtes seulement.
    Headers,
}

impl Ret {
    /// Décode la valeur d'un `RET=` (§4.3).
    ///
    /// # Errors
    ///
    /// [`Error::MalformedParameter`] pour toute autre valeur.
    pub fn parse(valeur: &[u8]) -> Result<Self, Error> {
        if valeur.eq_ignore_ascii_case(b"FULL") {
            Ok(Self::Full)
        } else if valeur.eq_ignore_ascii_case(b"HDRS") {
            Ok(Self::Headers)
        } else {
            Err(Error::MalformedParameter)
        }
    }
}

/// Décode un **xtext** (§4), et rend ce qui a été écrit dans `sortie`.
///
/// # LE DÉCODAGE NE PEUT QUE RACCOURCIR
///
/// `+41` fait un octet là où il en occupait trois : la sortie n'est jamais plus
/// longue que l'entrée. C'est ce qui permet à l'appelant de dimensionner son
/// tampon sans rien calculer — et ce qui rend impossible qu'une valeur venue du
/// pair fasse déborder quoi que ce soit.
///
/// # CE QUI SORT EST DE L'ASCII VISIBLE, ÉCHAPPÉES COMPRISES
///
/// Une échappée qui décoderait un `CR` ou un `LF` est REFUSÉE. Cette valeur
/// ressort dans un en-tête du rapport que nous composons, et une fin de ligne y
/// écrirait un champ entier à notre place. §4.4 l'exige déjà pour `ENVID` — la
/// valeur décodée doit être imprimable — et l'on est plus strict d'un cran, sans
/// espace, parce que la file écrit ces valeurs dans un fichier où l'espace
/// sépare.
///
/// # Errors
///
/// [`Error::MalformedParameter`] si un octet n'est pas de l'ASCII visible, si un
/// `+` n'est pas suivi de deux chiffres hexadécimaux, si une échappée décode
/// autre chose que de l'ASCII visible, ou si un `=` traîne ;
/// [`Error::BufferTooSmall`] si `sortie` ne suffit pas.
pub fn decode_xtext<'b>(valeur: &[u8], sortie: &'b mut [u8]) -> Result<&'b [u8], Error> {
    let mut ecrits = 0_usize;
    let mut reste = valeur;
    while let Some((premier, suite)) = reste.split_first() {
        let octet = match *premier {
            // `+` ouvre une échappée, et rien d'autre ne le fait.
            b'+' => {
                let (haut, bas) = match suite {
                    [haut, bas, ..] => (*haut, *bas),
                    _ => return Err(Error::MalformedParameter),
                };
                reste = suite.get(2..).unwrap_or_default();
                // Deux quartets tiennent dans un octet par construction : le
                // fort vaut au plus 15, donc `15 * 16 + 15 = 255`. Le dire avec
                // `saturating_*` évite une garde que rien n'atteindrait.
                let haut = quartet(haut)?;
                let bas = quartet(bas)?;
                let decode = haut.saturating_mul(16).saturating_add(bas);
                // ── L'ÉCHAPPÉE NE DOIT PAS RENDRE CE QU'ON REFUSE EN CLAIR ──
                //
                // **`+0D+0A` DÉCODE EN `CRLF`.** Cette valeur ressort dans un
                // en-tête du rapport que nous composons — `Original-Envelope-Id`
                // ou `Original-Recipient` — et une fin de ligne y écrirait un
                // champ entier à notre place, sous notre nom. Le fuzz l'a trouvé
                // à sa première campagne, sur `a+B2b`.
                //
                // §4.4 l'exige d'ailleurs pour `ENVID` : la valeur DÉCODÉE doit
                // être de l'ASCII imprimable. On est plus strict d'un cran —
                // pas d'espace non plus — parce que la file écrit ces valeurs
                // dans un fichier où l'espace SÉPARE.
                if !decode.is_ascii_graphic() {
                    return Err(Error::MalformedParameter);
                }
                decode
            }
            // **`=` EST INTERDIT EN CLAIR** (§4) : c'est ce qui sépare un
            // mot-clé de sa valeur, et le laisser passer couperait le paramètre
            // en deux pour qui relit.
            b'=' => return Err(Error::MalformedParameter),
            autre if autre.is_ascii_graphic() => {
                reste = suite;
                autre
            }
            _ => return Err(Error::MalformedParameter),
        };
        let place = sortie.get_mut(ecrits).ok_or(Error::BufferTooSmall {
            needed: ecrits.saturating_add(1),
        })?;
        *place = octet;
        ecrits = ecrits.saturating_add(1);
    }
    sortie
        .get(..ecrits)
        .ok_or(Error::BufferTooSmall { needed: ecrits })
}

/// La valeur d'un chiffre hexadécimal MAJUSCULE (§4).
///
/// **La minuscule est refusée**, et ce n'est pas du zèle : §4 impose
/// `2*HEXDIG` en majuscules, et deux écritures d'un même octet donneraient deux
/// `ORCPT` différents pour une même adresse — donc deux rapports là où le pair
/// n'en attend qu'un.
fn quartet(octet: u8) -> Result<u8, Error> {
    match octet {
        b'0'..=b'9' => Ok(octet.wrapping_sub(b'0')),
        b'A'..=b'F' => Ok(octet.wrapping_sub(b'A').saturating_add(10)),
        _ => Err(Error::MalformedParameter),
    }
}

/// Découpe un `ORCPT` en son type d'adresse et son adresse (§4.2).
///
/// L'adresse est rendue DÉCODÉE dans `sortie` ; le type, lui, ne l'est pas —
/// §4.2 le veut en clair, et il n'est fait que de lettres et de tirets.
///
/// # Errors
///
/// [`Error::MalformedParameter`] si le point-virgule manque, si le type n'est
/// pas un mot recevable, ou si l'adresse n'est pas un xtext valable.
pub fn parse_orcpt<'v, 'b>(
    valeur: &'v [u8],
    sortie: &'b mut [u8],
) -> Result<(&'v [u8], &'b [u8]), Error> {
    let coupe = valeur
        .iter()
        .position(|octet| *octet == b';')
        .ok_or(Error::MalformedParameter)?;
    let (type_adresse, reste) = valeur.split_at(coupe);
    // `split_at` garde le point-virgule en tête du reste.
    let adresse = reste.get(1..).unwrap_or_default();
    if type_adresse.is_empty()
        || type_adresse.len() > 40
        || !type_adresse
            .iter()
            .all(|octet| octet.is_ascii_alphanumeric() || *octet == b'-')
    {
        return Err(Error::MalformedParameter);
    }
    if adresse.is_empty() {
        return Err(Error::MalformedParameter);
    }
    // `adresse` n'est pas vide, et le décodage rend au moins un octet par octet
    // d'entrée reconnu : ce qui en sort ne peut pas être vide. Une garde qui le
    // vérifierait ne se déclencherait jamais.
    let decodee = decode_xtext(adresse, sortie)?;
    Ok((type_adresse, decodee))
}

#[cfg(test)]
mod tests;
