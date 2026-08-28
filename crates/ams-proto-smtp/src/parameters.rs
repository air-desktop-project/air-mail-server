//! Paramètres ESMTP (RFC 5321 §4.1.2).

use crate::{Error, Limits};

/// Les paramètres d'une commande `MAIL` ou `RCPT`.
///
/// Validés à la construction : le parcours ne peut plus échouer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Parameters<'a> {
    rest: &'a [u8],
}

impl<'a> Parameters<'a> {
    /// Aucun paramètre.
    #[must_use]
    pub fn empty() -> Self {
        Self { rest: &[] }
    }

    /// Valide une suite de paramètres séparés par des espaces.
    ///
    /// # Errors
    ///
    /// [`Error::MalformedParameter`] ou [`Error::TooManyParameters`].
    pub fn parse(rest: &'a [u8], limits: &Limits) -> Result<Self, Error> {
        let mut vus = 0_usize;
        for brut in rest.split(|&b| b == b' ') {
            vus = vus.saturating_add(1);
            if vus > limits.max_parameters {
                return Err(Error::TooManyParameters {
                    limit: limits.max_parameters,
                });
            }
            check_parameter(brut)?;
        }
        Ok(Self { rest })
    }

    /// Les octets tels qu'ils ont été reçus.
    #[must_use]
    pub fn as_bytes(&self) -> &'a [u8] {
        self.rest
    }

    /// Le paramètre dont le mot-clé vaut `keyword`, à la casse près.
    ///
    /// Les mots-clés ESMTP sont insensibles à la casse (RFC 5321 §2.4).
    #[must_use]
    pub fn find(&self, keyword: &[u8]) -> Option<Parameter<'a>> {
        self.into_iter()
            .find(|parametre| parametre.keyword.eq_ignore_ascii_case(keyword))
    }
}

impl<'a> IntoIterator for Parameters<'a> {
    type Item = Parameter<'a>;
    type IntoIter = ParametersIter<'a>;

    fn into_iter(self) -> ParametersIter<'a> {
        ParametersIter { rest: self.rest }
    }
}

/// Le parcours des paramètres.
#[derive(Debug, Clone, Copy)]
pub struct ParametersIter<'a> {
    rest: &'a [u8],
}

impl<'a> Iterator for ParametersIter<'a> {
    type Item = Parameter<'a>;

    fn next(&mut self) -> Option<Parameter<'a>> {
        if self.rest.is_empty() {
            return None;
        }
        let (brut, reste) = match self.rest.iter().position(|&b| b == b' ') {
            Some(at) => {
                let (brut, apres) = self.rest.split_at(at);
                (brut, apres.get(1..).unwrap_or(&[]))
            }
            None => (self.rest, &self.rest[..0]),
        };
        self.rest = reste;
        Some(Parameter::from_raw(brut))
    }
}

/// Un paramètre ESMTP : un mot-clé, et une valeur facultative.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Parameter<'a> {
    keyword: &'a [u8],
    value: Option<&'a [u8]>,
}

impl<'a> Parameter<'a> {
    /// Découpe un paramètre déjà validé.
    fn from_raw(brut: &'a [u8]) -> Self {
        match brut.iter().position(|&b| b == b'=') {
            Some(at) => {
                let (keyword, apres) = brut.split_at(at);
                Self {
                    keyword,
                    value: Some(apres.get(1..).unwrap_or(&[])),
                }
            }
            None => Self {
                keyword: brut,
                value: None,
            },
        }
    }

    /// Le mot-clé.
    #[must_use]
    pub fn keyword(&self) -> &'a [u8] {
        self.keyword
    }

    /// La valeur, si le paramètre en porte une.
    #[must_use]
    pub fn value(&self) -> Option<&'a [u8]> {
        self.value
    }
}

/// `esmtp-param = esmtp-keyword ["=" esmtp-value]`.
fn check_parameter(brut: &[u8]) -> Result<(), Error> {
    let (mot_cle, valeur) = match brut.iter().position(|&b| b == b'=') {
        Some(at) => {
            let (mot_cle, apres) = brut.split_at(at);
            (mot_cle, Some(apres.get(1..).unwrap_or(&[])))
        }
        None => (brut, None),
    };

    // `esmtp-keyword = (ALPHA / DIGIT) *(ALPHA / DIGIT / "-")`
    let [premier, suite @ ..] = mot_cle else {
        return Err(Error::MalformedParameter);
    };
    if !premier.is_ascii_alphanumeric() {
        return Err(Error::MalformedParameter);
    }
    if !suite
        .iter()
        .all(|&b| b.is_ascii_alphanumeric() || b == b'-')
    {
        return Err(Error::MalformedParameter);
    }

    // `esmtp-value = 1*(%d33-60 / %d62-126)` — imprimable, sans l'espace ni le
    // signe égal. Un `=` de plus scinderait le paramètre autrement selon
    // l'implémentation, et c'est exactement le genre de divergence qu'on refuse.
    if let Some(valeur) = valeur {
        if valeur.is_empty() {
            return Err(Error::MalformedParameter);
        }
        if !valeur
            .iter()
            .all(|&b| (33..=60).contains(&b) || (62..=126).contains(&b))
        {
            return Err(Error::MalformedParameter);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::Parameters;
    use crate::{Error, Limits};

    fn analyser(octets: &[u8]) -> Result<Parameters<'_>, Error> {
        Parameters::parse(octets, &Limits::DEFAULT)
    }

    #[test]
    fn des_parametres_ordinaires_se_parcourent_dans_l_ordre() {
        let parametres = analyser(b"SIZE=1000 BODY=8BITMIME SMTPUTF8").expect("recevables");
        let vus: std::vec::Vec<_> = parametres
            .into_iter()
            .map(|p| (p.keyword(), p.value()))
            .collect();
        assert_eq!(
            vus,
            [
                (b"SIZE".as_slice(), Some(b"1000".as_slice())),
                (b"BODY".as_slice(), Some(b"8BITMIME".as_slice())),
                (b"SMTPUTF8".as_slice(), None),
            ]
        );
        assert_eq!(parametres.as_bytes(), b"SIZE=1000 BODY=8BITMIME SMTPUTF8");
    }

    #[test]
    fn la_recherche_par_mot_cle_ignore_la_casse() {
        // RFC 5321 §2.4 : les mots-clés ESMTP y sont insensibles.
        let parametres = analyser(b"SIZE=1000").expect("recevables");
        assert_eq!(
            parametres.find(b"size").expect("SIZE").value(),
            Some(b"1000".as_slice())
        );
        assert_eq!(parametres.find(b"body"), None);
    }

    #[test]
    fn l_absence_de_parametre_se_parcourt_sans_rien_rendre() {
        let vides = Parameters::empty();
        assert_eq!(vides.as_bytes(), b"");
        assert_eq!(vides.into_iter().count(), 0);
        assert_eq!(vides.find(b"size"), None);
    }

    #[test]
    fn trop_de_parametres_est_refuse() {
        let bornes = Limits {
            max_parameters: 2,
            ..Limits::DEFAULT
        };
        assert_eq!(
            Parameters::parse(b"A B C", &bornes),
            Err(Error::TooManyParameters { limit: 2 })
        );
        assert!(Parameters::parse(b"A B", &bornes).is_ok());
    }

    #[test]
    fn les_parametres_mal_formes_sont_refuses() {
        for mauvais in [
            b"".as_slice(), // mot-clé vide
            b"A  B",        // espace doublé : le morceau du milieu est vide
            b"-SIZE",       // ne commence pas par une lettre ou un chiffre
            b"SI_ZE",       // souligné hors de l'alphabet du mot-clé
            b"SIZE=",       // valeur vide
            b"SIZE=a=b",    // le `=` est hors de l'alphabet de la valeur
            b"SIZE=a\x01b", // octet non imprimable
        ] {
            assert_eq!(
                analyser(mauvais),
                Err(Error::MalformedParameter),
                "{mauvais:?} aurait dû être refusé"
            );
        }
    }

    #[test]
    fn les_bornes_de_l_alphabet_de_valeur_sont_acceptees() {
        // `esmtp-value = 1*(%d33-60 / %d62-126)` : `!` vaut 33, `<` 60, `>` 62,
        // `~` 126. Le `=` (61) et l'espace (32) en sont exclus.
        assert!(analyser(b"AUTH=<>").is_ok());
        assert!(analyser(b"X=!~").is_ok());
    }

    #[test]
    fn les_types_se_copient_et_se_deboguent() {
        let parametres = analyser(b"SIZE=1000").expect("recevables");
        let copie = parametres;
        assert_eq!(copie, parametres);
        assert!(!std::format!("{parametres:?}").is_empty());

        let parcours = parametres.into_iter();
        assert!(!std::format!("{parcours:?}").is_empty());
        assert_eq!(parcours.count(), 1);

        let premier = parametres.into_iter().next().expect("un paramètre");
        assert_eq!(premier, premier);
        assert!(!std::format!("{premier:?}").is_empty());
    }
}
