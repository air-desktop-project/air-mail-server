//! La liste des suffixes publics, appliquée **sans entrée-sortie**.
//!
//! # La donnée vient de l'appelant, l'algorithme est ici
//!
//! Le fichier de <https://publicsuffix.org> pèse quelques centaines de
//! kibioctets et change toutes les semaines. Il n'a rien à faire dans un
//! binaire : celui qui l'exploite doit pouvoir le remplacer sans recompiler, et
//! savoir de quand date le sien. Cette crate ne le porte donc pas — elle le
//! **lit**, tel que l'appelant le lui prête.
//!
//! # L'algorithme est celui de publicsuffix.org, et il a trois pièges
//!
//! **Les étiquettes se comparent depuis la droite.** `co.uk` correspond à
//! `example.co.uk` mais pas à `xco.uk` : un suffixe qui se comparerait comme une
//! chaîne ferait correspondre le second, et deux domaines étrangers
//! s'aligneraient.
//!
//! **Une règle joker (`*.ck`) couvre une étiquette, pas davantage.**
//!
//! **Une règle d'exception (`!www.ck`) l'emporte sur toutes les autres**, et
//! retire sa propre étiquette de tête. C'est ce qui permet à `www.ck` d'être un
//! domaine enregistrable alors que `*.ck` dit le contraire.
//!
//! # Ce qu'elle ne fait pas : l'IDN
//!
//! Le fichier écrit les noms internationalisés en UTF-8 ; le DNS les transporte
//! en punycode. Cette crate compare des octets : une règle accentuée ne
//! correspondra donc pas à un domaine en `xn--`. Pour ces domaines-là,
//! l'alignement relâché se comporte comme l'alignement strict — **plus étroit,
//! jamais plus large** — et c'est le bon sens de l'erreur.
//!
//! # Ce qu'elle coûte
//!
//! Une lecture de la liste entière par question. C'est linéaire en la liste, pas
//! en le message, et cela se paie deux fois par message. Une structure d'index
//! irait plus vite ; elle demanderait d'allouer, et ce n'est pas le prix qu'on
//! veut payer ici.

use crate::alignment::PublicSuffix;

/// La liste des suffixes publics, telle qu'un fichier la porte.
#[derive(Debug, Clone, Copy)]
pub struct Suffixes<'a> {
    texte: &'a [u8],
}

impl<'a> Suffixes<'a> {
    /// Prête la liste, sans la copier ni la vérifier.
    ///
    /// Les lignes vides et les commentaires (`//`) s'ignorent, comme le veut le
    /// format.
    #[must_use]
    pub fn new(texte: &'a [u8]) -> Self {
        Self { texte }
    }

    /// Le **suffixe public** d'un domaine : le nombre d'étiquettes qu'il couvre.
    ///
    /// Sans règle correspondante, c'est une seule étiquette — le domaine de tête
    /// (`com`, `fr`), comme le veut la règle implicite `*`.
    fn suffixe(&self, domaine: &[u8]) -> usize {
        let etiquettes = compter(domaine);
        let mut meilleur = 1_usize;
        let mut exception: Option<usize> = None;

        for ligne in self.texte.split(|octet| matches!(octet, b'\n' | b'\r')) {
            let regle = ligne.trim_ascii();
            if regle.is_empty() || regle.starts_with(b"//") {
                continue;
            }
            let (regle, est_exception) = match regle.split_first() {
                Some((b'!', reste)) => (reste, true),
                _ => (regle, false),
            };
            let Some(combien) = correspond(regle, domaine) else {
                continue;
            };
            if est_exception {
                // Une exception retire sa propre étiquette de tête, et l'emporte
                // sur toutes les autres règles.
                let sien = combien.saturating_sub(1);
                exception = Some(exception.map_or(sien, |deja: usize| deja.max(sien)));
            } else if combien > meilleur {
                meilleur = combien;
            }
        }
        // La règle qui l'emporte est l'exception s'il y en a une, la plus longue
        // sinon — et jamais plus d'étiquettes que le domaine n'en porte.
        exception.unwrap_or(meilleur).min(etiquettes)
    }
}

impl PublicSuffix for Suffixes<'_> {
    fn organizational_domain<'a>(&self, domain: &'a [u8]) -> &'a [u8] {
        // UN NOM À ÉTIQUETTE VIDE N'EST PAS UN NOM. Lui tailler un domaine
        // organisationnel ferait aligner `a..com` avec `b..com` : on le rend
        // tel quel, et il ne s'alignera donc qu'avec lui-même.
        if domain.split(|octet| *octet == b'.').any(<[u8]>::is_empty) {
            return domain;
        }
        let etiquettes = compter(domain);
        // Le domaine organisationnel, c'est le suffixe public PLUS une
        // étiquette (RFC 7489 §3.2).
        let voulues = self.suffixe(domain).saturating_add(1);
        if voulues >= etiquettes {
            // Le domaine n'en porte pas davantage : il EST son propre domaine
            // organisationnel, et il ne s'alignera donc qu'avec lui-même.
            return domain;
        }
        // On retire les étiquettes de tête en sautant après le `n`-ième point.
        // `map_or` porte l'impossible dans la bibliothèque standard : il y a
        // exactement `etiquettes - 1` points, et l'on en saute moins que cela.
        let a_retirer = etiquettes.saturating_sub(voulues);
        let depart = domain
            .iter()
            .enumerate()
            .filter(|(_, octet)| **octet == b'.')
            .nth(a_retirer.saturating_sub(1))
            .map_or(0, |(rang, _)| rang.saturating_add(1));
        domain.get(depart..).unwrap_or(domain)
    }
}

/// Le nombre d'étiquettes d'un nom.
///
/// Un nom vide n'en a pas — mais il n'arrive jamais ici : l'appelant l'a écarté
/// avant, avec les autres noms à étiquette vide.
fn compter(domaine: &[u8]) -> usize {
    domaine
        .iter()
        .filter(|octet| **octet == b'.')
        .count()
        .saturating_add(1)
}

/// La règle correspond-elle, et sur combien d'étiquettes ?
///
/// La comparaison se fait **depuis la droite**, étiquette par étiquette : un
/// suffixe comparé comme une chaîne ferait correspondre `co.uk` à `xco.uk`, et
/// deux domaines étrangers s'aligneraient.
fn correspond(regle: &[u8], domaine: &[u8]) -> Option<usize> {
    let mut combien = 0_usize;
    let mut siennes = domaine.rsplit(|octet| *octet == b'.');
    for etiquette in regle.rsplit(|octet| *octet == b'.') {
        // La règle porte plus d'étiquettes que le nom : elle ne correspond pas.
        let sienne = siennes.next()?;
        // `*` couvre UNE étiquette, quelle qu'elle soit. Les étiquettes vides,
        // elles, ont été écartées par l'appelant.
        if etiquette != b"*" && !etiquette.eq_ignore_ascii_case(sienne) {
            return None;
        }
        combien = combien.saturating_add(1);
    }
    Some(combien)
}

#[cfg(test)]
mod tests;
