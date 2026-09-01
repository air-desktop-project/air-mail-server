//! L'enregistrement `TXT` qui dit que la politique a changé (§3.1).

/// La plus longue valeur d'identifiant que §3.1 permet.
const ID_MAX: usize = 32;

/// L'identifiant de politique d'un `TXT`, s'il y en a un.
///
/// # CET IDENTIFIANT N'A PAS BESOIN D'ÊTRE AUTHENTIQUE
///
/// C'est la différence avec DANE, et elle vaut d'être comprise. Il ne dit pas
/// CE QU'EST la politique — cela, c'est le `https://` vérifié qui le dit — il
/// dit seulement qu'elle a CHANGÉ. Un tiers qui le réécrit obtient au pire
/// qu'on retélécharge une politique qu'on a déjà ; un tiers qui le supprime
/// n'obtient rien, parce que le cache reste valable jusqu'à sa péremption.
///
/// **C'est pourquoi on ne demande pas le bit `AD` ici**, alors qu'on l'exige
/// pour un `TLSA`.
///
/// # LA FORME
///
/// `v=STSv1; id=20160831085700Z;` — des champs séparés par des points-virgules,
/// dont l'ordre n'est pas fixé. `v=STSv1` doit être le premier (§3.1).
/// L'identifiant est fait de lettres et de chiffres, de un à trente-deux.
///
/// Rend `None` pour tout ce qui n'a pas cette forme : un `TXT` du domaine qui
/// parle d'autre chose ne doit pas passer pour une politique.
#[must_use]
pub fn parse_id(txt: &str) -> Option<&str> {
    let mut champs = txt.split(';').map(str::trim);
    // §3.1 : `v=STSv1` VIENT EN PREMIER. Accepter l'inverse ferait lire comme
    // une politique un enregistrement qui n'en est pas une.
    //
    // `split` rend TOUJOURS au moins un morceau, même sur une chaîne vide : ce
    // premier appel ne peut pas manquer, et `unwrap_or_default` porte cette
    // certitude dans la bibliothèque standard plutôt que dans une garde que
    // rien n'atteindrait.
    if champs.next().unwrap_or_default() != "v=STSv1" {
        return None;
    }
    for champ in champs {
        let Some(valeur) = champ.strip_prefix("id=") else {
            continue;
        };
        let valeur = valeur.trim();
        if valeur.is_empty()
            || valeur.len() > ID_MAX
            || !valeur.bytes().all(|octet| octet.is_ascii_alphanumeric())
        {
            return None;
        }
        return Some(valeur);
    }
    None
}

#[cfg(test)]
mod tests;
