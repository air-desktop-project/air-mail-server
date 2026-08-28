//! Les destinataires acceptés d'une transaction, retenus SANS allocation.
//!
//! # Pourquoi la session les retient, alors qu'elle ne retient rien d'autre
//!
//! Parce qu'ils appartiennent à la **transaction**, et que la transaction vit
//! ici. La boucle, elle, ne voit ni `MAIL`, ni `RSET`, ni la fin d'un message :
//! elle ne saurait pas quand vider sa propre liste. Une liste qu'on oublie de
//! vider livrerait le message suivant aux destinataires du précédent — le pire
//! défaut qu'un serveur de courrier puisse avoir.
//!
//! # Deux bornes plutôt qu'une, et elles ne disent pas la même chose
//!
//! [`RECIPIENTS_MAX`] borne le NOMBRE, [`ARENA_OCTETS`] borne la PLACE. La
//! seconde n'est pas une redondance : cent adresses de deux cents octets ne
//! tiennent pas dans le même espace que cent adresses de vingt. Quand l'une ou
//! l'autre est atteinte, la réponse est la même — `452`, que la RFC 5321
//! §4.5.3.1.10 prévoit exactement pour cela.

/// Combien de destinataires une transaction peut retenir.
///
/// Cent, qui est le MINIMUM que la RFC 5321 §4.5.3.1.8 impose d'accepter. En
/// retenir moins serait non conforme ; en retenir plus n'aiderait personne, et
/// coûterait de la mémoire par connexion.
pub const RECIPIENTS_MAX: usize = 100;

/// La place que les adresses se partagent.
///
/// Huit kibioctets, soit quatre-vingts octets par destinataire au maximum
/// permis. Une adresse réelle en fait trente ; celle qui n'entre pas est
/// refusée par un `452`, jamais par un débordement (C3).
pub const ARENA_OCTETS: usize = 8192;

/// Les destinataires acceptés, à plat.
///
/// Les adresses sont concaténées dans `arene`, et `fins` porte l'indice de fin
/// de chacune. Pas de tableau de tranches : une tranche porte une durée de vie,
/// et une durée de vie dans une structure qu'on remet à zéro est une invitation
/// à se tromper.
pub struct Recipients {
    arene: [u8; ARENA_OCTETS],
    fins: [usize; RECIPIENTS_MAX],
    combien: usize,
    utilise: usize,
}

impl Recipients {
    /// Une liste vide.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            arene: [0; ARENA_OCTETS],
            fins: [0; RECIPIENTS_MAX],
            combien: 0,
            utilise: 0,
        }
    }

    /// Oublie tout.
    ///
    /// **Le tampon n'est pas effacé**, seulement les compteurs : ce qui reste
    /// est inatteignable — [`Self::iter`] ne parcourt que `combien` entrées — et
    /// l'effacer coûterait huit kibioctets à chaque `MAIL FROM`. Ce ne sont pas
    /// des secrets : ce sont des adresses que le pair vient d'envoyer en clair.
    pub const fn clear(&mut self) {
        self.combien = 0;
        self.utilise = 0;
    }

    /// Combien de destinataires sont retenus.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.combien
    }

    /// N'y a-t-il aucun destinataire ?
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.combien == 0
    }

    /// Retient une adresse, si elle tient.
    ///
    /// Rend `false` quand l'une des deux bornes est atteinte — l'appelant en
    /// fait un `452`, et **rien n'est écrit à moitié** : une adresse tronquée
    /// livrerait à quelqu'un d'autre.
    #[must_use]
    pub fn push(&mut self, morceaux: &[&[u8]]) -> bool {
        let longueur: usize = morceaux.iter().map(|part| part.len()).sum();
        // `saturating_add` plutôt que `checked_add` : la somme ne peut pas
        // déborder — l'arène fait huit kibioctets — et un `checked_add`
        // ouvrirait une branche d'erreur qu'aucun test ne peut atteindre. En
        // saturant, la borne ci-dessous répond de toute façon non.
        let fin = self.utilise.saturating_add(longueur);

        // LES DEUX BORNES, EN DEUX EMPRUNTS. Chacune est un `get_mut` plutôt
        // qu'une comparaison suivie d'un `get_mut` : la comparaison rendrait le
        // `get_mut` infaillible, donc son bras d'échec inatteignable — et une
        // garde qu'aucun test ne peut emprunter n'est pas une garde.
        //
        // L'ORDRE COMPTE : la case d'abord. Écrire les octets puis découvrir
        // qu'il n'y a plus de case laisserait l'arène entamée pour rien.
        let Some(case) = self.fins.get_mut(self.combien) else {
            return false;
        };
        let Some(cible) = self.arene.get_mut(self.utilise..fin) else {
            return false;
        };

        // `split_at_mut` ne peut pas paniquer ici : la somme des morceaux fait
        // exactement la longueur de `cible`, par construction de `fin`.
        let mut reste = cible;
        for part in morceaux {
            let (tete, suite) = reste.split_at_mut(part.len());
            tete.copy_from_slice(part);
            reste = suite;
        }

        *case = fin;
        self.combien = self.combien.saturating_add(1);
        self.utilise = fin;
        true
    }

    /// Les adresses retenues, dans l'ordre où elles ont été acceptées.
    pub fn iter(&self) -> impl Iterator<Item = &[u8]> {
        // `fins` porte les fins ; le début d'une adresse est la fin de la
        // précédente, et zéro pour la première. `windows` ne convient pas — il
        // faut aussi la première.
        self.fins
            .iter()
            .take(self.combien)
            .scan(0_usize, |debut, &fin| {
                let morceau = self.arene.get(*debut..fin);
                *debut = fin;
                morceau
            })
    }
}

impl Default for Recipients {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::{ARENA_OCTETS, RECIPIENTS_MAX, Recipients};

    fn liste(adresses: &[&[u8]]) -> Recipients {
        let mut retenus = Recipients::new();
        for adresse in adresses {
            assert!(retenus.push(&[adresse]));
        }
        retenus
    }

    #[test]
    fn les_adresses_ressortent_dans_l_ordre() {
        let retenus = liste(&[b"jean@example.com", b"paul@example.org"]);
        assert_eq!(retenus.len(), 2);
        assert!(!retenus.is_empty());
        let vus: std::vec::Vec<&[u8]> = retenus.iter().collect();
        assert_eq!(
            vus,
            std::vec![&b"jean@example.com"[..], b"paul@example.org"]
        );
    }

    #[test]
    fn une_adresse_se_compose_de_plusieurs_morceaux() {
        // C'est ainsi que la session écrit `local@domaine` sans rien assembler
        // ailleurs — elle n'a pas d'endroit où assembler.
        let mut retenus = Recipients::new();
        assert!(retenus.push(&[b"jean", b"@", b"example.com"]));
        let vus: std::vec::Vec<&[u8]> = retenus.iter().collect();
        assert_eq!(vus, std::vec![&b"jean@example.com"[..]]);
    }

    #[test]
    fn une_liste_neuve_ou_videe_ne_rend_rien() {
        let mut retenus = liste(&[b"jean@example.com"]);
        retenus.clear();
        assert!(retenus.is_empty());
        assert_eq!(retenus.iter().count(), 0);
        assert_eq!(Recipients::default().iter().count(), 0);
    }

    #[test]
    fn la_borne_de_nombre_arrete_avant_de_deborder() {
        let mut retenus = Recipients::new();
        for _ in 0..RECIPIENTS_MAX {
            assert!(retenus.push(&[b"a@b.co"]));
        }
        assert!(!retenus.push(&[b"a@b.co"]));
        assert_eq!(retenus.len(), RECIPIENTS_MAX);
    }

    #[test]
    fn la_borne_de_place_arrete_aussi_et_n_ecrit_rien_a_moitie() {
        // Cent adresses de deux cents octets ne tiennent pas là où cent adresses
        // de vingt tiennent : la borne de nombre ne suffit pas.
        let longue = [b'a'; 1000];
        let mut retenus = Recipients::new();
        let mut posees = 0_usize;
        while retenus.push(&[&longue]) {
            posees = posees.saturating_add(1);
        }
        assert!(posees < RECIPIENTS_MAX, "la place aurait dû borner avant");
        assert_eq!(posees, ARENA_OCTETS / 1000);
        // RIEN N'EST ÉCRIT À MOITIÉ : une adresse tronquée livrerait à quelqu'un
        // d'autre. Toutes celles qui sont là sont entières.
        for adresse in retenus.iter() {
            assert_eq!(adresse.len(), 1000);
        }
    }

    #[test]
    fn une_adresse_plus_grande_que_l_arene_est_refusee_seule() {
        let enorme = [b'a'; ARENA_OCTETS + 1];
        let mut retenus = Recipients::new();
        assert!(!retenus.push(&[&enorme]));
        assert!(retenus.is_empty());
    }

    #[test]
    fn on_peut_recommencer_apres_avoir_vide() {
        let mut retenus = liste(&[b"jean@example.com"]);
        retenus.clear();
        assert!(retenus.push(&[b"paul@example.org"]));
        let vus: std::vec::Vec<&[u8]> = retenus.iter().collect();
        assert_eq!(vus, std::vec![&b"paul@example.org"[..]]);
    }
}
