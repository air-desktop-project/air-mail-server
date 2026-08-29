//! Un tampon de taille fixe, pour ce que la session doit RETENIR.

/// Ce qu'on retient d'un pair, en octets et sans allouer.
///
/// # Pourquoi la session retient, et pourquoi c'est borné
///
/// Le domaine du `HELO` et l'expéditeur d'enveloppe servent APRÈS la commande
/// qui les a portés : SPF les demande, et la ligne qui les contenait est déjà
/// recouverte. Les retenir dans un tampon de taille fixe est ce qui permet de le
/// faire sans allouer — donc sans offrir à un pair de choisir combien de mémoire
/// on lui consacre.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Tampon<const N: usize> {
    octets: [u8; N],
    longueur: usize,
}

impl<const N: usize> Tampon<N> {
    pub(crate) const fn vide() -> Self {
        Self {
            octets: [0; N],
            longueur: 0,
        }
    }

    /// Remplace le contenu par la concaténation de `morceaux`.
    ///
    /// Rend `false` — et **laisse le tampon vide** — si cela ne tient pas. Un
    /// contenu tronqué désignerait autre chose que ce qu'on a reçu, et une
    /// vérification portant sur autre chose ne vérifie rien.
    pub(crate) fn poser(&mut self, morceaux: &[&[u8]]) -> bool {
        self.longueur = 0;
        for morceau in morceaux {
            let fin = self.longueur.saturating_add(morceau.len());
            let Some(place) = self.octets.get_mut(self.longueur..fin) else {
                self.longueur = 0;
                return false;
            };
            place.copy_from_slice(morceau);
            self.longueur = fin;
        }
        true
    }

    pub(crate) fn vider(&mut self) {
        self.longueur = 0;
    }

    pub(crate) fn as_bytes(&self) -> &[u8] {
        self.octets.get(..self.longueur).unwrap_or_default()
    }

    pub(crate) fn est_vide(&self) -> bool {
        self.longueur == 0
    }
}

#[cfg(test)]
mod tests {
    use super::Tampon;

    #[test]
    fn ce_qui_tient_se_retient() {
        let mut tampon = Tampon::<16>::vide();
        assert!(tampon.est_vide());
        assert!(tampon.poser(&[b"jean", b"@", b"example.com"]));
        assert_eq!(tampon.as_bytes(), b"jean@example.com");
        assert!(!tampon.est_vide());
    }

    #[test]
    fn ce_qui_ne_tient_pas_ne_se_tronque_pas() {
        // UN CONTENU TRONQUÉ DÉSIGNERAIT AUTRE CHOSE : `jean@example.com` coupé
        // à seize octets devient `jean@example.co`, un domaine qui existe et
        // qui n'est pas le bon.
        let mut tampon = Tampon::<8>::vide();
        assert!(!tampon.poser(&[b"jean", b"@", b"example.com"]));
        assert!(tampon.est_vide());
        assert_eq!(tampon.as_bytes(), b"");
    }

    #[test]
    fn poser_efface_ce_qui_precede() {
        let mut tampon = Tampon::<16>::vide();
        assert!(tampon.poser(&[b"premier"]));
        assert!(tampon.poser(&[b"second"]));
        assert_eq!(tampon.as_bytes(), b"second");
        tampon.vider();
        assert_eq!(tampon.as_bytes(), b"");
        let copie = tampon;
        assert!(copie.est_vide());
        assert!(!std::format!("{tampon:?}").is_empty());
    }
}
