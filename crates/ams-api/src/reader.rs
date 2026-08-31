// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! La lecture d'un corps JSON (RFC 8259), **sans allocation et sans récursion**.
//!
//! # C'EST LA SURFACE LA PLUS DANGEREUSE DE CETTE CRATE
//!
//! Tout le reste écrit ; ceci lit ce qu'un inconnu a envoyé. Un analyseur JSON
//! est l'endroit classique où l'on trouve trois choses : un débordement de pile
//! sur des crochets imbriqués, une divergence d'interprétation avec le voisin, et
//! une longueur qu'on croit bornée et qui ne l'est pas.
//!
//! # ON N'EST JAMAIS SEUL À LIRE
//!
//! Un corps JSON traverse souvent plus d'un logiciel : un mandataire qui
//! journalise, une passerelle qui filtre, et nous. Si deux d'entre eux ne lisent
//! pas la même chose dans les mêmes octets, le filtre protège un document que le
//! serveur ne verra jamais.
//!
//! C'est pourquoi ce lecteur refuse tout ce sur quoi les analyseurs divergent,
//! même quand la RFC le tolère :
//!
//! - **les clés répétées** — §4 dit seulement « SHOULD be unique », et chaque
//!   analyseur en fait ce qu'il veut : le premier gagne, le dernier gagne, ou une
//!   liste. `{"admin":false,"admin":true}` est le cas d'école ;
//! - **les nombres à virgule et les exposants** — la précision est laissée à
//!   l'implémentation (§6), donc deux lecteurs peuvent voir deux valeurs ;
//! - **ce qui suit la valeur racine** — `{"a":1}{"b":2}` fait un document pour
//!   nous et deux pour un lecteur en flux ;
//! - **les échappements dans les clés** — `"a"` et `"a"` nomment le même
//!   champ, et savoir lequel gagne est une question qu'on préfère ne pas poser.
//!
//! Aucun client honnête n'écrit rien de tout cela.
//!
//! # ET IL NE RÉCURSE PAS
//!
//! La pile d'imbrication est un tableau de taille fixe. Un corps qui n'est que
//! des crochets ouvrants ne fait donc pas grandir la pile d'appels : il se heurte
//! à une borne, et se refuse.

use crate::error::{Error, Reason};

/// Combien de niveaux d'imbrication on accepte dans un corps.
///
/// Huit, comme à l'écriture : ce qu'on ne sait pas produire, on n'a pas à savoir
/// le lire.
pub const BODY_DEPTH_MAX: usize = 8;

/// Combien de champs un objet peut porter.
///
/// Seize. C'est ce qu'il faut pour retenir les clés déjà vues et refuser les
/// répétitions sans rien allouer — et aucune ressource de cette API n'a de
/// représentation plus large.
pub const FIELDS_MAX: usize = 16;

/// Un nombre lu, tel qu'il était écrit.
///
/// # LE SIGNE ET LA GRANDEUR SONT SÉPARÉS, ET C'EST VOULU
///
/// Un identifiant de message va jusqu'à 2^64 - 1 ; un décalage peut être négatif.
/// Aucun type entier de Rust ne porte les deux, et en choisir un obligerait à
/// refuser à la LECTURE ce que l'appelant aurait peut-être accepté. On lit donc
/// ce qui est écrit, et c'est l'appelant qui dit dans quoi il veut le ranger.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Number {
    /// Le nombre était-il précédé d'un moins ?
    negatif: bool,
    /// Sa grandeur.
    grandeur: u64,
}

impl Number {
    /// La valeur, si elle tient dans un `u64` non signé.
    #[must_use]
    pub const fn as_u64(self) -> Option<u64> {
        match self.negatif && self.grandeur != 0 {
            true => None,
            false => Some(self.grandeur),
        }
    }

    /// La valeur, si elle tient dans un `i64`.
    #[must_use]
    pub fn as_i64(self) -> Option<i64> {
        match self.negatif {
            // `-9223372036854775808` tient, et sa grandeur ne tient pas dans un
            // `i64` : on la nie dans le non signé avant de convertir.
            // `-9223372036854775808` tient dans un `i64` alors que sa grandeur
            // n'y tient pas : c'est le seul nombre dont la négation existe sans
            // que le positif existe.
            true if self.grandeur == 1 << 63 => Some(i64::MIN),
            true => i64::try_from(self.grandeur).ok().and_then(i64::checked_neg),
            false => i64::try_from(self.grandeur).ok(),
        }
    }
}

/// Une chaîne lue, encore telle qu'elle était écrite.
///
/// # ON NE DÉCODE QUE CE QUE L'APPELANT DEMANDE
///
/// La plupart des chaînes d'un corps n'ont aucun échappement : les rendre telles
/// quelles évite de copier, et évite surtout d'exiger un tampon pour chacune. Ce
/// qui en a se décode à la demande, dans un tampon que l'appelant fournit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Str<'a> {
    /// Le contenu entre guillemets, échappements compris.
    brut: &'a str,
    /// Porte-t-il au moins un échappement ?
    echappe: bool,
}

impl<'a> Str<'a> {
    /// Le contenu, s'il ne porte aucun échappement.
    #[must_use]
    pub const fn as_plain(&self) -> Option<&'a str> {
        match self.echappe {
            true => None,
            false => Some(self.brut),
        }
    }

    /// Le contenu tel qu'il était écrit, échappements compris.
    #[must_use]
    pub const fn raw(&self) -> &'a str {
        self.brut
    }

    /// Ce contenu est-il exactement ce texte ?
    ///
    /// **UNE CHAÎNE ÉCHAPPÉE NE VAUT JAMAIS UN LITTÉRAL** : la comparer
    /// demanderait de la décoder, donc un tampon, à un endroit où l'appelant
    /// n'en a pas forcément. Il la décodera lui-même s'il y tient.
    #[must_use]
    pub fn is(&self, texte: &str) -> bool {
        !self.echappe && self.brut == texte
    }

    /// Décode les échappements dans `sortie`.
    ///
    /// # Errors
    ///
    /// [`Reason::BufferTooSmall`] si `sortie` ne suffit pas.
    pub fn unescape<'o>(&self, sortie: &'o mut [u8]) -> Result<&'o str, Error> {
        let mut ecrits = 0_usize;
        let mut octets = self.brut.chars();
        while let Some(caractere) = octets.next() {
            let valeur = match caractere {
                // Les séquences ont été validées à la lecture : ce qui suit une
                // barre oblique inverse est forcément l'une de celles-ci.
                '\\' => decoder_un_echappement(&mut octets),
                autre => autre,
            };
            let mut place = [0_u8; 4];
            let ecrit = valeur.encode_utf8(&mut place);
            let fin = ecrits.saturating_add(ecrit.len());
            let ou = sortie
                .get_mut(ecrits..fin)
                .ok_or(Error::new(Reason::BufferTooSmall))?;
            for (place, lu) in ou.iter_mut().zip(ecrit.as_bytes()) {
                *place = *lu;
            }
            ecrits = fin;
        }
        // **CE QU'ON VIENT D'ÉCRIRE EST DE L'UTF-8 PAR CONSTRUCTION** : chaque
        // octet sort de `char::encode_utf8`. Une garde ici serait une branche
        // qu'aucune chaîne ne peut emprunter.
        let ecrit = sortie.get(..ecrits).unwrap_or_default();
        Ok(core::str::from_utf8(ecrit).unwrap_or_default())
    }
}

/// Ce qu'une lecture rend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event<'a> {
    /// Un objet s'ouvre.
    ObjectStart,
    /// Un objet se ferme.
    ObjectEnd,
    /// Un tableau s'ouvre.
    ArrayStart,
    /// Un tableau se ferme.
    ArrayEnd,
    /// Le nom d'un champ.
    Key(Str<'a>),
    /// Une chaîne.
    Text(Str<'a>),
    /// Un nombre.
    Number(Number),
    /// `true` ou `false`.
    Bool(bool),
    /// `null`.
    Null,
}

/// Un niveau d'imbrication ouvert.
#[derive(Debug, Clone, Copy)]
struct Niveau {
    /// Est-ce un objet ? Sinon, c'est un tableau.
    objet: bool,
    /// N'a-t-on encore rien lu dedans ?
    vide: bool,
    /// Une clé attend-elle sa valeur ?
    clef_posee: bool,
    /// Les clés déjà vues, en rangs dans l'entrée.
    clefs: [(usize, usize); FIELDS_MAX],
    /// Combien.
    combien: usize,
}

/// Un lecteur de corps JSON.
#[derive(Debug)]
pub struct Reader<'a> {
    /// Ce qu'on lit.
    entree: &'a [u8],
    /// Où l'on en est.
    rang: usize,
    /// Les niveaux ouverts.
    niveaux: [Niveau; BODY_DEPTH_MAX],
    /// Combien.
    profondeur: usize,
    /// A-t-on lu la valeur racine ?
    racine_lue: bool,
}

impl<'a> Reader<'a> {
    /// Un lecteur sur ces octets.
    #[must_use]
    pub fn new(corps: &'a [u8]) -> Self {
        Self {
            entree: corps,
            rang: 0,
            niveaux: [Niveau {
                objet: false,
                vide: true,
                clef_posee: false,
                clefs: [(0, 0); FIELDS_MAX],
                combien: 0,
            }; BODY_DEPTH_MAX],
            profondeur: 0,
            racine_lue: false,
        }
    }

    /// L'événement suivant, ou `None` à la fin du document.
    ///
    /// **CE N'EST PAS UN `Iterator`**, et le nom le dit : un itérateur qui rend
    /// `None` a fini, tandis qu'ici `None` veut dire « fini ET tout est clos ».
    /// Les confondre laisserait un corps tronqué passer pour un corps complet.
    ///
    /// # Errors
    ///
    /// [`Reason::BadJsonBody`] pour tout ce qui n'est pas un corps que ce
    /// serveur accepte — voir la documentation du module.
    pub fn read(&mut self) -> Result<Option<Event<'a>>, Error> {
        self.sauter_les_blancs();
        let Some(octet) = self.entree.get(self.rang).copied() else {
            // **LA FIN N'EST UNE FIN QUE SI TOUT EST CLOS.**
            if self.profondeur != 0 || !self.racine_lue {
                return Err(Error::new(Reason::BadJsonBody));
            }
            return Ok(None);
        };
        // **APRÈS LA VALEUR RACINE, PLUS RIEN** : `{"a":1}{"b":2}` fait un
        // document pour nous et deux pour un lecteur en flux.
        if self.profondeur == 0 && self.racine_lue {
            return Err(Error::new(Reason::BadJsonBody));
        }
        match octet {
            b'}' => self.fermer(true),
            b']' => self.fermer(false),
            _ => self.lire_une_entree(),
        }
    }

    /// Lit ce qui n'est pas une fermeture.
    fn lire_une_entree(&mut self) -> Result<Option<Event<'a>>, Error> {
        let mauvais = Error::new(Reason::BadJsonBody);
        // Le séparateur qui précède, s'il en faut un.
        self.separer()?;
        // **L'OCTET SE RELIT APRÈS LA VIRGULE.** Le premier jet passait celui
        // que l'appelant avait lu avant `separer` : une fois la virgule
        // consommée, il désignait le séparateur et non la valeur, et `[1, 2]`
        // se refusait. Un octet retenu de l'autre côté d'un avancement n'est
        // plus le bon.
        self.sauter_les_blancs();
        // **IL Y A TOUJOURS UN OCTET ICI** : `read` en a vu un, et `separer`
        // refuse une virgule qui ne serait suivie de rien. Un zéro tomberait de
        // toute façon dans l'arme qui refuse, sans ajouter de branche.
        let octet = self.entree.get(self.rang).copied().unwrap_or(0);
        let niveau = self.niveau();
        let attend_une_clef = niveau.objet && !niveau.clef_posee;
        if attend_une_clef {
            self.sauter_les_blancs();
            let debut = self.rang;
            let texte = self.lire_une_chaine()?;
            // **AUCUN ÉCHAPPEMENT DANS UNE CLÉ** : `"a"` et `"a"` nomment le
            // même champ, et savoir lequel gagne est une question qu'on préfère
            // ne pas poser. Cela rend aussi la comparaison des doublons exacte,
            // puisqu'elle porte alors sur les octets écrits.
            if texte.echappe {
                return Err(mauvais);
            }
            self.noter_la_clef(debut, self.rang)?;
            self.sauter_les_blancs();
            if self.entree.get(self.rang) != Some(&b':') {
                return Err(mauvais);
            }
            self.rang = self.rang.saturating_add(1);
            self.marquer(|niveau| {
                niveau.clef_posee = true;
                niveau.vide = false;
            });
            return Ok(Some(Event::Key(texte)));
        }
        let evenement = self.lire_une_valeur(octet)?;
        Ok(Some(evenement))
    }

    /// Lit une valeur, quelle qu'elle soit.
    fn lire_une_valeur(&mut self, octet: u8) -> Result<Event<'a>, Error> {
        let mauvais = Error::new(Reason::BadJsonBody);
        let evenement = match octet {
            b'{' => {
                self.ouvrir(true)?;
                return Ok(Event::ObjectStart);
            }
            b'[' => {
                self.ouvrir(false)?;
                return Ok(Event::ArrayStart);
            }
            b'"' => Event::Text(self.lire_une_chaine()?),
            b't' => {
                self.attendre(b"true")?;
                Event::Bool(true)
            }
            b'f' => {
                self.attendre(b"false")?;
                Event::Bool(false)
            }
            b'n' => {
                self.attendre(b"null")?;
                Event::Null
            }
            b'-' | b'0'..=b'9' => Event::Number(self.lire_un_nombre()?),
            _ => return Err(mauvais),
        };
        self.apres_une_valeur();
        Ok(evenement)
    }

    /// Le niveau courant, ou un niveau vide hors de toute structure.
    ///
    /// # LE SENTINELLE EST VIDE, ET CELA SUFFIT
    ///
    /// Hors de toute structure, on rend un niveau où rien n'a été lu et qui
    /// n'est pas un objet. Les deux seules questions qu'on lui pose — « faut-il
    /// une virgule ? » et « attend-on une clé ? » — ont alors la bonne réponse
    /// sans qu'aucune garde ne le vérifie.
    ///
    /// Ce qui a vraiment besoin de distinguer la racine — la fermeture — regarde
    /// la profondeur, qui le dit sans détour.
    fn niveau(&self) -> Niveau {
        self.profondeur
            .checked_sub(1)
            .and_then(|rang| self.niveaux.get(rang))
            .copied()
            .unwrap_or(Niveau {
                objet: false,
                vide: true,
                clef_posee: false,
                clefs: [(0, 0); FIELDS_MAX],
                combien: 0,
            })
    }

    /// Modifie le niveau courant.
    ///
    /// **LE RANG EST BORNÉ PAR CONSTRUCTION** : la profondeur ne dépasse jamais
    /// [`BODY_DEPTH_MAX`], et l'on n'appelle ceci que dans une structure
    /// ouverte.
    fn marquer(&mut self, quoi: impl FnOnce(&mut Niveau)) {
        let rang = self.profondeur.saturating_sub(1);
        quoi(&mut self.niveaux[rang]);
    }

    /// Consomme la virgule qui précède une entrée, s'il en faut une.
    fn separer(&mut self) -> Result<(), Error> {
        let mauvais = Error::new(Reason::BadJsonBody);
        let niveau = self.niveau();
        // Dans un objet, la valeur suit sa clé sans virgule. Hors de toute
        // structure, le sentinelle est vide, et l'on ne demande donc rien.
        if niveau.clef_posee || niveau.vide {
            return Ok(());
        }
        if self.entree.get(self.rang) != Some(&b',') {
            return Err(mauvais);
        }
        self.rang = self.rang.saturating_add(1);
        self.sauter_les_blancs();
        // **PAS DE VIRGULE FINALE** : `[1,]` se lit différemment selon
        // l'analyseur, et certains y voient un élément de plus.
        match self.entree.get(self.rang) {
            Some(b'}' | b']') | None => Err(mauvais),
            Some(_) => Ok(()),
        }
    }

    /// Note une clé, et refuse les répétitions.
    fn noter_la_clef(&mut self, debut: usize, fin: usize) -> Result<(), Error> {
        let mauvais = Error::new(Reason::BadJsonBody);
        let neuve = self.entree.get(debut..fin).unwrap_or_default();
        let niveau = self.niveau();
        // **LES CLÉS RÉPÉTÉES SE REFUSENT** : §4 dit seulement « SHOULD be
        // unique », et chaque analyseur en fait ce qu'il veut.
        for (un, deux) in niveau.clefs.iter().take(niveau.combien) {
            if self.entree.get(*un..*deux).unwrap_or_default() == neuve {
                return Err(mauvais);
            }
        }
        if niveau.combien >= FIELDS_MAX {
            return Err(mauvais);
        }
        self.marquer(|niveau| {
            // La borne vient d'être vérifiée juste au-dessus.
            niveau.clefs[niveau.combien] = (debut, fin);
            niveau.combien = niveau.combien.saturating_add(1);
        });
        Ok(())
    }

    /// Ouvre un niveau.
    fn ouvrir(&mut self, objet: bool) -> Result<(), Error> {
        if self.profondeur >= BODY_DEPTH_MAX {
            return Err(Error::new(Reason::BadJsonBody));
        }
        self.rang = self.rang.saturating_add(1);
        self.apres_une_valeur();
        // La borne vient d'être vérifiée : le rang tient dans le tableau.
        let place = &mut self.niveaux[self.profondeur];
        place.objet = objet;
        place.vide = true;
        place.clef_posee = false;
        place.combien = 0;
        self.profondeur = self.profondeur.saturating_add(1);
        Ok(())
    }

    /// Ferme un niveau.
    fn fermer(&mut self, objet: bool) -> Result<Option<Event<'a>>, Error> {
        let mauvais = Error::new(Reason::BadJsonBody);
        if self.profondeur == 0 {
            return Err(mauvais);
        }
        let niveau = self.niveau();
        // **ON NE FERME PAS UN TABLEAU AVEC UNE ACCOLADE**, et une clé sans
        // valeur ne se ferme pas non plus.
        if niveau.objet != objet || niveau.clef_posee {
            return Err(mauvais);
        }
        self.rang = self.rang.saturating_add(1);
        self.profondeur = self.profondeur.saturating_sub(1);
        match objet {
            true => Ok(Some(Event::ObjectEnd)),
            false => Ok(Some(Event::ArrayEnd)),
        }
    }

    /// Note qu'une valeur vient d'être lue.
    fn apres_une_valeur(&mut self) {
        if self.profondeur == 0 {
            self.racine_lue = true;
            return;
        }
        self.marquer(|niveau| {
            niveau.clef_posee = false;
            niveau.vide = false;
        });
    }

    /// Saute les blancs de §2 : espace, tabulation, saut de ligne, retour
    /// chariot.
    ///
    /// **ET RIEN D'AUTRE.** Ni la page suivante, ni l'espace insécable, ni la
    /// marque d'ordre des octets : §8.1 interdit d'en ajouter une, et l'ignorer
    /// ferait d'un document deux lectures.
    fn sauter_les_blancs(&mut self) {
        while let Some(octet) = self.entree.get(self.rang) {
            if !matches!(octet, b' ' | b'\t' | b'\n' | b'\r') {
                return;
            }
            self.rang = self.rang.saturating_add(1);
        }
    }

    /// Consomme un mot-clé exact.
    fn attendre(&mut self, mot: &[u8]) -> Result<(), Error> {
        let fin = self.rang.saturating_add(mot.len());
        let lu = self.entree.get(self.rang..fin).unwrap_or_default();
        if lu != mot {
            return Err(Error::new(Reason::BadJsonBody));
        }
        self.rang = fin;
        Ok(())
    }

    /// Lit une chaîne, et valide ses échappements.
    fn lire_une_chaine(&mut self) -> Result<Str<'a>, Error> {
        let mauvais = Error::new(Reason::BadJsonBody);
        if self.entree.get(self.rang) != Some(&b'"') {
            return Err(mauvais);
        }
        self.rang = self.rang.saturating_add(1);
        let debut = self.rang;
        let mut echappe = false;
        loop {
            let octet = self.entree.get(self.rang).copied().ok_or(mauvais)?;
            match octet {
                b'"' => break,
                // **AUCUN OCTET DE CONTRÔLE NON ÉCHAPPÉ** : §7 l'exige, et
                // l'accepter ferait passer un saut de ligne dans un nom.
                0x00..=0x1f => return Err(mauvais),
                b'\\' => {
                    echappe = true;
                    self.rang = self.rang.saturating_add(1);
                    self.valider_un_echappement()?;
                }
                _ => self.rang = self.rang.saturating_add(1),
            }
        }
        let brut = self.entree.get(debut..self.rang).unwrap_or_default();
        self.rang = self.rang.saturating_add(1);
        let brut = core::str::from_utf8(brut).map_err(|_| mauvais)?;
        Ok(Str { brut, echappe })
    }

    /// Valide la séquence qui suit une barre oblique inverse.
    fn valider_un_echappement(&mut self) -> Result<(), Error> {
        let mauvais = Error::new(Reason::BadJsonBody);
        let octet = self.entree.get(self.rang).copied().ok_or(mauvais)?;
        self.rang = self.rang.saturating_add(1);
        match octet {
            b'"' | b'\\' | b'/' | b'b' | b'f' | b'n' | b'r' | b't' => Ok(()),
            b'u' => self.valider_un_point_de_code(),
            _ => Err(mauvais),
        }
    }

    /// Valide un `\uXXXX`, paire d'indirection comprise.
    ///
    /// # UNE MOITIÉ DE PAIRE N'EST PAS UN CARACTÈRE
    ///
    /// §7 laisse écrire les caractères hors du plan multilingue de base en deux
    /// `\uXXXX`. Une moitié seule ne désigne aucun caractère : certains
    /// analyseurs la rendent en U+FFFD, d'autres en WTF-8, d'autres refusent —
    /// trois lectures d'un même document, dont deux silencieuses.
    fn valider_un_point_de_code(&mut self) -> Result<(), Error> {
        let mauvais = Error::new(Reason::BadJsonBody);
        let haut = self.lire_quatre_chiffres()?;
        // Ce qui n'est pas une moitié de paire est un caractère à soi seul.
        if !(0xd800..=0xdfff).contains(&haut) {
            return Ok(());
        }
        // Une moitié basse en premier n'ouvre rien.
        if !(0xd800..=0xdbff).contains(&haut) {
            return Err(mauvais);
        }
        if self.entree.get(self.rang) != Some(&b'\\')
            || self.entree.get(self.rang.saturating_add(1)) != Some(&b'u')
        {
            return Err(mauvais);
        }
        self.rang = self.rang.saturating_add(2);
        let bas = self.lire_quatre_chiffres()?;
        match (0xdc00..=0xdfff).contains(&bas) {
            true => Ok(()),
            false => Err(mauvais),
        }
    }

    /// Lit exactement quatre chiffres hexadécimaux.
    fn lire_quatre_chiffres(&mut self) -> Result<u32, Error> {
        let mauvais = Error::new(Reason::BadJsonBody);
        let mut valeur = 0_u32;
        for _ in 0..4 {
            let octet = self.entree.get(self.rang).copied().ok_or(mauvais)?;
            let chiffre = chiffre_hexadecimal(octet).ok_or(mauvais)?;
            valeur = valeur.saturating_mul(16).saturating_add(u32::from(chiffre));
            self.rang = self.rang.saturating_add(1);
        }
        Ok(valeur)
    }

    /// Lit un nombre entier.
    ///
    /// # NI VIRGULE NI EXPOSANT
    ///
    /// §6 laisse la précision à l'implémentation, et prévient que seuls les
    /// entiers entre -(2^53)+1 et (2^53)-1 sont sûrs d'être interopérables. Un
    /// `1e400` ou un `0.1` lus ici seraient relus ailleurs avec une autre valeur,
    /// et deux composants ne verraient pas la même chose.
    fn lire_un_nombre(&mut self) -> Result<Number, Error> {
        let mauvais = Error::new(Reason::BadJsonBody);
        let negatif = self.entree.get(self.rang) == Some(&b'-');
        if negatif {
            self.rang = self.rang.saturating_add(1);
        }
        let premier = self.entree.get(self.rang).copied().ok_or(mauvais)?;
        // §6 : « leading zeros are not allowed ». Ce n'est pas nous qui le
        // décidons — mais l'accepter donnerait deux écritures d'un même nombre.
        let zero_seul = premier == b'0';
        if !premier.is_ascii_digit() {
            return Err(mauvais);
        }
        let mut grandeur = 0_u64;
        while let Some(octet) = self.entree.get(self.rang).copied() {
            let Some(chiffre) = octet.checked_sub(b'0').filter(|c| *c <= 9) else {
                break;
            };
            grandeur = grandeur
                .checked_mul(10)
                .and_then(|dix| dix.checked_add(u64::from(chiffre)))
                .ok_or(mauvais)?;
            self.rang = self.rang.saturating_add(1);
            if zero_seul {
                break;
            }
        }
        // Un zéro de tête suivi d'un chiffre.
        if zero_seul && self.entree.get(self.rang).is_some_and(u8::is_ascii_digit) {
            return Err(mauvais);
        }
        // **NI VIRGULE NI EXPOSANT**, et le dire vaut mieux que de tronquer.
        if matches!(self.entree.get(self.rang), Some(b'.' | b'e' | b'E')) {
            return Err(mauvais);
        }
        Ok(Number { negatif, grandeur })
    }
}

/// La valeur d'un chiffre hexadécimal, dans les deux casses.
const fn chiffre_hexadecimal(octet: u8) -> Option<u8> {
    match octet {
        b'0'..=b'9' => Some(octet.wrapping_sub(b'0')),
        b'a'..=b'f' => Some(octet.wrapping_sub(b'a').wrapping_add(10)),
        b'A'..=b'F' => Some(octet.wrapping_sub(b'A').wrapping_add(10)),
        _ => None,
    }
}

/// Le caractère que désigne une séquence d'échappement déjà validée.
fn decoder_un_echappement(octets: &mut core::str::Chars<'_>) -> char {
    // La lecture a validé la séquence : il y a toujours un caractère ici, et
    // `unwrap_or` le porte sans ajouter une branche qu'aucun corps ne peut
    // emprunter.
    let marque = octets.next().unwrap_or('\u{fffd}');
    match marque {
        'b' => '\u{8}',
        'f' => '\u{c}',
        'n' => '\n',
        'r' => '\r',
        't' => '\t',
        'u' => decoder_un_point_de_code(octets),
        // `"`, `\` et `/` valent pour eux-mêmes.
        autre => autre,
    }
}

/// Le caractère que désigne un `\uXXXX` déjà validé.
fn decoder_un_point_de_code(octets: &mut core::str::Chars<'_>) -> char {
    let haut = quatre_chiffres(octets);
    if !(0xd800..=0xdbff).contains(&haut) {
        return char::from_u32(haut).unwrap_or('\u{fffd}');
    }
    // La lecture a validé la paire : la seconde moitié suit.
    let _ = octets.next();
    let _ = octets.next();
    let bas = quatre_chiffres(octets);
    let point = 0x1_0000_u32
        .saturating_add((haut.saturating_sub(0xd800)).saturating_mul(0x400))
        .saturating_add(bas.saturating_sub(0xdc00));
    char::from_u32(point).unwrap_or('\u{fffd}')
}

/// Les quatre chiffres suivants, en valeur.
fn quatre_chiffres(octets: &mut core::str::Chars<'_>) -> u32 {
    let mut valeur = 0_u32;
    for _ in 0..4 {
        let chiffre = octets
            .next()
            .and_then(|caractere| caractere.to_digit(16))
            .unwrap_or(0);
        valeur = valeur.saturating_mul(16).saturating_add(chiffre);
    }
    valeur
}

#[cfg(test)]
mod tests;
