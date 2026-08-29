//! L'évaluation d'une politique SPF (RFC 7208 §4), **sans entrée-sortie**.
//!
//! # Elle POSE DES QUESTIONS ; elle n'interroge personne
//!
//! [`Evaluator::poll`] rend soit un verdict, soit une **question** — un nom et
//! ce qu'on veut en savoir. L'appelant la résout comme il l'entend, et rend la
//! réponse par [`Evaluator::answer`]. C'est C1, et ce n'est pas seulement une
//! affaire de principe : **la limite des dix résolutions se compte ici**, sur
//! une machine à états qu'on peut éprouver, plutôt que dans un résolveur où elle
//! se perdrait.
//!
//! # Ce qu'on demande n'est pas une requête, c'est une QUESTION
//!
//! `MxAddresses` veut « les adresses des serveurs de courrier de ce domaine » :
//! deux tours de DNS, que l'appelant enchaîne. Ce découpage-là est celui de la
//! RFC, qui compte **un** mécanisme `mx` comme **une** résolution — et il évite
//! à cette crate de retenir une liste de noms entre deux réponses, donc
//! d'allouer.
//!
//! Les sous-limites de chaque question appartiennent à l'appelant, et la RFC les
//! nomme : au plus dix enregistrements `MX`, au plus dix noms rendus par une
//! résolution inverse (§4.6.4). Elles sont écrites sur [`Query`], parce qu'un
//! contrat qu'on ne peut pas vérifier doit au moins être lisible.
//!
//! # Ce que le verdict vaut, et ce qu'il ne vaut pas
//!
//! SPF dit si **cette adresse** avait le droit d'émettre pour **ce domaine**. Il
//! ne dit rien de l'en-tête `From:` que lira l'humain — c'est DMARC qui les
//! rapproche. Un `Pass` n'est donc pas un blanc-seing : c'est une brique.

use core::net::IpAddr;

use crate::macros::{Context, EXPANDED_MAX, Expanded, expand};
use crate::term::{DomainSpec, Lookup, Resolution};
use crate::{Error, Limits, Modifier, Qualifier, Record, Term};

/// La plus grande politique qu'une trame retienne.
///
/// L'enregistrement est **recopié** dans la trame : les octets viennent d'une
/// réponse DNS que l'appelant ne peut pas garder vivante pendant qu'il en
/// résout d'autres. Mille octets, comme [`Limits::max_record_octets`] par
/// défaut ; au-delà, l'enregistrement est refusé plutôt que tronqué.
const RECORD_BUF: usize = 1000;

/// Combien de politiques peuvent s'empiler.
///
/// Chaque `include` en coûte une résolution : avec dix résolutions au plus, on
/// ne peut pas descendre plus bas que onze trames. La borne n'est donc pas une
/// invention, c'est une conséquence.
const MAX_DEPTH: usize = 11;

/// Ce qu'une évaluation SPF conclut (RFC 7208 §2.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Aucun enregistrement : le domaine ne dit rien. **Ce n'est pas un refus.**
    None,
    /// Le domaine ne se prononce pas.
    Neutral,
    /// L'adresse avait le droit d'émettre.
    Pass,
    /// L'adresse n'avait pas ce droit, et le domaine le dit fermement.
    Fail,
    /// L'adresse n'avait pas ce droit, mais le domaine n'ose pas encore le dire.
    SoftFail,
    /// Une résolution a échoué : **réessayer a un sens**.
    TempError,
    /// La politique est irrecevable : réessayer n'en a aucun.
    PermError,
}

impl Verdict {
    /// Le verdict d'un mécanisme qui correspond.
    const fn du_qualificateur(qualifier: Qualifier) -> Self {
        match qualifier {
            Qualifier::Pass => Self::Pass,
            Qualifier::Fail => Self::Fail,
            Qualifier::SoftFail => Self::SoftFail,
            Qualifier::Neutral => Self::Neutral,
        }
    }
}

/// Ce qu'on veut savoir d'un nom.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Query {
    /// Les enregistrements TXT — pour y trouver une politique.
    Txt,
    /// Les adresses (A **et** AAAA) du nom.
    Addresses,
    /// Les adresses des serveurs de courrier du nom.
    ///
    /// **L'appelant s'arrête à dix enregistrements `MX`** (RFC 7208 §4.6.4).
    /// Cette crate ne peut pas le vérifier : elle ne voit que des adresses.
    MxAddresses,
    /// Le nom existe-t-il, au sens d'un enregistrement A ?
    Exists,
    /// Les noms que la résolution inverse de l'adresse du pair **confirme**.
    ///
    /// L'appelant résout l'adresse en noms, puis chaque nom en adresses, et ne
    /// rend que ceux qui reviennent à l'adresse de départ (RFC 7208 §5.5).
    /// **Il s'arrête à dix noms** (§4.6.4). Sans cette confirmation, n'importe
    /// qui pourrait faire pointer sa résolution inverse où il veut.
    PtrNames,
}

/// La question posée : un nom, et ce qu'on veut en savoir.
///
/// Le nom est **copié** plutôt qu'emprunté : l'appelant va s'en servir pour
/// faire de l'entrée-sortie, et un emprunt sur l'évaluateur l'empêcherait de lui
/// rendre la réponse.
#[derive(Debug, Clone, Copy)]
pub struct Question {
    kind: Query,
    nom: [u8; EXPANDED_MAX],
    longueur: usize,
}

impl Question {
    /// Ce qu'on veut savoir.
    #[must_use]
    pub const fn kind(&self) -> Query {
        self.kind
    }

    /// Le nom à interroger. Vide pour [`Query::PtrNames`], qui porte sur
    /// l'adresse du pair.
    #[must_use]
    pub fn name(&self) -> &[u8] {
        self.nom.get(..self.longueur).unwrap_or_default()
    }
}

/// Ce que l'appelant a trouvé.
#[derive(Debug, Clone, Copy)]
pub enum Answer<'a> {
    /// Les enregistrements TXT du nom.
    Txt(&'a [&'a [u8]]),
    /// Les adresses trouvées.
    Addresses(&'a [IpAddr]),
    /// Les noms confirmés par la résolution inverse.
    Names(&'a [&'a [u8]]),
    /// Le nom existe, ou non.
    Exists(bool),
    /// Rien : le nom n'existe pas, ou n'a pas l'enregistrement demandé.
    ///
    /// C'est une **résolution vide** au sens de la RFC 7208 §4.6.4, et il n'en
    /// faut pas plus de deux.
    NotFound,
    /// La résolution a échoué : réessayer a un sens.
    TempError,
}

/// Ce qu'il faut faire ensuite.
///
/// La variante `Ask` est grosse — elle porte un nom de domaine entier. C'est le
/// prix de « la question ne garde pas d'emprunt » : l'appelant résout pendant
/// que l'évaluateur ne tient plus rien, ce qui est précisément ce qui permet de
/// n'allouer nulle part. Onze de ces valeurs au plus circulent par évaluation.
#[expect(
    clippy::large_enum_variant,
    reason = "le nom est copié pour rendre la main sans emprunt ; voir ci-dessus"
)]
#[derive(Debug, Clone, Copy)]
pub enum Step {
    /// Résoudre cette question, puis appeler [`Evaluator::answer`].
    Ask(Question),
    /// C'est fini.
    Done(Verdict),
}

/// Une politique en cours d'évaluation.
#[derive(Debug, Clone, Copy)]
struct Frame {
    domaine: [u8; EXPANDED_MAX],
    domaine_len: usize,
    politique: [u8; RECORD_BUF],
    politique_len: usize,
    /// Le rang du terme à examiner.
    terme: usize,
    /// La politique est-elle chargée ?
    chargee: bool,
    /// Cette trame est-elle un `include` de la précédente, et avec quel
    /// qualificateur ?
    include: Option<Qualifier>,
    /// Y est-on arrivé par un `redirect=` ?
    ///
    /// La différence n'est pas cosmétique : un `redirect=` vers un domaine sans
    /// politique vaut `permerror` (RFC 7208 §6.1), là où l'absence de politique
    /// au départ vaut `none`.
    via_redirect: bool,
}

impl Frame {
    /// Une trame pour un domaine qui vient de l'APPELANT — donc de longueur
    /// inconnue, donc faillible.
    fn depuis_domaine(domaine: &[u8], via_redirect: bool) -> Option<Self> {
        let mut trame = Self::vide(None, via_redirect);
        trame.domaine_len = domaine.len();
        trame
            .domaine
            .get_mut(..domaine.len())?
            .copy_from_slice(domaine);
        Some(trame)
    }

    /// Une trame pour un domaine qui vient d'une EXPANSION.
    ///
    /// [`Expanded`] borne ses octets à [`EXPANDED_MAX`], qui est la taille du
    /// tampon : la recopie ne peut pas déborder, et le dire dans le type
    /// dispense d'une garde qu'aucun test ne pourrait atteindre.
    fn depuis_expansion(
        domaine: &Expanded,
        include: Option<Qualifier>,
        via_redirect: bool,
    ) -> Self {
        let source = domaine.as_bytes();
        let mut trame = Self::vide(include, via_redirect);
        trame.domaine_len = source.len();
        let (cible, _) = trame.domaine.split_at_mut(source.len());
        cible.copy_from_slice(source);
        trame
    }

    fn vide(include: Option<Qualifier>, via_redirect: bool) -> Self {
        Self {
            domaine: [0; EXPANDED_MAX],
            domaine_len: 0,
            politique: [0; RECORD_BUF],
            politique_len: 0,
            terme: 0,
            chargee: false,
            include,
            via_redirect,
        }
    }

    fn domaine(&self) -> &[u8] {
        self.domaine.get(..self.domaine_len).unwrap_or_default()
    }

    fn politique(&self) -> &[u8] {
        self.politique.get(..self.politique_len).unwrap_or_default()
    }
}

/// L'état de la machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Etat {
    /// Il faut charger la politique de la trame du dessus.
    Charger,
    /// Il faut examiner le terme courant.
    Termes,
    /// On attend la réponse à une question.
    Attente(Query),
    /// C'est fini.
    Fini(Verdict),
}

/// L'évaluateur.
///
/// Voir la documentation du module : il pose des questions, il n'interroge
/// personne.
pub struct Evaluator<'a> {
    contexte: Context<'a>,
    limits: Limits,
    frames: [Frame; MAX_DEPTH],
    profondeur: usize,
    etat: Etat,
    resolutions: u8,
    vides: u8,
    /// Le qualificateur du mécanisme dont on attend la réponse.
    qualificateur_en_cours: Qualifier,
    /// Ses préfixes (`a/24`, `mx//64`), retenus EN POSANT la question.
    ///
    /// La première version les relisait sur le terme précédent au retour de la
    /// réponse : deux lectures de la même politique, et un chemin d'erreur pour
    /// une relecture qui ne peut pas échouer. Les retenir coûte deux octets.
    prefixes_en_cours: (u8, u8),
    /// Le tampon d'expansion, réemployé à chaque question.
    expansion: Expanded,
}

impl<'a> Evaluator<'a> {
    /// Ouvre une évaluation pour `domain`.
    ///
    /// Le domaine est celui de l'expéditeur d'enveloppe — ou celui du `HELO`
    /// quand `MAIL FROM:<>` est nul (RFC 7208 §2.4). **C'est l'appelant qui
    /// choisit**, et [`Context::sender`] dit pourquoi.
    #[must_use]
    pub fn new(contexte: Context<'a>, domain: &[u8], limits: Limits) -> Self {
        let vide = Frame::vide(None, false);
        let mut evaluateur = Self {
            contexte,
            limits,
            frames: [vide; MAX_DEPTH],
            profondeur: 0,
            etat: Etat::Charger,
            resolutions: 0,
            vides: 0,
            qualificateur_en_cours: Qualifier::Pass,
            prefixes_en_cours: (32, 128),
            expansion: Expanded::new(),
        };
        match Frame::depuis_domaine(domain, false) {
            Some(trame) => evaluateur.frames[0] = trame,
            // Un domaine plus long qu'un nom de domaine ne désigne rien
            // d'interrogeable : `permerror`, et tout de suite.
            None => evaluateur.etat = Etat::Fini(Verdict::PermError),
        }
        evaluateur
    }

    /// Que faire maintenant ?
    ///
    /// Rappeler sans avoir répondu rend **la même question** : la méthode ne
    /// consomme rien, et un appelant qui recommence son tour de boucle ne perd
    /// pas sa place.
    pub fn poll(&mut self) -> Step {
        loop {
            match self.etat {
                Etat::Fini(verdict) => return Step::Done(verdict),
                Etat::Attente(kind) => return Step::Ask(self.question(kind)),
                Etat::Charger => {
                    // La toute première politique ne compte PAS dans les dix :
                    // la RFC 7208 §4.6.4 borne les mécanismes qui résolvent, et
                    // le domaine de départ n'en est pas un.
                    self.etat = Etat::Attente(Query::Txt);
                }
                Etat::Termes => self.avancer(),
            }
        }
    }

    /// Rend la réponse à la dernière question.
    ///
    /// Une réponse qui ne correspond pas à la question posée — des adresses là
    /// où l'on demandait des TXT — vaut [`Verdict::PermError`] : c'est un
    /// défaut de l'appelant, et le taire ferait conclure sur du vent.
    pub fn answer(&mut self, answer: Answer<'_>) {
        let Etat::Attente(kind) = self.etat else {
            // Une réponse qu'on n'attendait pas ne change rien.
            return;
        };
        if matches!(answer, Answer::TempError) {
            // Il remonte par la sortie commune : une panne dans un `include`
            // doit être la panne de toute l'évaluation, et le faire dire par le
            // même chemin que les autres verdicts évite d'avoir deux règles.
            self.terminer_trame(Verdict::TempError);
            return;
        }
        match (kind, answer) {
            (Query::Txt, Answer::Txt(records)) => self.charger(records),
            (Query::Txt, Answer::NotFound) => self.charger(&[]),
            (Query::Addresses | Query::MxAddresses, Answer::Addresses(adresses)) => {
                self.repondre_adresses(adresses);
            }
            (Query::Addresses | Query::MxAddresses, Answer::NotFound) => {
                self.vide_puis_avancer();
            }
            (Query::Exists, Answer::Exists(trouve)) => {
                if trouve {
                    self.conclure_mecanisme(true);
                } else {
                    self.vide_puis_avancer();
                }
            }
            (Query::Exists, Answer::NotFound) => self.vide_puis_avancer(),
            (Query::PtrNames, Answer::Names(noms)) => self.repondre_noms(noms),
            (Query::PtrNames, Answer::NotFound) => self.vide_puis_avancer(),
            _ => self.etat = Etat::Fini(Verdict::PermError),
        }
    }

    /// La question courante, nom compris.
    fn question(&self, kind: Query) -> Question {
        let trame = self.trame();
        let source: &[u8] = if kind == Query::Txt {
            trame.domaine()
        } else {
            self.expansion.as_bytes()
        };
        let mut nom = [0_u8; EXPANDED_MAX];
        let (cible, _) = nom.split_at_mut(source.len().min(EXPANDED_MAX));
        cible.copy_from_slice(source);
        Question {
            kind,
            nom,
            longueur: if kind == Query::PtrNames {
                // La résolution inverse porte sur l'ADRESSE du pair, que
                // l'appelant connaît déjà : lui rendre un nom vide vaut mieux
                // que lui en rendre un qui n'a pas servi.
                0
            } else {
                source.len()
            },
        }
    }

    /// La trame courante. `min` rend l'indexation totale sans ouvrir de
    /// branche à nous : `profondeur` est déjà borné par [`Self::empiler`].
    fn trame(&self) -> Frame {
        self.frames[self.profondeur.min(MAX_DEPTH - 1)]
    }

    /// La trame courante, pour l'écrire.
    fn trame_mut(&mut self) -> &mut Frame {
        &mut self.frames[self.profondeur.min(MAX_DEPTH - 1)]
    }

    /// Charge la politique trouvée dans les TXT d'un domaine.
    fn charger(&mut self, records: &[&[u8]]) {
        let mut trouvee: Option<&[u8]> = None;
        for brut in records {
            match Record::parse(brut, &self.limits) {
                // Un TXT qui parle d'autre chose n'est pas une faute : un
                // domaine en publie pour bien des raisons.
                Err(Error::NotSpf) => continue,
                // DEUX POLITIQUES, C'EST UNE QUESTION SANS RÉPONSE : la RFC
                // 7208 §4.5 veut `permerror`, et choisir à la place de
                // l'auteur serait pire.
                Ok(_) if trouvee.is_some() => {
                    self.etat = Etat::Fini(Verdict::PermError);
                    return;
                }
                Ok(_) => trouvee = Some(brut),
                Err(_) => {
                    self.etat = Etat::Fini(Verdict::PermError);
                    return;
                }
            }
        }

        let Some(politique) = trouvee else {
            // Aucune politique : `none`. Au départ, c'est le verdict — le
            // domaine ne dit rien. Après un `include` (§5.2) ou un `redirect=`
            // (§6.1), c'est une politique qui en désigne une qui n'existe pas,
            // et `terminer_trame` en fait un `permerror`. La règle est écrite
            // là-bas, une seule fois.
            self.terminer_trame(Verdict::None);
            return;
        };
        if politique.len() > RECORD_BUF {
            // Atteignable en desserrant `max_record_octets` au-delà du tampon :
            // on refuse plutôt que de tronquer, car une politique tronquée se
            // lirait comme une politique valide qui dit autre chose.
            self.etat = Etat::Fini(Verdict::PermError);
            return;
        }
        let trame = self.trame_mut();
        let (cible, _) = trame
            .politique
            .split_at_mut(politique.len().min(RECORD_BUF));
        cible.copy_from_slice(politique);
        trame.politique_len = politique.len();
        trame.terme = 0;
        trame.chargee = true;
        self.etat = Etat::Termes;
    }

    /// Examine le terme courant.
    fn avancer(&mut self) {
        let trame = self.trame();
        // La politique a été validée au chargement : la relire ne peut pas
        // échouer, et `map_or` porte l'impossible dans la bibliothèque standard
        // plutôt que dans une garde à nous.
        // La politique a été validée au chargement, et la trame en garde une
        // copie exacte : la relire ne peut pas échouer. `unwrap_or_default`
        // porte cette impossibilité dans la bibliothèque standard plutôt que
        // dans une garde à nous — UNE GARDE INATTEIGNABLE N'EST PAS UNE GARDE.
        let politique = Record::parse(trame.politique(), &self.limits).unwrap_or_default();
        let Some(terme) = politique.terms().nth(trame.terme) else {
            // Plus de mécanisme : reste le `redirect=`, s'il y en a un.
            self.apres_les_mecanismes(&politique);
            return;
        };
        self.avancer_le_terme();

        let Term::Mechanism {
            qualifier,
            mechanism,
        } = terme
        else {
            // Les modificateurs ne se lisent pas dans l'ordre : `redirect=` ne
            // s'applique qu'à la fin, et le reste s'ignore (RFC 7208 §6).
            return;
        };

        let (domaine, lookup) = match mechanism.resolve(self.contexte.client) {
            Resolution::Answered(true) => {
                self.terminer_trame(Verdict::du_qualificateur(qualifier));
                return;
            }
            Resolution::Answered(false) => return,
            Resolution::Needs { domain, lookup } => (domain, lookup),
        };

        // Un mécanisme qui résout : on prépare la question.
        self.qualificateur_en_cours = qualifier;
        self.prefixes_en_cours = (domaine.prefix4, domaine.prefix6);

        if self.resolutions >= self.limits.max_lookups {
            // LA LIMITE DES DIX. Elle n'est pas une commodité : sans elle, un
            // enregistrement hostile fait travailler le résolveur d'autrui.
            self.etat = Etat::Fini(Verdict::PermError);
            return;
        }
        self.resolutions = self.resolutions.saturating_add(1);

        if self.developper(&domaine).is_err() {
            self.etat = Etat::Fini(Verdict::PermError);
            return;
        }

        match lookup {
            // Un `include` : on empile une politique de plus.
            Lookup::Policy => self.empiler(qualifier),
            Lookup::Addresses => self.etat = Etat::Attente(Query::Addresses),
            Lookup::MxAddresses => self.etat = Etat::Attente(Query::MxAddresses),
            Lookup::Exists => self.etat = Etat::Attente(Query::Exists),
            Lookup::PtrNames => self.etat = Etat::Attente(Query::PtrNames),
        }
    }

    /// Développe le domaine d'un mécanisme, ou celui de la trame s'il est vide.
    fn developper(&mut self, domaine: &DomainSpec<'_>) -> Result<(), Error> {
        let courant = self.trame();
        if domaine.spec.is_empty() {
            // Sans domaine, c'est celui de la trame (RFC 7208 §5.3) — et il n'a
            // pas de macro à développer.
            return expand(
                courant.domaine(),
                &self.contexte,
                courant.domaine(),
                &mut self.expansion,
            );
        }
        expand(
            domaine.spec,
            &self.contexte,
            courant.domaine(),
            &mut self.expansion,
        )
    }

    /// Empile la politique d'un `include`.
    fn empiler(&mut self, qualifier: Qualifier) {
        let suivante = self.profondeur.saturating_add(1);
        if suivante >= MAX_DEPTH {
            // Avec les limites par défaut, la borne des résolutions arrive la
            // première. En les desserrant, c'est celle-ci qui tient — et elle
            // doit tenir, car sous elle il y a un tableau.
            self.etat = Etat::Fini(Verdict::PermError);
            return;
        }
        self.frames[suivante] = Frame::depuis_expansion(&self.expansion, Some(qualifier), false);
        self.profondeur = suivante;
        self.etat = Etat::Charger;
    }

    /// Passe au terme suivant de la trame courante.
    fn avancer_le_terme(&mut self) {
        let trame = self.trame_mut();
        trame.terme = trame.terme.saturating_add(1);
    }

    /// Plus aucun mécanisme : `redirect=`, ou le défaut.
    fn apres_les_mecanismes(&mut self, politique: &Record<'_>) {
        let redirection = politique.terms().find_map(|terme| match terme {
            Term::Modifier(Modifier::Redirect(domaine)) => Some(domaine),
            _ => None,
        });
        let Some(domaine) = redirection else {
            // RFC 7208 §4.7 : le défaut est `neutral`, comme si l'enregistrement
            // finissait par `?all`.
            self.terminer_trame(Verdict::Neutral);
            return;
        };

        // Le `redirect=` compte lui aussi dans les dix (§4.6.4).
        if self.resolutions >= self.limits.max_lookups {
            self.etat = Etat::Fini(Verdict::PermError);
            return;
        }
        self.resolutions = self.resolutions.saturating_add(1);

        let courant = self.trame();
        if expand(
            domaine,
            &self.contexte,
            courant.domaine(),
            &mut self.expansion,
        )
        .is_err()
        {
            self.etat = Etat::Fini(Verdict::PermError);
            return;
        }

        // UN `redirect=` REMPLACE la politique courante, il ne s'y ajoute pas :
        // son verdict devient le nôtre (RFC 7208 §6.1). La trame est donc
        // réécrite, et la profondeur ne bouge pas — ce qui rend impossible
        // qu'une chaîne de redirections fasse déborder la pile.
        *self.trame_mut() = Frame::depuis_expansion(&self.expansion, courant.include, true);
        self.etat = Etat::Charger;
    }

    /// Une réponse d'adresses : le mécanisme correspond-il ?
    fn repondre_adresses(&mut self, adresses: &[IpAddr]) {
        if adresses.is_empty() {
            self.vide_puis_avancer();
            return;
        }
        // Une adresse d'une autre famille que le pair ne correspond jamais
        // (RFC 7208 §5.3) : `meme_adresse` le dit, et le dit seule.
        let prefixes = self.prefixes_en_cours;
        let correspond = adresses
            .iter()
            .any(|adresse| crate::term::meme_adresse(*adresse, self.contexte.client, prefixes));
        self.conclure_mecanisme(correspond);
    }

    /// Une réponse de noms confirmés : l'un d'eux est-il sous le domaine ?
    fn repondre_noms(&mut self, noms: &[&[u8]]) {
        if noms.is_empty() {
            self.vide_puis_avancer();
            return;
        }
        // RFC 7208 §5.5 : le nom doit être le domaine, ou un sous-domaine.
        let cible = self.expansion;
        let correspond = noms.iter().any(|nom| sous_domaine(nom, cible.as_bytes()));
        self.conclure_mecanisme(correspond);
    }

    /// Le mécanisme a répondu.
    fn conclure_mecanisme(&mut self, correspond: bool) {
        if correspond {
            self.terminer_trame(Verdict::du_qualificateur(self.qualificateur_en_cours));
        } else {
            self.etat = Etat::Termes;
        }
    }

    /// Une résolution vide : on la compte, et on passe au terme suivant.
    fn vide_puis_avancer(&mut self) {
        self.vides = self.vides.saturating_add(1);
        if self.vides > self.limits.max_void_lookups {
            // RFC 7208 §4.6.4 : une politique qui accumule les noms inexistants
            // est soit fautive, soit hostile.
            self.etat = Etat::Fini(Verdict::PermError);
            return;
        }
        self.etat = Etat::Termes;
    }

    /// La trame courante a conclu : on remonte.
    fn terminer_trame(&mut self, verdict: Verdict) {
        let trame = self.trame();
        // Un `redirect=` vers un domaine sans politique vaut `permerror`
        // (RFC 7208 §6.1), là où l'absence au départ vaut `none`.
        let verdict = if trame.via_redirect && verdict == Verdict::None {
            Verdict::PermError
        } else {
            verdict
        };

        let Some(qualifier) = trame.include else {
            self.etat = Etat::Fini(verdict);
            return;
        };

        // RFC 7208 §5.2 : un `include` correspond SI ET SEULEMENT SI la
        // politique incluse rend `pass`. Tout le reste ne correspond pas — sauf
        // les erreurs, qui remontent telles quelles.
        self.profondeur = self.profondeur.saturating_sub(1);
        match verdict {
            // L'`include` a correspondu : c'est SON qualificateur qui décide,
            // et la trame PARENTE conclut — récursivement, car elle peut
            // elle-même être un `include`.
            Verdict::Pass => self.terminer_trame(Verdict::du_qualificateur(qualifier)),
            Verdict::Fail | Verdict::SoftFail | Verdict::Neutral => self.etat = Etat::Termes,
            Verdict::TempError => self.etat = Etat::Fini(Verdict::TempError),
            Verdict::None | Verdict::PermError => self.etat = Etat::Fini(Verdict::PermError),
        }
    }
}

/// `nom` est-il `domaine` ou l'un de ses sous-domaines ?
fn sous_domaine(nom: &[u8], domaine: &[u8]) -> bool {
    if nom.eq_ignore_ascii_case(domaine) {
        return true;
    }
    // `a.example.com` est sous `example.com` ; `badexample.com` ne l'est pas —
    // le point compte, et l'oublier autoriserait qui enregistre un nom qui
    // finit par le nôtre.
    let Some(reste) = nom.len().checked_sub(domaine.len()) else {
        return false;
    };
    let Some(reste) = reste.checked_sub(1) else {
        return false;
    };
    nom.get(reste) == Some(&b'.')
        && nom
            .get(reste.saturating_add(1)..)
            .is_some_and(|queue| queue.eq_ignore_ascii_case(domaine))
}

#[cfg(test)]
mod tests;
