//! La machine à états d'une session SMTP, **sans entrée-sortie**.

use ams_proto_smtp::{
    ChunkEvent, ChunkReceiver, Class, ClientId, Code, Command, DataEvent, DataFault, DataReceiver,
    ENVID_MAX, Error as SmtpError, Notify, ORCPT_MAX, Parameter, Parameters, Path, Ret, Status,
    decode_xtext, encode, parse_orcpt,
};
use ams_sasl::{decode_base64, parse_plain};
use core::net::IpAddr;

use ams_mime::{Received, Transport, write_received, write_return_path};
use ams_spf::{Identity, ReceivedSpf, Verdict, write_received_spf};

use crate::digits::{MAX_DIGITS, decimal};
use crate::sauts::Sauts;
use crate::tampon::Tampon;
use crate::{Config, Error, Policy, RecipientVerdict, Recipients, SenderPolicy};

/// La bannière : le domaine (255 au plus) suivi de `" ESMTP"`.
const BANNER_MAX: usize = 255 + 6;
/// La ligne `SIZE` : le mot-clé, une espace, et vingt chiffres au plus.
const SIZE_LINE_MAX: usize = 5 + MAX_DIGITS;
/// Ce qu'une réponse SASL peut faire, une fois décodée.
///
/// Fixe, parce que cette crate n'alloue pas (C3). Cinq cent douze octets
/// majorent très largement une réponse `PLAIN` réelle — un nom de compte et un
/// mot de passe — et laissent passer tout ce qu'une ligne de commande de la RFC
/// 5321 peut porter, dont le base64 ne rend que trois quarts.
const SASL_DECODED_MAX: usize = 512;

/// Ce qu'un nom de compte peut peser.
///
/// La borne d'une partie locale (RFC 5321 §4.5.3.1.1) : un compte se nomme comme
/// une boîte, et ce qui ne tient pas dans une adresse n'a pas à tenir ici.
const LOGIN_MAX: usize = 64;

/// La place d'une ligne de réponse, état étendu compris.
///
/// Le plus long texte du vocabulaire tient largement dedans ; ce qui n'y
/// tiendrait pas partirait sans son état, et non tronqué.
const LIGNE_MAX: usize = 256;

/// Combien de `Received:` un message a le droit de porter (RFC 5321 §6.3).
///
/// §6.3 veut « a large number », sans en fixer un ; trente est celui de Postfix
/// et de Sendmail. La valeur exacte n'a jamais compté pour personne : ce qui
/// compte est qu'il y en ait une, et qu'un message qui tourne finisse par
/// s'arrêter ailleurs que dans un disque plein.
pub const HOPS_MAX: u32 = 30;

/// Le nombre maximal de lignes d'un `EHLO` : domaine, `SIZE`, `8BITMIME`,
/// `ENHANCEDSTATUSCODES`, `PIPELINING`, `CHUNKING`, `DSN`, `STARTTLS`, `AUTH`.
const EHLO_LINES_MAX: usize = 9;

/// Ce qu'un nom de domaine peut faire (RFC 1035 §2.3.4).
const DOMAIN_MAX: usize = 255;

/// Ce qu'un expéditeur d'enveloppe peut faire : une partie locale (64 au plus,
/// RFC 5321 §4.5.3.1.1), un `@`, un domaine.
const SENDER_MAX: usize = 64 + 1 + DOMAIN_MAX;

/// Où en est la session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    /// La bannière est partie ; on attend `EHLO` ou `HELO`.
    Greeted,
    /// Le pair s'est nommé ; aucune transaction n'est ouverte.
    Identified,
    /// `MAIL FROM` accepté. `recipients` compte les `RCPT` acceptés.
    ///
    /// `chunked` retient qu'un `BDAT` a déjà été servi dans CETTE transaction :
    /// un `DATA` qui suivrait se disputerait le même message.
    Transaction { recipients: usize, chunked: bool },
    /// Un `AUTH` a été accepté : l'appelant conduit l'échange SASL.
    Auth,
    /// Un `DATA` a été accepté : l'appelant lit le message.
    Data,
    /// Le message porte plus de traces que §6.3 n'en tolère : il tourne en
    /// boucle. **Le verdict de l'appelant ne sera pas consulté.**
    Looped,
    /// Un morceau a été refusé par la grammaire. L'appelant finit de consommer
    /// les octets annoncés, puis rend la main ; **son verdict ne sera pas
    /// consulté**.
    ChunkFailed {
        /// Les destinataires de la transaction, pour la réponse.
        recipients: usize,
        /// Ce morceau était-il le dernier ?
        last: bool,
        /// Ce qui l'a fait refuser.
        cause: DataFault,
    },
    /// Un `BDAT` a été accepté : l'appelant lit **exactement** les octets
    /// annoncés.
    ///
    /// `recipients` est retenu ici parce qu'il faut y revenir quand le morceau
    /// n'est pas le dernier : la transaction continue, et le `RCPT` suivant —
    /// s'il y en avait un — doit compter à partir du même nombre.
    Chunk { recipients: usize, last: bool },
    /// Les données ont été refusées par la grammaire. La cause décide de la
    /// réponse, et **le verdict de l'appelant ne sera pas consulté**.
    DataFailed(DataFault),
    /// `QUIT` a été traité.
    Closed,
}

/// Ce que l'appelant doit faire après avoir émis la réponse.
///
/// Pas `#[non_exhaustive]`, pour la même raison que
/// [`Command`](ams_proto_smtp::Command) : une action nouvelle doit casser la
/// compilation de la boucle qui la pilote, pas tomber dans un bras `_`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Rien de particulier : lire la commande suivante.
    Continue,
    /// Conduire la poignée de main TLS, puis appeler
    /// [`SmtpSession::on_tls_established`].
    StartTls,
    /// Lire **une ligne de plus** et la passer à
    /// [`SmtpSession::feed_auth`] : le pair doit répondre au défi SASL.
    ///
    /// # Elle ne porte AUCUNE donnée, et c'est le sujet
    ///
    /// Une version antérieure passait à l'appelant le mécanisme et la réponse
    /// initiale, à charge pour lui de conduire l'échange. C'était mettre du
    /// protocole dans la boucle — base64, format de `PLAIN`, annulation par
    /// `*` — c'est-à-dire hors du périmètre couvert à 100 %, et à réécrire une
    /// seconde fois pour Air. L'échange est donc conduit par la session, et la
    /// boucle ne sait qu'une chose : lire une ligne de plus.
    ///
    /// C'est aussi ce qui a fait disparaître le paramètre de durée de vie
    /// d'`Action` : plus rien n'y emprunte la ligne de commande.
    ReadAuthResponse,
    /// **Vérifier l'expéditeur**, puis appeler [`SmtpSession::sender_checked`].
    ///
    /// # Elle ne porte AUCUNE réponse, et c'est le sujet
    ///
    /// Le tour qui rend cette action rend une réponse VIDE : la session n'a rien
    /// à dire tant qu'elle ne sait pas. C'est l'appelant qui résout — SPF veut
    /// le DNS, et le DNS est une entrée-sortie — puis lui rend le verdict, et
    /// c'est ELLE qui compose le `250`, le `550` ou le `451`. Le vocabulaire de
    /// sortie reste clos (C1).
    ///
    /// L'identité à vérifier se lit sur [`SmtpSession::sender_identity`] : la
    /// faire porter par l'action l'aurait fait emprunter la ligne de commande,
    /// que l'appelant recouvre en lisant la suivante.
    CheckSender,
    /// Lire le message jusqu'à `<CRLF>.<CRLF>`.
    ReceiveData,
    /// Lire **exactement** `size` octets, puis rendre la main (RFC 3030 §2).
    ///
    /// # LE NOMBRE VIENT DE LA COMMANDE, ET IL N'Y A RIEN À CHERCHER
    ///
    /// C'est toute la différence avec [`Action::ReceiveData`] : il n'y a pas de
    /// délimiteur à trouver dans le flux, donc pas d'endroit où deux serveurs
    /// pourraient couper différemment. Ce qui suit ces octets est une COMMANDE,
    /// et en lire un de plus la ferait passer pour des données.
    ///
    /// L'appelant lit ces octets **même s'il en refuse le contenu** : ils sont
    /// annoncés, et ne pas les consommer laisserait la queue du morceau se faire
    /// lire comme des commandes. Il rend ensuite la main par
    /// [`SmtpSession::on_chunk_received`] si `last` est faux, et par
    /// [`SmtpSession::on_data_settled`] s'il est vrai — c'est alors un message
    /// entier, remis comme celui d'un `DATA`.
    ReceiveChunk {
        /// Le nombre d'octets à lire, exactement.
        size: u64,
        /// Ce morceau termine-t-il le message ?
        last: bool,
    },
    /// Fermer la connexion.
    Close,
}

/// Ce qu'un paramètre ESMTP vaut pour nous.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Verdict7 {
    /// Compris, et rien de plus à faire.
    Compris,
    /// Compris, et c'est l'identifiant d'enveloppe — sa longueur, DÉCODÉE.
    ///
    /// Le décoder une seconde fois chez l'appelant ouvrirait la porte à deux
    /// lectures d'un même xtext.
    Envid(usize),
    /// Compris, et le message annoncé dépasse ce qu'on accepte (RFC 1870 §6.2).
    TropGros,
    /// **On ne le connaît pas.** RFC 5321 §4.1.1.11 veut un `555`.
    Inconnu,
}

/// Ce que ce serveur fait des paramètres d'un `MAIL FROM:` (§4.1.1.11).
///
/// # ON N'ACCEPTE QUE CE QU'ON TIENT
///
/// Un paramètre accepté en silence est une promesse qu'on n'a pas faite et que
/// le pair croit avoir reçue. `NOTIFY=NEVER` en est l'exemple qui coûte : un
/// expéditeur qui le pose croit avoir supprimé ses rapports de non-remise, et
/// les recevra quand même. Mieux vaut un refus franc.
///
/// `SIZE` est vérifié parce qu'il est ANNONCÉ. Un serveur qui offre `SIZE` et ne
/// s'en sert pas fait lire au pair un mébioctet qu'il a déjà décidé de refuser.
fn verdict_du_parametre_mail(
    parametre: &Parameter<'_>,
    max_message: u64,
    dsn: bool,
    envid: &mut [u8; ENVID_MAX],
) -> Verdict7 {
    let mot = parametre.keyword();
    // ── RFC 3461, et seulement si on l'annonce ──────────────────────────────
    //
    // **UN PARAMÈTRE QU'ON N'ANNONCE PAS SE REFUSE.** Sans file, ce serveur ne
    // peut émettre aucun rapport : accepter `RET=` reviendrait à promettre un
    // rapport qui ne partira jamais.
    if mot.eq_ignore_ascii_case(b"RET") {
        return match parametre.value() {
            Some(valeur) if dsn && Ret::parse(valeur).is_ok() => Verdict7::Compris,
            _ => Verdict7::Inconnu,
        };
    }
    if mot.eq_ignore_ascii_case(b"ENVID") {
        // **IL RESSORT DANS UN RAPPORT QUE NOUS COMPOSONS.** Un `CRLF` glissé
        // dedans écrirait des champs de statut à notre place ; le xtext de §4
        // l'interdit, et on le vérifie ici plutôt que de le supposer.
        let Some(valeur) = parametre.value() else {
            return Verdict7::Inconnu;
        };
        return match decode_xtext(valeur, envid) {
            Ok(decode) if dsn && !decode.is_empty() => Verdict7::Envid(decode.len()),
            _ => Verdict7::Inconnu,
        };
    }
    if mot.eq_ignore_ascii_case(b"SIZE") {
        // **UNE TAILLE ILLISIBLE N'EST PAS UNE TAILLE DE ZÉRO.** Un pair qui
        // écrit `SIZE=abc` n'a pas annoncé une petite taille : il a écrit
        // n'importe quoi, et §6.2 de RFC 1870 veut des chiffres.
        let Some(valeur) = parametre.value() else {
            return Verdict7::Inconnu;
        };
        let Some(taille) = decimal_u64(valeur) else {
            return Verdict7::Inconnu;
        };
        if taille > max_message {
            return Verdict7::TropGros;
        }
        return Verdict7::Compris;
    }
    if mot.eq_ignore_ascii_case(b"BODY") {
        // RFC 6152 : `8BITMIME` ou `7BIT`, et rien d'autre. La phase de données
        // est propre sur huit bits — elle n'y touche pas — donc les deux
        // conviennent.
        return match parametre.value() {
            Some(valeur)
                if valeur.eq_ignore_ascii_case(b"8BITMIME")
                    || valeur.eq_ignore_ascii_case(b"7BIT") =>
            {
                Verdict7::Compris
            }
            _ => Verdict7::Inconnu,
        };
    }
    if mot.eq_ignore_ascii_case(b"AUTH") {
        // **ON L'ACCEPTE SANS S'Y FIER** (RFC 4954 §5). C'est l'identité que le
        // pair PRÉTEND avoir authentifiée en amont, et rien ne l'atteste ; §5
        // veut qu'un serveur qui annonce `AUTH` l'accepte, et lui laisse le
        // droit de ne pas la croire. Ce serveur ne la croit pas.
        return Verdict7::Compris;
    }
    Verdict7::Inconnu
}

/// Un entier décimal, ou `None` si ce n'en est pas un.
///
/// Un débordement est un refus, et non une troncature : une taille annoncée plus
/// petite qu'elle ne l'est ferait passer la vérification de §6.2.
fn decimal_u64(octets: &[u8]) -> Option<u64> {
    if octets.is_empty() || !octets.iter().all(u8::is_ascii_digit) {
        return None;
    }
    let mut valeur = 0_u64;
    for chiffre in octets {
        valeur = valeur
            .checked_mul(10)?
            .checked_add(u64::from(chiffre.wrapping_sub(b'0')))?;
    }
    Some(valeur)
}

/// L'état étendu d'une réponse (RFC 3463), ou `None` pour une `3xx`.
///
/// # POURQUOI UNE TABLE, ET UNE SEULE
///
/// Un même refus doit rendre le même état partout. Le composer sur place, à
/// chacun des cinquante-cinq endroits qui répondent, aurait fini par donner deux
/// états au même sens — et c'est exactement ce qu'un lecteur automatique ne
/// pardonne pas : il trie sur l'état, pas sur le texte.
///
/// # CE QUI N'EST PAS NOMMÉ PREND LE SUJET « INDÉFINI »
///
/// `x.0.0` veut dire « autre, ou indéfini » (§3.3 de RFC 3463) : ce n'est pas un
/// défaut silencieux, c'est la réponse juste quand on n'a rien de plus précis à
/// dire. La CLASSE, elle, n'est jamais devinée — elle vient du code à trois
/// chiffres, et [`Status::agrees_with`] le vérifie.
fn statut_de(code: Code, texte: &[u8]) -> Option<Status> {
    let precis = match texte {
        b"Sender ok" => Some(Status::SENDER_OK),
        b"Recipient ok" => Some(Status::RECIPIENT_OK),
        b"Authentication successful" => Some(Status::SECURITY_OK),
        b"Mailbox unavailable" => Some(Status::MAILBOX_UNAVAILABLE),
        b"Relay access denied"
        | b"Message rejected"
        | b"Encryption required for authentication"
        | b"Authentication credentials invalid" => Some(Status::POLICY),
        b"Unrecognized authentication type" | b"Authentication aborted" => Some(Status::SECURITY),
        b"Mailbox busy, try again later" => Some(Status::MAILBOX_BUSY),
        b"Too many recipients" => Some(Status::TOO_MANY_RECIPIENTS),
        b"Message exceeds maximum size" => Some(Status::MESSAGE_TOO_LARGE),
        b"Too many hops; message is looping" => Some(Status::TOO_MANY_HOPS),
        b"Bare CR or LF in message data" => Some(Status::BAD_CONTENT),
        b"Command not recognised" => Some(Status::UNKNOWN_COMMAND),
        b"Line too long"
        | b"Line must end with CRLF"
        | b"Syntax error in parameters or arguments" => Some(Status::SYNTAX_ERROR),
        b"Command not implemented" | b"EXPN not available" | b"Parameter not recognised" => {
            Some(Status::BAD_PARAMETER)
        }
        b"Already authenticated"
        | b"Nested MAIL command"
        | b"Need MAIL before RCPT"
        | b"Need RCPT before DATA"
        | b"Need MAIL and RCPT before BDAT"
        | b"Need RCPT before BDAT"
        | b"BDAT already started; finish with BDAT LAST"
        | b"Send EHLO first"
        | b"TLS already active" => Some(Status::BAD_SEQUENCE),
        b"Message not accepted, try again later" => Some(Status::NOT_ACCEPTING),
        // Les trois réponses de SPF et de DMARC portaient leur code DANS leur
        // texte, écrit à la main. Elles passent par la table comme les autres :
        // deux endroits qui décident du même état finissent par en donner deux.
        b"Message rejected: sender domain policy (DMARC)" => Some(Status::POLICY),
        b"Sender address rejected: not authorized by SPF" => Some(Status::SPF_REFUSED),
        b"Temporary error while checking SPF, try again later" => Some(Status::DNS_TEMP),
        b"Service not available, closing transmission channel" => Some(Status::NOT_ACCEPTING),
        _ => None,
    };
    if let Some(statut) = precis
        && statut.agrees_with(code)
    {
        return Some(statut);
    }
    // **LA CLASSE VIENT DU CODE, JAMAIS DU TEXTE.** Un `550 4.x.x` ferait
    // réessayer un pair qu'on refuse définitivement.
    match code.class() {
        Class::Positive => Some(Status::OK),
        Class::TransientFailure => Some(Status::LOCAL_ERROR),
        Class::PermanentFailure => Some(Status::POLICY_OTHER),
        // §4 de RFC 2034 : les `3xx` n'en portent pas, et RFC 3463 ne définit
        // aucune classe `3`. Ce sont des invitations à continuer, pas des
        // verdicts.
        Class::Intermediate => None,
    }
}

/// Écrit `<état> <texte>` dans `ligne`, et le rend.
///
/// Rend `None` si la place manque — le texte part alors SANS son état, plutôt
/// que tronqué : une réponse amputée serait pire qu'une réponse sans code
/// étendu.
fn prefixer<'l>(ligne: &'l mut [u8], statut: Status, texte: &[u8]) -> Option<&'l [u8]> {
    let ecrits = statut.write(ligne).ok()?.len();
    *ligne.get_mut(ecrits)? = b' ';
    let apres = ecrits.saturating_add(1);
    let fin = apres.saturating_add(texte.len());
    ligne.get_mut(apres..fin)?.copy_from_slice(texte);
    ligne.get(..fin)
}

/// L'identité que SPF vérifie (RFC 7208 §2.4).
///
/// # Pourquoi TROIS champs pour une seule question
///
/// SPF interroge **un domaine**, mais ses macros (§7) parlent aussi de
/// l'expéditeur entier — `%{l}` en veut la partie locale, `%{o}` le domaine — et
/// du nom annoncé au `HELO`, `%{h}`. Les trois viennent d'endroits différents de
/// la session, et c'est elle qui sait lesquels : la boucle ne les reconstituerait
/// qu'en refaisant sa grammaire.
///
/// # Le cas de l'expéditeur nul
///
/// `MAIL FROM:<>` est l'avis de non-remise : il n'a pas de domaine à vérifier.
/// La RFC 7208 §2.4 veut alors qu'on vérifie **le domaine du `HELO`**, avec
/// `postmaster@<helo>` pour expéditeur. Sans cette règle, un avis de non-remise
/// échapperait entièrement à SPF — et c'est précisément la forme qu'emprunte la
/// rétrodiffusion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SenderIdentity<'s> {
    /// Le domaine dont on lira la politique.
    pub domain: &'s [u8],
    /// `local@domaine`, pour les macros.
    pub sender: &'s [u8],
    /// Le nom annoncé au `HELO`, pour `%{h}`.
    pub helo: &'s [u8],
    /// LAQUELLE des deux identités a été vérifiée.
    ///
    /// Un rapport DMARC doit le dire (`<scope>`), et un journal a tout intérêt
    /// à le dire aussi : « SPF a réussi » ne veut pas la même chose selon qu'il
    /// s'agit de l'enveloppe ou d'un nom annoncé au `HELO`, que personne ne
    /// vérifie par ailleurs.
    pub scope: Identity,
}

/// Ce que l'appelant a fait du message reçu.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataOutcome {
    /// Le message est pris en charge. Le pair n'a plus à s'en occuper.
    Accepted,
    /// Refusé **définitivement**.
    RejectedPermanent,
    /// Refusé parce que **le domaine d'auteur le demande** (DMARC, RFC 7489).
    ///
    /// # Pourquoi une issue à part
    ///
    /// Le pair n'a rien fait de mal : son message est syntaxiquement correct, et
    /// la remise aurait réussi. Ce qui le refuse, c'est la politique publiée par
    /// le domaine qu'il affiche dans son `From:` — et lui dire « transaction
    /// échouée » l'enverrait chercher la faute là où elle n'est pas. RFC 7489
    /// §10.3 veut un `550 5.7.1`, et c'est ce qu'on répond.
    RejectedByPolicy,
    /// Refusé **pour l'instant** : le pair doit réessayer.
    RejectedTemporary,
}

/// Une réponse à émettre, et ce qu'il faut faire ensuite.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Turn<'b> {
    reply: &'b [u8],
    action: Action,
    peer_fault: bool,
    refused_recipient: bool,
}

impl<'b> Turn<'b> {
    /// Les octets à émettre, tels quels.
    #[must_use]
    pub fn reply(&self) -> &'b [u8] {
        self.reply
    }

    /// Ce qu'il faut faire **après** les avoir émis.
    #[must_use]
    pub fn action(&self) -> Action {
        self.action
    }

    /// Cette réponse sanctionne-t-elle une faute du pair ?
    ///
    /// # À quoi elle sert, et pourquoi la session doit la rendre
    ///
    /// C8 compte les « trames invalides » par source. La boucle ne peut pas le
    /// déduire d'un code de réponse : `502` sanctionne un verbe retiré par la
    /// RFC — une faute — mais aussi un `EXPN` qu'on décline poliment, qui n'en
    /// est pas une. Seul l'endroit qui compose la réponse sait laquelle des deux
    /// c'est, et le faire deviner à la boucle y remettrait du protocole.
    ///
    /// **Vrai pour** : syntaxe irrecevable, verbe inconnu ou retiré, mauvaise
    /// séquence, extension non annoncée, données refusées par la grammaire.
    ///
    /// **Faux pour** : tout le reste, y compris les refus LÉGITIMES — boîte
    /// inconnue, relais refusé, trop de destinataires, `VRFY`/`EXPN` déclinés.
    /// Un expéditeur qui se trompe d'adresse n'est pas un attaquant.
    ///
    /// **Ce que cela ne couvre pas** : un destinataire refusé n'est pas compté,
    /// alors qu'une rafale de refus est la signature d'une récolte d'adresses.
    /// Cela mérite un compteur à soi, avec son propre seuil ; le mêler à celui-ci
    /// bannirait des expéditeurs légitimes. Ce n'est pas fait.
    #[must_use]
    pub fn peer_fault(&self) -> bool {
        self.peer_fault
    }

    /// Cette réponse a-t-elle refusé un destinataire, DÉFINITIVEMENT ?
    ///
    /// # UN REFUS N'EST PAS UNE FAUTE, ET UNE RAFALE N'EST PAS UN REFUS
    ///
    /// Un expéditeur qui se trompe d'adresse n'est pas un attaquant :
    /// [`Turn::peer_fault`] reste faux, et il doit le rester. Mais une RAFALE de
    /// refus est la signature d'une récolte d'adresses — le pair ne cherche pas à
    /// écrire, il cherche à savoir QUI EXISTE, et chaque refus est une réponse
    /// qu'il note.
    ///
    /// La boucle a donc besoin des deux signaux, et la session est la seule à
    /// pouvoir les distinguer : un `550` sanctionne une boîte inconnue, mais
    /// aussi un verbe qu'on refuse, et le code ne dit pas lequel.
    ///
    /// **SEULS LES REFUS DÉFINITIFS COMPTENT.** Un `450` dit que NOUS ne pouvons
    /// pas, pas que l'adresse n'existe pas : il n'apprend rien à qui récolte, et
    /// le compter punirait un pair pour nos propres embarras.
    #[must_use]
    pub fn refused_recipient(&self) -> bool {
        self.refused_recipient
    }
}

/// Une session SMTP côté serveur.
///
/// # Elle ne fait aucune entrée-sortie
///
/// Elle reçoit une ligne, rend des octets à émettre et une action. Elle
/// n'attend jamais, ne lit rien, n'écrit nulle part. C'est ce qui la rend
/// pilotable pas à pas depuis un test, donc couvrable à 100 % (C2).
///
/// # Elle n'échappe JAMAIS ce que le pair a envoyé
///
/// Aucune réponse ne contient de donnée venue du client — pas d'adresse
/// reprise, pas de commande citée, pas de détail d'erreur d'analyse. C'est ce
/// qui rend l'injection de réponse inexprimable ici, plutôt que seulement
/// refusée par l'encodeur. Cela prive le pair d'un diagnostic précis, et c'est
/// un prix assumé : ce qu'il a envoyé, il le sait déjà.
pub struct SmtpSession<'a, P: Policy> {
    config: Config<'a>,
    policy: P,
    phase: Phase,
    tls: bool,
    authenticated: bool,
    /// L'identifiant d'enveloppe du déposant (RFC 3461 §4.4), décodé.
    ///
    /// Il vaut pour la TRANSACTION, contrairement à `NOTIFY` et `ORCPT` qui
    /// valent par destinataire — c'est §4.4 qui le dit, et cela se comprend :
    /// il désigne l'envoi, pas un de ses destinataires.
    envid: [u8; ENVID_MAX],
    envid_len: usize,
    /// Les `Received:` du message en cours (RFC 5321 §6.3).
    sauts: Sauts,
    /// Le pair s'est-il nommé par `EHLO` plutôt que par `HELO` ?
    ///
    /// C'est ce que le mot de RFC 3848 distingue dans l'en-tête `Received:` :
    /// `ESMTP` contre `SMTP`. La différence n'a l'air de rien, et c'est
    /// pourtant la seule trace qu'un pair n'a pas su parler ESMTP.
    esmtp: bool,
    /// Les destinataires acceptés de la transaction en cours.
    recipients: Recipients,
    data: DataReceiver,
    /// Le récepteur de morceaux, quand le message arrive par `BDAT`.
    ///
    /// **Il vit le temps d'une TRANSACTION**, et non d'un morceau : c'est lui
    /// qui compte les octets du message entier, et qui voit un `CRLF` coupé par
    /// une frontière de `BDAT`.
    chunk: ChunkReceiver,
    banner: [u8; BANNER_MAX],
    banner_len: usize,
    size_line: [u8; SIZE_LINE_MAX],
    size_len: usize,
    /// Le nom annoncé au `HELO`, s'il en est un — vide pour un littéral
    /// d'adresse, qui ne désigne aucune politique.
    helo: Tampon<DOMAIN_MAX>,
    /// L'expéditeur de la transaction en cours, sous la forme `local@domaine`.
    expediteur: Tampon<SENDER_MAX>,
    /// Le `MAIL FROM:` de la transaction, retenu QUOI QU'IL ARRIVE.
    ///
    /// # POURQUOI IL NE SE CONFOND PAS AVEC [`SmtpSession::expediteur`]
    ///
    /// Celui-là ne se remplit que lorsqu'une politique d'expéditeur est en
    /// vigueur, et il porte l'identité que SPF doit VÉRIFIER — c'est-à-dire, pour
    /// un chemin nul, `postmaster@` suivi du `HELO`, qui n'est pas ce que le pair
    /// a écrit.
    ///
    /// Celui-ci porte ce que le pair a écrit, et rien d'autre. C'est l'adresse à
    /// laquelle un rapport de non-remise reviendra, et l'inventer serait
    /// l'envoyer à quelqu'un qui n'a rien demandé.
    chemin_de_retour: Tampon<SENDER_MAX>,
    /// Le compte qui s'est authentifié, s'il y en a un.
    ///
    /// # POURQUOI LE RETENIR, ET NON SEULEMENT UN BOOLÉEN
    ///
    /// « Authentifié » suffit à décider si l'on relaie. Il ne suffit PAS à
    /// décider au nom de QUI l'on relaie : un compte authentifié qui écrit
    /// `From: patron@example.com` obtiendrait, sans cela, notre signature DKIM
    /// sur une adresse qui n'est pas la sienne. Le booléen ouvre la porte ; le
    /// nom dit ce qu'on a le droit d'affirmer en la franchissant.
    compte: Tampon<LOGIN_MAX>,
    /// Le chemin de retour TEL QU'IL A ÉTÉ ÉCRIT, pour le `Return-Path:`.
    ///
    /// # POURQUOI UN SECOND TAMPON, ET NON `chemin_de_retour`
    ///
    /// Celui-là ne retient que ce à quoi un rapport pourrait REVENIR : ni un
    /// chemin nul, ni un littéral d'adresse. Le `Return-Path:` de §4.4, lui, ne
    /// consigne pas où l'on répondrait, il consigne CE QUE LE PAIR A DIT — et
    /// les deux ne coïncident pas.
    ///
    /// Les confondre écrirait `<>` pour `jean@[192.0.2.1]`, c'est-à-dire « ceci
    /// est un rapport, ne me réponds pas » (§2 de RFC 3834) sur un message
    /// ordinaire. Un mensonge silencieux, et de ceux qui font taire un
    /// répondeur.
    depose: Tampon<SENDER_MAX>,
    /// Un `MAIL FROM:` a-t-il été accepté dans la transaction en cours ?
    ///
    /// **C'est ce qui distingue `<>` de « rien du tout »** : `depose` est vide
    /// dans les deux cas, et seul l'un des deux mérite un en-tête.
    depose_vu: bool,
    /// Le domaine dont SPF lira la politique.
    domaine_verifie: Tampon<DOMAIN_MAX>,
    /// Le verdict rendu par l'appelant pour cette transaction.
    verdict: Option<Verdict>,
    /// L'identité vérifiée était-elle celle du `HELO` ?
    ///
    /// C'est le cas de l'expéditeur nul (RFC 7208 §2.4), et l'en-tête
    /// `Received-SPF` doit le DIRE : ne pas le dire ferait croire que l'adresse
    /// de l'enveloppe a été vérifiée.
    identite_helo: bool,
}

impl<'a, P: Policy> SmtpSession<'a, P> {
    /// Ouvre une session.
    ///
    /// La bannière et la ligne `SIZE` sont composées **une fois**, ici : elles ne
    /// changent pas, et les recomposer à chaque `EHLO` serait du travail offert à
    /// qui envoie mille `EHLO`.
    #[must_use]
    pub fn new(config: Config<'a>, policy: P) -> Self {
        let domaine = config.domain();
        let mut banner = [0_u8; BANNER_MAX];
        // `Config::new` a borné le domaine à 255 octets : la bannière tient.
        let fin_domaine = domaine.len();
        banner[..fin_domaine].copy_from_slice(domaine);
        let fin_banniere = fin_domaine.saturating_add(6);
        banner[fin_domaine..fin_banniere].copy_from_slice(b" ESMTP");

        let mut size_line = [0_u8; SIZE_LINE_MAX];
        size_line[..5].copy_from_slice(b"SIZE ");
        let mut chiffres = [0_u8; MAX_DIGITS];
        let debut = decimal(config.max_message_octets(), &mut chiffres);
        let ecrits = MAX_DIGITS.saturating_sub(debut);
        let fin_size = ecrits.saturating_add(5);
        size_line[5..fin_size].copy_from_slice(&chiffres[debut..]);

        Self {
            config,
            policy,
            phase: Phase::Greeted,
            data: DataReceiver::new(config.limits(), config.max_message_octets()),
            chunk: ChunkReceiver::new(config.limits(), config.max_message_octets()),
            tls: false,
            authenticated: false,
            envid: [0; ENVID_MAX],
            envid_len: 0,
            sauts: Sauts::new(),
            esmtp: false,
            recipients: Recipients::new(),
            banner,
            banner_len: fin_banniere,
            size_line,
            size_len: fin_size,
            helo: Tampon::vide(),
            expediteur: Tampon::vide(),
            compte: Tampon::vide(),
            chemin_de_retour: Tampon::vide(),
            depose: Tampon::vide(),
            depose_vu: false,
            domaine_verifie: Tampon::vide(),
            verdict: None,
            identite_helo: false,
        }
    }

    /// La bannière d'accueil, à émettre **avant** toute commande.
    ///
    /// # Errors
    ///
    /// [`Error::Reply`] si `out` est trop petit.
    pub fn greeting<'b>(&self, out: &'b mut [u8]) -> Result<&'b [u8], Error> {
        let banniere = self.banner.get(..self.banner_len).unwrap_or_default();
        encode(out, Code::SERVICE_READY, &[banniere], self.config.limits()).map_err(Error::Reply)
    }

    /// La réponse à émettre avant de fermer une connexion qu'on ne peut pas
    /// servir : garde anti-flooding, arrêt du service, saturation.
    ///
    /// # Pourquoi elle vient d'ici et non de la boucle
    ///
    /// La boucle ne compose aucune réponse — c'est ce qui garde le vocabulaire de
    /// sortie CLOS, et donc l'écho inexprimable. Un `421` fabriqué là-bas serait
    /// la première fuite de protocole hors des crates sans entrée-sortie.
    ///
    /// # Errors
    ///
    /// [`Error::Reply`] si `out` est trop petit.
    pub fn unavailable<'b>(&self, out: &'b mut [u8]) -> Result<&'b [u8], Error> {
        // **ELLE PASSE PAR `compose`, COMME LES AUTRES.** Elle composait sa
        // réponse à part, et repartait donc SANS code étendu le jour où toutes
        // les autres en ont eu un — un refus de service est une réponse comme
        // les autres, et un lecteur automatique trie sur l'état.
        Ok(self
            .compose(
                Code::SERVICE_CLOSING,
                b"Service not available, closing transmission channel",
                Action::Close,
                false,
                out,
            )?
            .reply)
    }

    /// La poignée de main TLS a abouti.
    ///
    /// **Toute la session est remise à zéro**, et ce n'est pas une précaution :
    /// la RFC 3207 §4.2 l'exige. Ce qu'un pair a dit en clair a pu être dit par
    /// quelqu'un d'autre ; le conserver après le chiffrement reviendrait à
    /// authentifier de la parole non protégée. Le pair doit renvoyer `EHLO`.
    pub fn on_tls_established(&mut self) {
        self.tls = true;
        self.authenticated = false;
        // **L'IDENTITÉ TOMBE AVEC L'AUTHENTIFICATION.** La laisser derrière
        // ferait écrire au nom du compte précédent après un `STARTTLS`, qui
        // remet tout à zéro (§4.2 de RFC 3207).
        self.compte.vider();
        self.quitter_la_transaction();
        self.phase = Phase::Greeted;
    }

    /// Le message a été lu : rend la réponse à émettre.
    ///
    /// C'est ici que la transaction se termine. La session revient à l'état
    /// identifié : le pair peut enchaîner un autre `MAIL` sans se renommer.
    ///
    /// # Errors
    ///
    /// [`Error::NotInCommandPhase`] si aucun `DATA` n'est en cours.
    pub fn on_data_settled<'b>(
        &mut self,
        outcome: DataOutcome,
        out: &'b mut [u8],
    ) -> Result<Turn<'b>, Error> {
        let refus = match self.phase {
            Phase::Looped => {
                self.quitter_la_transaction();
                return self.refus(
                    Code::TRANSACTION_FAILED,
                    b"Too many hops; message is looping",
                    out,
                );
            }
            Phase::Data | Phase::Chunk { last: true, .. } => None,
            Phase::DataFailed(cause)
            | Phase::ChunkFailed {
                last: true, cause, ..
            } => Some(cause),
            _ => return Err(Error::NotInCommandPhase),
        };
        self.quitter_la_transaction();
        // UN MESSAGE REFUSÉ PAR LA GRAMMAIRE NE PEUT PAS ÊTRE ACCEPTÉ PAR
        // L'APPELANT : le verdict n'est pas consulté. Sans cela, une boucle
        // distraite pourrait remettre un message que le décodeur a rejeté.
        if let Some(cause) = refus {
            return match cause {
                DataFault::BareLineEnding => self.refus(
                    Code::TRANSACTION_FAILED,
                    b"Bare CR or LF in message data",
                    out,
                ),
                DataFault::LineTooLong { .. } => {
                    self.refus(Code::SYNTAX_ERROR, b"Line too long", out)
                }
                DataFault::MessageTooLarge { .. } => self.refus(
                    Code::MESSAGE_TOO_LARGE,
                    b"Message exceeds maximum size",
                    out,
                ),
            };
        }
        match outcome {
            DataOutcome::Accepted => self.simple(Code::OK, b"Message accepted", out),
            DataOutcome::RejectedPermanent => {
                self.simple(Code::TRANSACTION_FAILED, b"Message rejected", out)
            }
            // On NOMME la raison : le pair doit pouvoir corriger, et il ne
            // corrigera pas ce qu'il ne sait pas.
            DataOutcome::RejectedByPolicy => self.simple(
                Code::MAILBOX_UNAVAILABLE,
                b"Message rejected: sender domain policy (DMARC)",
                out,
            ),
            DataOutcome::RejectedTemporary => self.simple(
                Code::LOCAL_ERROR,
                b"Message not accepted, try again later",
                out,
            ),
        }
    }

    /// Fournit des octets de la phase de données.
    ///
    /// Rend l'événement et le nombre d'octets **consommés** — qui n'est pas celui
    /// des octets rendus : un point échappé est consommé sans être rendu.
    ///
    /// # Errors
    ///
    /// [`Error::NotInDataPhase`] hors de la phase de données, et
    /// [`Error::DataRefused`] quand le pair a envoyé ce que la grammaire refuse.
    /// Dans ce dernier cas, **cesser de lire** et appeler
    /// [`Self::on_data_settled`].
    pub fn feed_data<'i>(&mut self, input: &'i [u8]) -> Result<(DataEvent<'i>, usize), Error> {
        if self.phase != Phase::Data {
            return Err(Error::NotInDataPhase);
        }
        let progres = match self.data.next(input) {
            Ok(progres) => progres,
            Err(cause) => {
                self.phase = Phase::DataFailed(cause);
                return Err(Error::DataRefused);
            }
        };
        self.compter_les_sauts(&progres.0)?;
        Ok(progres)
    }

    /// Compte les `Received:` du message, et refuse au-delà du seuil (§6.3).
    ///
    /// # UNE BOUCLE NE S'ARRÊTE PAS TOUTE SEULE
    ///
    /// Deux serveurs mal réglés qui se renvoient un message le multiplient à
    /// chaque tour, et chaque saut est licite. §6.3 donne la seule méthode qui
    /// marche sans mémoire partagée : compter les traces, et refuser au-delà
    /// d'un seuil large.
    ///
    /// **LE REFUS EST DÉFINITIF.** Réessayer ne fera pas disparaître les trente
    /// sauts déjà écrits ; un `4xx` ferait tourner la boucle plus longtemps, ce
    /// qui est exactement ce qu'on cherche à arrêter.
    fn compter_les_sauts(&mut self, evenement: &DataEvent<'_>) -> Result<(), Error> {
        if let DataEvent::Content(morceau) = *evenement {
            self.sauts.update(morceau);
        }
        if self.sauts.count() <= HOPS_MAX {
            return Ok(());
        }
        self.phase = Phase::Looped;
        Err(Error::DataRefused)
    }

    /// Donne des octets du morceau en cours, et rend ce qu'ils contiennent.
    ///
    /// **L'appelant lit EXACTEMENT ce que `BDAT` a annoncé**, ni plus ni moins :
    /// ce qui suit est une commande. Le récepteur le lui rappelle en ne
    /// consommant jamais au-delà du morceau.
    ///
    /// # UNE FAUTE N'ARRÊTE PAS LA LECTURE, ELLE ARRÊTE LE MESSAGE
    ///
    /// C'est la différence avec [`Self::feed_data`], et elle tient à la forme de
    /// `BDAT` : les octets sont annoncés, donc ils arrivent. Cesser de lire
    /// laisserait la queue du morceau se faire lire comme des commandes — la
    /// contrebande, par l'autre porte. L'appelant continue donc de consommer, et
    /// **c'est la session qui retient que le message est perdu**.
    ///
    /// # Errors
    ///
    /// [`Error::NotInDataPhase`] hors d'un morceau.
    pub fn feed_chunk<'i>(&mut self, input: &'i [u8]) -> Result<(ChunkEvent<'i>, usize), Error> {
        let Phase::Chunk { recipients, last } = self.phase else {
            if let Phase::ChunkFailed { .. } = self.phase {
                // On a déjà refusé ce message ; on aide seulement l'appelant à
                // finir de consommer ce qui a été annoncé.
                return Ok((ChunkEvent::NeedMore, input.len()));
            }
            return Err(Error::NotInDataPhase);
        };
        match self.chunk.next(input) {
            Ok(progres) => Ok(progres),
            Err(cause) => {
                self.phase = Phase::ChunkFailed {
                    recipients,
                    last,
                    cause,
                };
                Ok((ChunkEvent::NeedMore, input.len()))
            }
        }
    }

    /// Le morceau annoncé a été lu, et **ce n'était pas le dernier**.
    ///
    /// Rend le `250` de §2, ou le refus que la grammaire impose. Le dernier
    /// morceau, lui, passe par [`Self::on_data_settled`] : c'est un message
    /// entier, remis comme celui d'un `DATA`.
    ///
    /// # Errors
    ///
    /// [`Error::NotInCommandPhase`] hors d'un morceau non final.
    pub fn on_chunk_received<'b>(&mut self, out: &'b mut [u8]) -> Result<Turn<'b>, Error> {
        match self.phase {
            Phase::Chunk {
                recipients,
                last: false,
            } => {
                self.phase = Phase::Transaction {
                    recipients,
                    chunked: true,
                };
                self.simple(Code::OK, b"Chunk ok", out)
            }
            Phase::ChunkFailed { cause, .. } => {
                self.quitter_la_transaction();
                Self::refus_de_morceau(self, cause, out)
            }
            _ => Err(Error::NotInCommandPhase),
        }
    }

    /// La réponse que chaque faute de morceau impose.
    fn refus_de_morceau<'b>(
        &mut self,
        cause: DataFault,
        out: &'b mut [u8],
    ) -> Result<Turn<'b>, Error> {
        match cause {
            DataFault::BareLineEnding => self.refus(
                Code::TRANSACTION_FAILED,
                b"Bare CR or LF in message data",
                out,
            ),
            DataFault::LineTooLong { .. } => self.refus(Code::SYNTAX_ERROR, b"Line too long", out),
            DataFault::MessageTooLarge { .. } => self.refus(
                Code::MESSAGE_TOO_LARGE,
                b"Message exceeds maximum size",
                out,
            ),
        }
    }

    /// Le nombre d'octets de message reçus pour la transaction en cours.
    ///
    /// Les deux phases y répondent : `DATA` compte ses lignes dé-échappées,
    /// `BDAT` ses morceaux. **Une seule question, une seule réponse** — une
    /// transaction n'emprunte jamais les deux chemins, et quitter la transaction
    /// remet les deux compteurs à zéro. La somme est donc toujours celle du
    /// message en cours, et il n'y a pas de cas à distinguer.
    #[must_use]
    pub fn received_octets(&self) -> u64 {
        self.data
            .content_octets()
            .saturating_add(self.chunk.content_octets())
    }

    /// La session est-elle chiffrée ?
    #[must_use]
    pub fn is_encrypted(&self) -> bool {
        self.tls
    }

    /// Le pair est-il authentifié ?
    #[must_use]
    pub fn is_authenticated(&self) -> bool {
        self.authenticated
    }

    /// Le compte qui s'est authentifié, s'il y en a un.
    ///
    /// **`None` DIT DEUX CHOSES**, et l'appelant doit les traiter pareil :
    /// personne ne s'est authentifié, ou le nom donné ne tenait pas. Dans les
    /// deux cas, rien ne permet de dire au nom de qui ce pair écrit.
    #[must_use]
    pub fn submitter(&self) -> Option<&[u8]> {
        (self.authenticated && !self.compte.est_vide()).then(|| self.compte.as_bytes())
    }

    /// Traite une ligne de commande, **CRLF compris**.
    ///
    /// # Errors
    ///
    /// [`Error::SessionClosed`], [`Error::NotInCommandPhase`] ou
    /// [`Error::Reply`]. Un pair qui envoie n'importe quoi obtient une
    /// **réponse**, jamais une erreur.
    pub fn handle<'b>(&mut self, line: &[u8], out: &'b mut [u8]) -> Result<Turn<'b>, Error> {
        match self.phase {
            Phase::Closed => return Err(Error::SessionClosed),
            Phase::Auth | Phase::Data | Phase::DataFailed(_) | Phase::Looped => {
                return Err(Error::NotInCommandPhase);
            }
            Phase::Greeted | Phase::Identified | Phase::Transaction { .. } => {}
            Phase::Chunk { .. } | Phase::ChunkFailed { .. } => {
                return Err(Error::NotInCommandPhase);
            }
        }

        let commande = match Command::parse(line, self.config.limits()) {
            Ok(commande) => commande,
            Err(cause) => return self.on_parse_error(&cause, out),
        };

        match commande {
            Command::Ehlo(client_id) => self.on_ehlo(&client_id, out),
            Command::Helo(nom) => self.on_helo(nom, out),
            Command::Mail {
                reverse_path,
                parameters,
            } => self.on_mail(&reverse_path, &parameters, out),
            Command::Rcpt {
                forward_path,
                parameters,
            } => self.on_rcpt(&forward_path, &parameters, out),
            Command::Data => self.on_data(out),
            Command::Bdat { size, last } => self.on_bdat(size, last, out),
            Command::Rset => {
                self.reset_transaction();
                self.simple(Code::OK, b"Reset ok", out)
            }
            Command::Noop => self.simple(Code::OK, b"OK", out),
            Command::Quit => {
                self.phase = Phase::Closed;
                self.finish(Code::CLOSING, b"Bye", Action::Close, out)
            }
            Command::StartTls => self.on_starttls(out),
            Command::Auth {
                mechanism,
                initial_response,
            } => self.on_auth(mechanism, initial_response, out),
            Command::Vrfy => self.simple(
                Code::CANNOT_VRFY,
                b"Cannot verify; message will be attempted",
                out,
            ),
            // `EXPN` developpe une liste, c'est-a-dire en publie les membres.
            // La RFC 5321 §7.3 autorise a ne pas l'implementer, et c'est ce
            // qu'on fait.
            Command::Expn => self.simple(Code::NOT_IMPLEMENTED, b"EXPN not available", out),
            Command::Help => self.simple(Code::HELP_MESSAGE, b"See RFC 5321", out),
        }
    }

    /// Traduit une erreur d'analyse en code de reponse.
    ///
    /// **Le detail n'est jamais renvoye au pair.** Il sait ce qu'il a envoye ;
    /// le lui reciter n'ajoute rien, et exposerait le vocabulaire interne de
    /// l'analyseur a qui cherche a le cartographier.
    fn on_parse_error<'b>(
        &mut self,
        cause: &SmtpError,
        out: &'b mut [u8],
    ) -> Result<Turn<'b>, Error> {
        match cause {
            SmtpError::LineTooLong { .. } => self.refus(Code::SYNTAX_ERROR, b"Line too long", out),
            SmtpError::MalformedLineEnding => {
                self.refus(Code::SYNTAX_ERROR, b"Line must end with CRLF", out)
            }
            SmtpError::UnknownVerb => {
                self.refus(Code::SYNTAX_ERROR, b"Command not recognised", out)
            }
            SmtpError::ObsoleteVerb => {
                self.refus(Code::NOT_IMPLEMENTED, b"Command not implemented", out)
            }
            // Tout le reste porte sur les ARGUMENTS, et `501` est exactement ce
            // que la RFC 5321 §4.2.2 prevoit pour cela.
            _ => self.refus(
                Code::ARGUMENT_ERROR,
                b"Syntax error in parameters or arguments",
                out,
            ),
        }
    }

    /// `EHLO` — annonce les extensions **effectivement servies**.
    fn on_ehlo<'b>(
        &mut self,
        client_id: &ClientId<'_>,
        out: &'b mut [u8],
    ) -> Result<Turn<'b>, Error> {
        // RFC 5321 §4.1.4 : `EHLO` annule la transaction en cours.
        self.quitter_la_transaction();
        self.esmtp = true;
        self.retenir_le_helo(client_id);

        let mut lignes: [&[u8]; EHLO_LINES_MAX] = [b""; EHLO_LINES_MAX];
        let mut posees = 0_usize;
        lignes[posees] = self.config.domain();
        posees = posees.saturating_add(1);
        lignes[posees] = self.size_line.get(..self.size_len).unwrap_or_default();
        posees = posees.saturating_add(1);
        // **`8BITMIME` (RFC 6152) EST ANNONCÉ TOUJOURS**, et il ne coûte rien :
        // la phase de données ne touche à aucun octet — elle refuse un `CR` ou
        // un `LF` isolé, et laisse passer le reste tel quel. Ce serveur était
        // donc DÉJÀ propre sur huit bits, et ne le disait pas : les pairs
        // recodaient en quoted-printable ce qu'on aurait pris tel quel.
        lignes[posees] = b"8BITMIME";
        posees = posees.saturating_add(1);
        // **`ENHANCEDSTATUSCODES` (RFC 2034) EST ANNONCÉ TOUJOURS**, et les
        // codes partent de même — y compris vers un client qui n'a dit que
        // `HELO`. Un code étendu est un PRÉFIXE DE TEXTE : qui ne le comprend
        // pas le lit comme le début du message, ce que §4 prévoit qu'il fasse.
        // Deux formes de réponse selon le salut, c'est deux vocabulaires de
        // sortie — et deux vocabulaires finissent par diverger.
        lignes[posees] = b"ENHANCEDSTATUSCODES";
        posees = posees.saturating_add(1);
        // **`PIPELINING` (RFC 2920) EST ANNONCÉ TOUJOURS.** Ce n'est pas une
        // capacité qu'on ajoute : la boucle prend UNE LIGNE À LA FOIS dans son
        // tampon, donc un lot arrivé en un seul segment est déjà servi commande
        // par commande, dans l'ordre. Ce qui manquait était l'annonce — et un
        // service qu'on rend sans le dire est un service que personne n'emploie.
        //
        // §3.1 interdit au client de grouper par-dessus `STARTTLS`, et la boucle
        // ne se contente pas de l'espérer : elle refuse la connexion qui le
        // fait. Voir `connection::conduire`.
        lignes[posees] = b"PIPELINING";
        posees = posees.saturating_add(1);
        // **`CHUNKING` EST ANNONCÉ TOUJOURS**, et sans réglage : la session sait
        // conduire `BDAT`, quel que soit l'appelant, et un service qu'on sert
        // sans l'annoncer est un service que personne n'emploie — donc que rien
        // n'éprouve. Il ne dépend pas du chiffrement : `BDAT` ne porte aucun
        // secret, et ce serveur reçoit du courrier en clair de toute façon.
        lignes[posees] = b"CHUNKING";
        posees = posees.saturating_add(1);
        // **`DSN` (RFC 3461) NE S'ANNONCE QUE SI L'ON PEUT ÉMETTRE.** §4.2 veut
        // qu'un serveur qui l'annonce ÉMETTE un rapport de succès quand on lui
        // en demande un — et émettre suppose la file. Sans elle, l'annonce
        // serait une promesse vide, et `NOTIFY=SUCCESS` recevrait un `504` :
        // le pair saurait au moins à quoi s'en tenir.
        if self.config.capabilities().dsn {
            lignes[posees] = b"DSN";
            posees = posees.saturating_add(1);
        }
        // On n'annonce QUE ce que l'appelant a declare savoir conduire, et
        // `AUTH` seulement sous chiffrement (C6) : annoncer un mecanisme qu'on
        // refusera ensuite ferait envoyer un mot de passe en clair a un client
        // qui aurait cru l'offre.
        if self.config.capabilities().starttls && !self.tls {
            lignes[posees] = b"STARTTLS";
            posees = posees.saturating_add(1);
        }
        if self.config.capabilities().auth && self.tls {
            lignes[posees] = b"AUTH PLAIN";
            posees = posees.saturating_add(1);
        }

        let reply = encode(
            out,
            Code::OK,
            lignes.get(..posees).unwrap_or_default(),
            self.config.limits(),
        )
        .map_err(Error::Reply)?;
        Ok(Turn {
            reply,
            action: Action::Continue,
            peer_fault: false,
            refused_recipient: false,
        })
    }

    /// `HELO` — accepte, mais n'annonce rien.
    ///
    /// Une session `HELO` n'a donc ni `STARTTLS` ni `AUTH` : elle ne peut que
    /// remettre du courrier en clair et sans s'authentifier. C6 n'interdit pas
    /// `HELO` ; ce qu'une telle session a le droit de faire releve de la
    /// politique de relais, pas de cette couche.
    fn on_helo<'b>(&mut self, nom: &[u8], out: &'b mut [u8]) -> Result<Turn<'b>, Error> {
        self.quitter_la_transaction();
        self.esmtp = false;
        // `HELO` ne porte qu'un nom de domaine : la grammaire l'a déjà validé.
        self.retenir_le_helo(&ClientId::Domain(nom));
        let domaine = self.config.domain();
        let reply =
            encode(out, Code::OK, &[domaine], self.config.limits()).map_err(Error::Reply)?;
        Ok(Turn {
            reply,
            action: Action::Continue,
            peer_fault: false,
            refused_recipient: false,
        })
    }

    /// `MAIL FROM:` — ouvre une transaction.
    fn on_mail<'b>(
        &mut self,
        reverse_path: &Path<'_>,
        parameters: &Parameters<'_>,
        out: &'b mut [u8],
    ) -> Result<Turn<'b>, Error> {
        match self.phase {
            Phase::Greeted => self.refus(Code::BAD_SEQUENCE, b"Send EHLO first", out),
            Phase::Transaction { .. } => {
                self.refus(Code::BAD_SEQUENCE, b"Nested MAIL command", out)
            }
            _ => {
                // **LES PARAMÈTRES SE TRIENT AVANT D'OUVRIR LA TRANSACTION** :
                // refuser après l'avoir ouverte laisserait une transaction
                // entamée que le pair croirait close.
                let mut envid = [0_u8; ENVID_MAX];
                let mut envid_len = 0_usize;
                for parametre in *parameters {
                    match verdict_du_parametre_mail(
                        &parametre,
                        self.config.max_message_octets(),
                        self.config.capabilities().dsn,
                        &mut envid,
                    ) {
                        Verdict7::Compris => {}
                        Verdict7::Envid(combien) => envid_len = combien,
                        Verdict7::TropGros => {
                            return self.refus(
                                Code::MESSAGE_TOO_LARGE,
                                b"Message exceeds maximum size",
                                out,
                            );
                        }
                        Verdict7::Inconnu => {
                            return self.refus(
                                Code::PARAMETER_NOT_IMPLEMENTED,
                                b"Parameter not recognised",
                                out,
                            );
                        }
                    }
                }
                self.phase = Phase::Transaction {
                    recipients: 0,
                    chunked: false,
                };
                self.envid = envid;
                self.envid_len = envid_len;
                self.retenir_le_chemin_de_retour(reverse_path);
                if self.retenir_l_expediteur(reverse_path) {
                    // L'identité est vérifiable : on rend la main à l'appelant,
                    // SANS RÉPONDRE. C'est lui qui résout.
                    return self.differer(out);
                }
                self.simple(Code::OK, b"Sender ok", out)
            }
        }
    }

    /// Retient le `MAIL FROM:` tel que le pair l'a écrit.
    ///
    /// **UN CHEMIN NUL NE SE RETIENT PAS**, et c'est une décision : `<>` est
    /// l'expéditeur des notifications, et une notification n'en engendre pas
    /// une autre (§6.1 de RFC 5321). Un message déposé avec `<>` n'a donc
    /// personne à qui rendre compte, et la remise le refusera plutôt que de
    /// mettre en file ce qu'elle ne saurait pas rendre.
    fn retenir_le_chemin_de_retour(&mut self, reverse_path: &Path<'_>) {
        self.chemin_de_retour.vider();
        // **CE QUE LE PAIR A DIT SE RETIENT ENTIER**, littéral d'adresse
        // compris : c'est ce que le `Return-Path:` de §4.4 doit consigner, et
        // non l'adresse à laquelle un rapport reviendrait.
        self.depose.vider();
        self.depose_vu = true;
        if let Path::Mailbox(boite) = reverse_path {
            // **LE LITTÉRAL PORTE DÉJÀ SES CROCHETS** : les rajouter écrirait
            // `jean@[[192.0.2.1]]`, une adresse qui ne désigne rien.
            let domaine = match boite.domain() {
                ClientId::Domain(nom) | ClientId::AddressLiteral(nom) => nom,
            };
            // **AUCUNE GARDE SUR LA PLACE, PARCE QU'IL N'Y A RIEN À GARDER.**
            // `SENDER_MAX` est la somme EXACTE de ce qu'une partie locale (64,
            // §4.5.3.1.1) et un domaine (`DOMAIN_MAX`) peuvent peser, plus
            // l'arobase : ce dépôt ne peut pas ne pas tenir. Un `if` ici serait
            // une branche que rien n'atteint — donc pas une garde.
            //
            // Ce qui compte est que la borne reste EXACTE : un tampon plus
            // court laisserait `depose` vide, ce qui écrirait `<>` pour une
            // vraie adresse — c'est-à-dire « ceci est un rapport ».
            let _ = self
                .depose
                .poser(&[boite.local_part().as_bytes(), b"@", domaine]);
        }
        let Path::Mailbox(boite) = reverse_path else {
            return;
        };
        let ClientId::Domain(domaine) = boite.domain() else {
            // UN LITTÉRAL D'ADRESSE NE SE RETIENT PAS NON PLUS : `jean@[192.0.2.1]`
            // ne désigne aucune zone, et un rapport qu'on lui adresserait
            // n'atteindrait rien qu'on puisse résoudre.
            return;
        };
        self.chemin_de_retour
            .poser(&[boite.local_part().as_bytes(), b"@", domaine]);
    }

    /// L'adresse à laquelle un rapport de non-remise reviendra.
    ///
    /// `None` hors transaction, et pour un chemin nul ou un littéral d'adresse —
    /// voir [`SmtpSession::retenir_le_chemin_de_retour`].
    #[must_use]
    pub fn return_path(&self) -> Option<&[u8]> {
        (!self.chemin_de_retour.est_vide()).then(|| self.chemin_de_retour.as_bytes())
    }

    /// Retient l'identité à vérifier, et dit si elle l'est.
    ///
    /// Rend `false` — donc « accepte sans vérifier » — dans cinq cas, et
    /// aucun n'est un échec :
    ///
    /// - **le pair s'est AUTHENTIFIÉ** : voir ci-dessous ;
    /// - la politique d'expéditeur ne le demande pas ;
    /// - l'expéditeur est nul ET le `HELO` n'était pas un domaine, si bien qu'il
    ///   n'y a rien à interroger (RFC 7208 §2.4) ;
    /// - le domaine de l'expéditeur est un LITTÉRAL D'ADRESSE : `jean@[192.0.2.1]`
    ///   ne désigne aucune zone, et SPF n'a rien à y lire ;
    /// - l'identité ne tient pas dans les tampons, ce qui veut dire qu'elle est
    ///   plus longue qu'un nom de domaine.
    fn retenir_l_expediteur(&mut self, reverse_path: &Path<'_>) -> bool {
        // ── UNE SOUMISSION AUTHENTIFIÉE NE SE VÉRIFIE PAS PAR SPF ───────────
        //
        // SPF demande si l'ADRESSE QUI SE CONNECTE a le droit d'écrire pour ce
        // domaine. Or celui qui soumet le fait depuis un portable, un téléphone,
        // un hôtel : jamais depuis une machine que sa propre politique nomme.
        // **`fail` est donc le résultat NORMAL d'une soumission légitime**, et
        // non une anomalie.
        //
        // Le vérifier tout de même coûtait une interrogation DNS par
        // transaction, et surtout apposait `Received-SPF: fail` sur le message —
        // qui PARTAIT AVEC LUI vers le destinataire. Un filtre d'en face lisait
        // alors un échec que NOUS avions écrit à propos de NOTRE PROPRE
        // utilisateur.
        //
        // Ce qui autorise un déposant, c'est `AUTH` ; et le `From:` qu'il a le
        // droit d'affirmer est déjà borné ailleurs (RFC 6409 §6.1).
        if self.authenticated {
            return false;
        }
        if self.config.sender_policy() == SenderPolicy::Ignore {
            return false;
        }
        match reverse_path {
            Path::Mailbox(boite) => match boite.domain() {
                ClientId::Domain(domaine) => {
                    self.identite_helo = false;
                    self.domaine_verifie.poser(&[domaine])
                        && self
                            .expediteur
                            .poser(&[boite.local_part().as_bytes(), b"@", domaine])
                }
                // Un littéral d'adresse ne désigne aucune zone.
                ClientId::AddressLiteral(_) => false,
            },
            // RFC 7208 §2.4 : l'expéditeur nul se vérifie sur le `HELO`.
            Path::Null => {
                self.identite_helo = true;
                !self.helo.est_vide()
                    && self.domaine_verifie.poser(&[self.helo.as_bytes()])
                    && self
                        .expediteur
                        .poser(&[b"postmaster@", self.helo.as_bytes()])
            }
            // `<Postmaster>` n'est pas un expéditeur : la grammaire le refuse en
            // `MAIL FROM:` avant d'arriver ici.
            Path::Postmaster => false,
        }
    }

    /// Retient le nom annoncé, s'il en est un.
    fn retenir_le_helo(&mut self, client_id: &ClientId<'_>) {
        match client_id {
            ClientId::Domain(nom) => {
                self.helo.poser(&[nom]);
            }
            // UN LITTÉRAL D'ADRESSE N'EST PAS UN NOM : `[192.0.2.1]` ne désigne
            // aucune zone, et le retenir ferait interroger un domaine qui
            // n'existe pas. On oublie le précédent plutôt que de le garder : un
            // second `HELO` remplace le premier, y compris par rien.
            ClientId::AddressLiteral(_) => self.helo.vider(),
        }
    }

    /// Un tour SANS RÉPONSE : l'appelant doit vérifier avant qu'on parle.
    fn differer<'b>(&self, out: &'b mut [u8]) -> Result<Turn<'b>, Error> {
        let vide = out.get(..0).unwrap_or_default();
        Ok(Turn {
            reply: vide,
            action: Action::CheckSender,
            peer_fault: false,
            refused_recipient: false,
        })
    }

    /// L'identité que l'appelant doit vérifier.
    ///
    /// Rend `None` hors du tour qui a demandé [`Action::CheckSender`].
    #[must_use]
    pub fn sender_identity(&self) -> Option<SenderIdentity<'_>> {
        if self.domaine_verifie.est_vide() {
            return None;
        }
        Some(SenderIdentity {
            domain: self.domaine_verifie.as_bytes(),
            sender: self.expediteur.as_bytes(),
            helo: self.helo.as_bytes(),
            scope: if self.identite_helo {
                Identity::Helo
            } else {
                Identity::MailFrom
            },
        })
    }

    /// L'en-tête `Received-SPF` de la transaction en cours (RFC 7208 §9.1).
    ///
    /// Rend `None` quand rien n'a été vérifié — et **rien n'est alors écrit** :
    /// un en-tête qui dirait `none` sans qu'aucune résolution ait eu lieu
    /// mentirait sur ce qu'on a fait.
    ///
    /// # Pourquoi la session, et pas la boucle
    ///
    /// La boucle ne compose aucun texte de protocole, pas plus un en-tête qu'une
    /// réponse : c'est ce qui garde le vocabulaire de sortie clos. Elle apporte
    /// la seule chose qu'elle sache et que la session ignore — l'adresse du
    /// pair — et reçoit des octets à écrire.
    #[must_use]
    pub fn received_spf<'b>(&self, client: IpAddr, out: &'b mut [u8]) -> Option<&'b [u8]> {
        let verdict = self.verdict?;
        let champ = ReceivedSpf {
            result: verdict,
            client,
            sender: self.expediteur.as_bytes(),
            helo: self.helo.as_bytes(),
            receiver: self.config.domain(),
            identity: if self.identite_helo {
                Identity::Helo
            } else {
                Identity::MailFrom
            },
        };
        // UN EN-TÊTE QU'ON NE SAIT PAS ÉCRIRE NE S'ÉCRIT PAS. La composition
        // refuse ce qui ne tient pas dans une ligne et ce qui porte un octet
        // hors de l'ASCII imprimable ; dans les deux cas, le message part sans
        // trace plutôt qu'avec une trace douteuse.
        write_received_spf(out, &champ).ok()
    }

    /// Compose l'en-tête `Received:` de ce saut (RFC 5321 §4.4).
    ///
    /// # §4.4 EN EXIGE DEUX, ET CELUI-CI EST LA TRACE
    ///
    /// L'autre est le `Return-Path:` de la remise finale — voir
    /// [`SmtpSession::received_return_path`]. §4.4 ne suggère ni l'un ni
    /// l'autre : un serveur qui accepte un message **DOIT** y poser sa trace. Sans elle, le chemin d'un message est intraçable, la
    /// boucle de §6.3 ne se détecte plus, et les filtres en aval se méfient d'un
    /// message qui n'en porte aucune.
    ///
    /// # L'HEURE VIENT DE L'APPELANT, ET C'EST C1
    ///
    /// Une session ne lit pas d'horloge : elle rendrait deux réponses
    /// différentes au même appel, et cesserait d'être éprouvable. La boucle
    /// apporte donc les deux choses qu'elle seule sait — l'adresse du pair et
    /// l'instant — et reçoit des octets à écrire.
    ///
    /// # LE MOT DE `with` DIT CE QUI S'EST PASSÉ (RFC 3848)
    ///
    /// `SMTP` pour un `HELO`, `ESMTP` pour un `EHLO`, et le `S` puis le `A`
    /// quand le saut était chiffré puis authentifié. Il n'y a pas d'`ESMTPA` :
    /// cette session refuse `AUTH` hors chiffrement (C6), et la variante serait
    /// une branche que rien ne pourrait construire.
    #[must_use]
    pub fn received<'b>(&self, client: IpAddr, date: u64, out: &'b mut [u8]) -> Option<&'b [u8]> {
        let champ = Received {
            helo: self.helo.as_bytes(),
            client,
            receiver: self.config.domain(),
            with: match (self.esmtp, self.tls, self.authenticated) {
                (false, _, _) => Transport::Smtp,
                (true, false, _) => Transport::Esmtp,
                (true, true, false) => Transport::Esmtps,
                (true, true, true) => Transport::EsmtpsA,
            },
            date,
        };
        // UN EN-TÊTE QU'ON NE SAIT PAS ÉCRIRE NE S'ÉCRIT PAS, comme pour
        // `Received-SPF` : le message part sans trace plutôt qu'avec une trace
        // douteuse.
        write_received(out, &champ).ok()
    }

    /// L'en-tête `Return-Path:` que la REMISE FINALE doit poser (§4.4).
    ///
    /// # LA NORME EN EXIGE DEUX, PAS UN
    ///
    /// §4.4 demande la trace `Received:` à qui accepte un message, ET cette
    /// ligne-ci à qui le remet : « this use of return-path is required ». Sans
    /// elle, l'expéditeur d'ENVELOPPE est perdu à la remise — `From:` ne le dit
    /// pas, et cet écart est toute la base de SPF, de DMARC et du traitement des
    /// rebonds.
    ///
    /// # `<>` N'EST PAS « RIEN », ET LA NUANCE FAIT TAIRE UN RÉPONDEUR
    ///
    /// Un chemin nul dit « ceci est un rapport » : §2 de RFC 3834 veut qu'un
    /// répondeur automatique s'abstienne devant lui. C'est donc une valeur à
    /// écrire, et non une absence — d'où `None` réservé au seul cas où aucun
    /// `MAIL FROM:` n'a été accepté.
    ///
    /// # Pourquoi la session, et pas la boucle
    ///
    /// La boucle ne compose aucun texte de protocole. Elle n'apporte ici même
    /// rien : tout ce qu'il faut a été dit par le pair.
    #[must_use]
    pub fn received_return_path<'b>(&self, out: &'b mut [u8]) -> Option<&'b [u8]> {
        if !self.depose_vu {
            return None;
        }
        // UN EN-TÊTE QU'ON NE SAIT PAS ÉCRIRE NE S'ÉCRIT PAS, comme pour les
        // deux autres traces : le message arrive sans plutôt qu'avec une ligne
        // douteuse.
        write_return_path(out, self.depose.as_bytes()).ok()
    }

    /// L'identifiant d'enveloppe du déposant (RFC 3461 §4.4), s'il en a donné.
    ///
    /// **Il est rendu DÉCODÉ** : le xtext de §4 a été défait à l'acceptation,
    /// une seule fois, et ce qui n'était pas un xtext valable n'est jamais
    /// arrivé jusqu'ici.
    #[must_use]
    pub fn envelope_id(&self) -> Option<&[u8]> {
        // `envid_len` vient de `decode_xtext`, qui n'écrit jamais au-delà du
        // tampon : la tranche existe toujours. `unwrap_or_default` porte cette
        // certitude plutôt qu'un `?` que rien n'emprunterait.
        let vu = self.envid.get(..self.envid_len).unwrap_or_default();
        (!vu.is_empty()).then_some(vu)
    }

    /// Ce que le destinataire de rang `rang` a demandé (RFC 3461).
    ///
    /// La boucle en a besoin pour la file : c'est elle qui écrit l'enveloppe, et
    /// c'est la session qui sait ce que le pair a demandé.
    #[must_use]
    pub fn recipient_report(&self, rang: usize) -> Option<(Notify, &[u8])> {
        self.recipients.rapport(rang)
    }

    /// Le verdict retenu pour la transaction en cours, s'il y en a un.
    ///
    /// Il sert au journal et à l'en-tête `Received-SPF` : un verdict qu'on
    /// n'écrit nulle part ne se relit pas le jour où l'on se demande pourquoi un
    /// message est passé.
    #[must_use]
    pub fn sender_verdict(&self) -> Option<Verdict> {
        self.verdict
    }

    /// Rend le verdict de la vérification, et compose la réponse au `MAIL FROM:`.
    ///
    /// # Ce que chaque verdict vaut, et pourquoi
    ///
    /// - **`Fail`** : le domaine dit lui-même que cette adresse n'a pas le droit
    ///   d'émettre pour lui. C'est le seul verdict qui refuse (`550 5.7.23`,
    ///   RFC 7372 §3.2) — et seulement sous [`SenderPolicy::Enforce`].
    /// - **`TempError`** : la résolution n'a pas abouti. On AJOURNE (`451 4.4.3`)
    ///   plutôt que de refuser : le pair réessaiera, et un message qui serait
    ///   passé cinq minutes plus tard n'est pas jeté.
    /// - **`SoftFail`** : le domaine dit « probablement pas », et la RFC 7208
    ///   §8.5 veut qu'on n'en fasse pas un refus. Le retenir suffit : c'est à
    ///   DMARC (C9) de le rapprocher de l'en-tête `From:`.
    /// - **`PermError`** : la politique du domaine est illisible. **On accepte**,
    ///   parce que refuser punirait l'expéditeur pour la faute de son
    ///   administrateur — et parce qu'une politique fautive est le cas le plus
    ///   fréquent des trois erreurs.
    /// - **`Pass`, `Neutral`, `None`** : rien à opposer.
    ///
    /// # Errors
    ///
    /// [`Error::Reply`] si `out` est trop petit.
    pub fn sender_checked<'b>(
        &mut self,
        verdict: Verdict,
        out: &'b mut [u8],
    ) -> Result<Turn<'b>, Error> {
        if self.config.sender_policy() != SenderPolicy::Enforce {
            self.verdict = Some(verdict);
            return self.simple(Code::OK, b"Sender ok", out);
        }
        // LE VERDICT SE POSE APRÈS. Abandonner la transaction efface ce qu'elle
        // portait — l'identité comprise — et le verdict serait effacé avec elle.
        // Or il doit rester lisible : c'est ce que le journal consigne, et sans
        // lui personne ne saurait POURQUOI ce message a été refusé.
        let tour = match verdict {
            Verdict::Fail => {
                self.quitter_la_transaction();
                self.refus(
                    Code::MAILBOX_UNAVAILABLE,
                    b"Sender address rejected: not authorized by SPF",
                    out,
                )
            }
            Verdict::TempError => {
                self.quitter_la_transaction();
                self.simple(
                    Code::LOCAL_ERROR,
                    b"Temporary error while checking SPF, try again later",
                    out,
                )
            }
            Verdict::Pass
            | Verdict::Neutral
            | Verdict::None
            | Verdict::SoftFail
            | Verdict::PermError => self.simple(Code::OK, b"Sender ok", out),
        };
        self.verdict = Some(verdict);
        tour
    }

    /// `RCPT TO:` — la seule commande dont la session ne decide pas elle-meme.
    fn on_rcpt<'b>(
        &mut self,
        forward_path: &Path<'_>,
        parameters: &Parameters<'_>,
        out: &'b mut [u8],
    ) -> Result<Turn<'b>, Error> {
        // ── `NOTIFY` et `ORCPT` (RFC 3461 §4.1 et §4.2) ─────────────────────
        //
        // Ils sont PAR DESTINATAIRE : deux `RCPT` d'une même transaction peuvent
        // demander deux choses différentes, et c'est tout l'objet de §4.1.
        //
        // **UN PARAMÈTRE QU'ON N'ANNONCE PAS SE REFUSE.** Sans file, `NOTIFY`
        // ne veut rien dire — un `NEVER` qu'on honorerait sans pouvoir rien
        // émettre serait vrai par accident, et un `SUCCESS` serait une promesse
        // vide.
        let mut notify = Notify::default();
        let mut orcpt = [0_u8; ORCPT_MAX];
        let mut orcpt_vu = 0_usize;
        for parametre in *parameters {
            let mot = parametre.keyword();
            let servi = if mot.eq_ignore_ascii_case(b"NOTIFY") {
                match parametre.value() {
                    Some(valeur) if self.config.capabilities().dsn => match Notify::parse(valeur) {
                        Ok(vu) => {
                            notify = vu;
                            true
                        }
                        Err(_) => false,
                    },
                    _ => false,
                }
            } else if mot.eq_ignore_ascii_case(b"ORCPT") {
                match parametre.value() {
                    Some(valeur) if self.config.capabilities().dsn => {
                        match parse_orcpt(valeur, &mut orcpt) {
                            Ok((_, adresse)) => {
                                orcpt_vu = adresse.len();
                                true
                            }
                            Err(_) => false,
                        }
                    }
                    _ => false,
                }
            } else {
                false
            };
            if !servi {
                return self.refus(
                    Code::PARAMETER_NOT_IMPLEMENTED,
                    b"Parameter not recognised",
                    out,
                );
            }
        }

        let Phase::Transaction {
            recipients,
            chunked,
        } = self.phase
        else {
            return self.refus(Code::BAD_SEQUENCE, b"Need MAIL before RCPT", out);
        };
        if recipients >= self.config.max_recipients() {
            return self.simple(Code::TOO_MANY_RECIPIENTS, b"Too many recipients", out);
        }
        match self
            .policy
            .accepts_recipient(forward_path, self.authenticated)
        {
            RecipientVerdict::Accept => {
                // ON RETIENT L'ADRESSE, ET SEULEMENT SI ELLE TIENT. La refuser
                // ici plutôt que de la tronquer n'est pas une précaution : une
                // adresse tronquée livrerait le message à quelqu'un d'autre.
                if !self.retenir(forward_path) {
                    return self.simple(Code::TOO_MANY_RECIPIENTS, b"Too many recipients", out);
                }
                // Ce que CE destinataire-là a demandé (RFC 3461 §4.1, §4.2).
                self.recipients
                    .poser_le_rapport(notify, orcpt.get(..orcpt_vu).unwrap_or_default());
                self.phase = Phase::Transaction {
                    recipients: recipients.saturating_add(1),
                    chunked,
                };
                self.simple(Code::OK, b"Recipient ok", out)
            }
            RecipientVerdict::RejectPermanent => {
                self.refus_de_destinataire(Code::MAILBOX_UNAVAILABLE, b"Mailbox unavailable", out)
            }
            RecipientVerdict::RejectTemporary => {
                self.simple(Code::MAILBOX_BUSY, b"Mailbox busy, try again later", out)
            }
            RecipientVerdict::RelayDenied => {
                // **UN RELAIS NIÉ EST AUSSI UNE RÉPONSE À QUI RÉCOLTE** : il dit
                // « pas ici », ce qui renseigne autant qu'un « pas cette boîte ».
                self.refus_de_destinataire(Code::MAILBOX_UNAVAILABLE, b"Relay access denied", out)
            }
        }
    }

    /// `DATA` — exige au moins un destinataire accepte.
    fn on_data<'b>(&mut self, out: &'b mut [u8]) -> Result<Turn<'b>, Error> {
        match self.phase {
            // **`BDAT` ET `DATA` SE DISPUTENT LE MÊME MESSAGE** (RFC 3030 §2).
            // Celui qui a commencé le finit ; l'autre est une faute de séquence,
            // et non de syntaxe — le pair n'a rien à corriger dans son texte.
            Phase::Transaction { chunked: true, .. } => self.refus(
                Code::BAD_SEQUENCE,
                b"BDAT already started; finish with BDAT LAST",
                out,
            ),
            Phase::Transaction { recipients, .. } if recipients > 0 => {
                self.phase = Phase::Data;
                // Un récepteur NEUF par message : celui du message précédent
                // porte ses compteurs, et les réutiliser ferait refuser le
                // second message pour la taille du premier.
                self.data =
                    DataReceiver::new(self.config.limits(), self.config.max_message_octets());
                self.finish(
                    Code::START_MAIL_INPUT,
                    b"Start mail input; end with <CRLF>.<CRLF>",
                    Action::ReceiveData,
                    out,
                )
            }
            _ => self.refus(Code::BAD_SEQUENCE, b"Need RCPT before DATA", out),
        }
    }

    /// `BDAT taille [LAST]` (RFC 3030 §2) — exige au moins un destinataire.
    ///
    /// # LA RÉPONSE NE PART QU'APRÈS LES OCTETS
    ///
    /// `DATA` répond `354` puis lit ; `BDAT` lit d'abord, et répond ensuite —
    /// §2 le veut ainsi, et c'est cohérent : il n'y a rien à annoncer, la taille
    /// est déjà connue des deux côtés. Le tour rend donc une réponse VIDE et
    /// [`Action::ReceiveChunk`], comme [`Action::CheckSender`] rend une réponse
    /// vide en attendant un verdict.
    fn on_bdat<'b>(&mut self, size: u64, last: bool, out: &'b mut [u8]) -> Result<Turn<'b>, Error> {
        let Phase::Transaction {
            recipients,
            chunked,
        } = self.phase
        else {
            return self.refus(Code::BAD_SEQUENCE, b"Need MAIL and RCPT before BDAT", out);
        };
        if recipients == 0 {
            return self.refus(Code::BAD_SEQUENCE, b"Need RCPT before BDAT", out);
        }
        // Un récepteur NEUF au PREMIER morceau, et un seul : les suivants
        // continuent le même message, et le remettre à zéro entre deux morceaux
        // effacerait le compte des octets et l'état d'un `CRLF` coupé en deux.
        if !chunked {
            self.chunk = ChunkReceiver::new(self.config.limits(), self.config.max_message_octets());
        }
        // **LA TAILLE SE REFUSE AVANT D'ÊTRE LUE.** Elle est annoncée : lire un
        // gibioctet pour le jeter ensuite ferait travailler la machine au
        // rythme d'un pair qui n'a rien à livrer.
        if let Err(cause) = self.chunk.begin(size, last) {
            self.quitter_la_transaction();
            // **UN SEUL ENDROIT DÉCIDE DE CE QU'UNE FAUTE RÉPOND.** Refaire ici
            // le `match` de `refus_de_morceau` y ajouterait deux bras que rien
            // ne peut atteindre — `begin` ne rend que la borne franchie — et une
            // garde inatteignable n'est pas une garde.
            return self.refus_de_morceau(cause, out);
        }
        self.phase = Phase::Chunk { recipients, last };
        // **UN TOUR SANS RÉPONSE**, comme celui qui diffère un verdict SPF : §2
        // veut que le `250` parte APRÈS les octets, et non avant. Écrire quoi
        // que ce soit ici le ferait arriver au milieu du morceau que le pair est
        // déjà en train d'envoyer.
        let vide = out.get(..0).unwrap_or_default();
        Ok(Turn {
            reply: vide,
            action: Action::ReceiveChunk { size, last },
            peer_fault: false,
            refused_recipient: false,
        })
    }

    /// `STARTTLS` (RFC 3207 §4).
    fn on_starttls<'b>(&mut self, out: &'b mut [u8]) -> Result<Turn<'b>, Error> {
        if !self.config.capabilities().starttls {
            return self.refus(Code::NOT_IMPLEMENTED, b"Command not implemented", out);
        }
        if self.tls {
            return self.refus(Code::BAD_SEQUENCE, b"TLS already active", out);
        }
        if self.phase == Phase::Greeted {
            return self.refus(Code::BAD_SEQUENCE, b"Send EHLO first", out);
        }
        self.finish(
            Code::SERVICE_READY,
            b"Ready to start TLS",
            Action::StartTls,
            out,
        )
    }

    /// Retient un destinataire accepté, sous sa forme `locale@domaine`.
    ///
    /// # Le `<Postmaster>` nu est résolu ICI, et pas ailleurs
    ///
    /// La RFC 5321 §4.1.1.3 admet un `RCPT TO:<Postmaster>` sans domaine. Le
    /// domaine sous-entendu est celui du serveur — et la session est le seul
    /// endroit qui le connaisse. Le laisser nu obligerait la remise à deviner,
    /// et deux endroits qui devinent la même chose finissent par deviner
    /// différemment.
    fn retenir(&mut self, forward_path: &Path<'_>) -> bool {
        match forward_path {
            Path::Mailbox(boite) => self.recipients.push(&[
                boite.local_part().as_bytes(),
                b"@",
                boite.domain().as_bytes(),
            ]),
            Path::Postmaster => self
                .recipients
                .push(&[b"postmaster", b"@", self.config.domain()]),
            // `<>` n'est pas un destinataire ; `on_rcpt` ne l'accepte jamais, et
            // la grammaire le refuse avant lui.
            Path::Null => false,
        }
    }

    /// Les destinataires acceptés de la transaction en cours.
    ///
    /// Vide hors transaction, et **vidé dès qu'elle se termine** — par `RSET`,
    /// par un nouveau `MAIL`, ou par la fin du message. C'est la session qui les
    /// retient parce que c'est elle qui voit ces trois-là ; une liste tenue
    /// ailleurs finirait par livrer un message aux destinataires du précédent.
    pub fn recipients(&self) -> impl Iterator<Item = &[u8]> {
        self.recipients.iter()
    }

    /// `AUTH` (RFC 4954) — **le refus emblematique de C6**.
    fn on_auth<'b>(
        &mut self,
        mechanism: &[u8],
        initial_response: Option<&[u8]>,
        out: &'b mut [u8],
    ) -> Result<Turn<'b>, Error> {
        if !self.config.capabilities().auth {
            return self.refus(Code::NOT_IMPLEMENTED, b"Command not implemented", out);
        }
        if !self.tls {
            // Ce refus n'est PAS reglable. Un mot de passe envoye en clair est
            // lu par qui regarde passer les paquets, et l'avoir accepte une fois
            // suffit a le compromettre pour toujours.
            return self.refus(
                Code::ENCRYPTION_REQUIRED,
                b"Encryption required for authentication",
                out,
            );
        }
        if self.authenticated {
            return self.refus(Code::BAD_SEQUENCE, b"Already authenticated", out);
        }
        if self.phase == Phase::Greeted {
            return self.refus(Code::BAD_SEQUENCE, b"Send EHLO first", out);
        }
        // `504` et non `502` : `AUTH` est servi, c'est le mecanisme qui ne l'est
        // pas. Un `502` laisserait croire qu'`AUTH` n'existe pas ici, et un
        // client qui sait faire `PLAIN` renoncerait pour rien.
        // Comparaison EXACTE, et non « à la casse près » : la RFC 4422 §3.1
        // impose des majuscules, et `ams_proto_smtp` refuse déjà tout le reste.
        // Une seconde lecture, plus tolérante que la première, finirait par
        // diverger d'elle — c'est la règle qu'on s'applique partout ailleurs.
        if mechanism != b"PLAIN" {
            return self.refus(
                Code::PARAMETER_NOT_IMPLEMENTED,
                b"Unrecognized authentication type",
                out,
            );
        }

        match initial_response {
            // RFC 4954 §4 : avec une reponse initiale, IL NE FAUT PAS envoyer de
            // defi. Le `334` de trop desynchroniserait la conversation — le
            // client attendrait un verdict, le serveur une reponse.
            Some(reponse) => {
                // Un `=` SEUL vaut reponse initiale VIDE (meme §) : sans cette
                // convention, « rien » et « une chaine vide » s'ecriraient pareil.
                let brut: &[u8] = if reponse == b"=" { b"" } else { reponse };
                self.regler_authentification(brut, out)
            }
            None => {
                self.phase = Phase::Auth;
                // Le defi de `PLAIN` est VIDE : la ligne est `334 ` et rien de
                // plus. Il n'y a donc rien a encoder en base64, et c'est
                // pourquoi `ams_sasl` n'a pas d'encodeur.
                self.finish(Code::AUTH_CHALLENGE, b"", Action::ReadAuthResponse, out)
            }
        }
    }

    /// Lit la reponse du pair au defi SASL, et rend le verdict.
    ///
    /// # Ce que l'appelant doit faire, et rien de plus
    ///
    /// Voir [`Action::ReadAuthResponse`] : lire **une ligne** — sans son
    /// `CRLF` — et la passer ici. Il n'a ni base64 a decoder, ni format a
    /// connaitre, ni annulation a reconnaitre.
    ///
    /// # Errors
    ///
    /// [`Error::NotInAuthExchange`] si aucun defi n'est en attente.
    pub fn feed_auth<'b>(&mut self, response: &[u8], out: &'b mut [u8]) -> Result<Turn<'b>, Error> {
        if self.phase != Phase::Auth {
            return Err(Error::NotInAuthExchange);
        }
        // RFC 4954 §4 : `*` annule l'echange. Ce n'est PAS une faute du pair —
        // un client qui renonce parce que l'utilisateur a ferme sa fenetre fait
        // exactement ce que la RFC prevoit. Le compter au garde punirait la
        // conformite.
        if response == b"*" {
            self.phase = Phase::Identified;
            return self.simple(Code::ARGUMENT_ERROR, b"Authentication aborted", out);
        }
        self.regler_authentification(response, out)
    }

    /// Decode, lit, interroge la politique, et repond.
    fn regler_authentification<'b>(
        &mut self,
        base64: &[u8],
        out: &'b mut [u8],
    ) -> Result<Turn<'b>, Error> {
        self.phase = Phase::Identified;

        // Un tampon FIXE : cette crate n'alloue pas (C3). Sa taille majore ce
        // qu'une ligne de commande peut porter apres decodage — `MAX_COMMAND` de
        // la RFC 5321 fait 512 octets, dont le base64 ne rend que 384. Une
        // configuration qui releverait la borne au-dela de 683 verrait des
        // reponses refusees ici, et c'est le bon sens de l'erreur.
        let mut clair = [0_u8; SASL_DECODED_MAX];
        let succes = match decode_base64(base64, &mut clair) {
            // `ecrits` ne depasse jamais la taille du tampon : `decode` n'ecrit
            // qu'a travers `get_mut`. L'indexation ne peut donc pas paniquer, et
            // un `get(..)` ouvrirait ici une branche qu'aucun test ne peut
            // atteindre — ce que C2 refuse.
            Ok(ecrits) => match parse_plain(&clair[..ecrits]) {
                Ok(identifiants) => {
                    let accorde = self.policy.authenticate(&identifiants);
                    if accorde {
                        // **ON RETIENT QUI S'EST AUTHENTIFIÉ**, et pas seulement
                        // QUE quelqu'un l'a fait. Un nom qui ne tient pas laisse
                        // le tampon vide, et la remise refusera alors tout
                        // `From:` : mieux vaut ne rien émettre que de signer une
                        // adresse qu'on ne sait pas rattacher à un compte.
                        self.compte.poser(&[identifiants.authentication_identity]);
                    }
                    accorde
                }
                Err(_) => false,
            },
            Err(_) => false,
        };

        self.authenticated = succes;
        if succes {
            self.simple(Code::AUTH_SUCCEEDED, b"Authentication successful", out)
        } else {
            // LE REFUS NE DIT PAS CE QUI A MANQUE. « Utilisateur inconnu » et
            // « mot de passe faux » sont deux reponses differentes, et cette
            // difference est un annuaire pour qui la mesure.
            //
            // Il est en revanche compte comme une FAUTE (C8) : un mot de passe
            // essaye au hasard est exactement ce qu'un garde doit voir passer.
            // Une faute de frappe humaine n'atteindra pas le seuil ; mille
            // tentatives par minute, si.
            self.refus(
                Code::AUTH_FAILED,
                b"Authentication credentials invalid",
                out,
            )
        }
    }

    /// Annule la transaction en cours, sans toucher a l'identification.
    fn reset_transaction(&mut self) {
        self.quitter_la_transaction();
    }

    /// Revient à l'état identifié, **et oublie les destinataires**.
    ///
    /// # Un seul endroit, et c'est le sujet
    ///
    /// Cinq chemins quittent une transaction : `RSET`, `EHLO`, `HELO`, la fin
    /// d'un message, et la poignée de main TLS. Chacun devait remettre la phase
    /// à zéro ; il leur faut maintenant vider aussi la liste des destinataires,
    /// et **celui qui l'oublierait livrerait le message suivant aux
    /// destinataires du précédent**. Ils passent donc tous par ici.
    fn quitter_la_transaction(&mut self) {
        self.phase = Phase::Identified;
        self.recipients.clear();
        // **LE COMPTE DES SAUTS EST CELUI D'UN MESSAGE**, pas d'une connexion :
        // le garder ferait refuser le second message pour les traces du premier.
        self.sauts = Sauts::new();
        // L'identifiant d'enveloppe est celui d'une TRANSACTION : le garder
        // ferait rattacher le rapport du message suivant à l'envoi précédent.
        self.envid_len = 0;
        // **LES DEUX RÉCEPTEURS REPARTENT À ZÉRO**, et pas seulement celui qu'on
        // vient d'employer : c'est ce qui rend `received_octets` sommable sans
        // avoir à savoir par quel chemin le message est arrivé.
        self.data = DataReceiver::new(self.config.limits(), self.config.max_message_octets());
        self.chunk = ChunkReceiver::new(self.config.limits(), self.config.max_message_octets());
        // L'IDENTITÉ EST CELLE D'UNE TRANSACTION, pas d'une connexion. La
        // laisser derrière ferait vérifier le message suivant sur l'expéditeur
        // du précédent — ou pire, ferait croire à un verdict qu'on n'a pas
        // demandé. Le `HELO`, lui, survit : c'est la connexion qui le porte.
        self.expediteur.vider();
        self.chemin_de_retour.vider();
        // **LE `Return-Path:` EST CELUI D'UNE TRANSACTION**, comme le reste : le
        // laisser derrière ferait consigner sur le message suivant l'expéditeur
        // d'enveloppe du précédent — et un `RSET` sert précisément à repartir de
        // rien.
        self.depose.vider();
        self.depose_vu = false;
        self.domaine_verifie.vider();
        self.verdict = None;
    }

    /// Une reponse d'une ligne, sans action et sans faute du pair.
    fn simple<'b>(&self, code: Code, texte: &[u8], out: &'b mut [u8]) -> Result<Turn<'b>, Error> {
        self.compose(code, texte, Action::Continue, false, out)
    }

    /// Une reponse d'une ligne qui SANCTIONNE UNE FAUTE du pair (cf.
    /// [`Turn::peer_fault`]).
    fn refus<'b>(&self, code: Code, texte: &[u8], out: &'b mut [u8]) -> Result<Turn<'b>, Error> {
        self.compose(code, texte, Action::Continue, true, out)
    }

    /// Une reponse d'une ligne, avec une action.
    fn finish<'b>(
        &self,
        code: Code,
        texte: &[u8],
        action: Action,
        out: &'b mut [u8],
    ) -> Result<Turn<'b>, Error> {
        self.compose(code, texte, action, false, out)
    }

    /// Compose une reponse d'une ligne, **code d'état étendu compris**.
    ///
    /// # RFC 2034 : LE CODE ÉTENDU PRÉFIXE LE TEXTE, ET RIEN D'AUTRE
    ///
    /// §4 veut qu'il soit écrit en tête du texte de TOUTES les réponses `2xx`,
    /// `4xx` et `5xx`. Les `3xx`, elles, n'en portent pas : ce sont des
    /// invitations à continuer — `334` et `354` —, pas des verdicts, et
    /// RFC 3463 ne définit aucune classe `3`. [`Status::new`] le refuse, ce qui
    /// rend l'oubli impossible plutôt qu'improbable.
    ///
    /// L'état vient d'une SEULE table ([`statut_de`]) : un même refus doit
    /// rendre le même état partout, et le composer sur place en cinquante-cinq
    /// endroits aurait fini par en donner deux au même sens.
    fn compose<'b>(
        &self,
        code: Code,
        texte: &[u8],
        action: Action,
        peer_fault: bool,
        out: &'b mut [u8],
    ) -> Result<Turn<'b>, Error> {
        let mut ligne = [0_u8; LIGNE_MAX];
        let texte = match statut_de(code, texte) {
            Some(statut) => prefixer(&mut ligne, statut, texte).unwrap_or(texte),
            None => texte,
        };
        let reply = encode(out, code, &[texte], self.config.limits()).map_err(Error::Reply)?;
        Ok(Turn {
            reply,
            action,
            peer_fault,
            refused_recipient: false,
        })
    }

    /// Une réponse qui REFUSE UN DESTINATAIRE, définitivement.
    ///
    /// Ce n'est pas une faute du pair — voir [`Turn::refused_recipient`].
    fn refus_de_destinataire<'b>(
        &self,
        code: Code,
        texte: &[u8],
        out: &'b mut [u8],
    ) -> Result<Turn<'b>, Error> {
        let mut tour = self.compose(code, texte, Action::Continue, false, out)?;
        tour.refused_recipient = true;
        Ok(tour)
    }
}

#[cfg(test)]
mod tests {
    use super::{Action, ChunkEvent, Code, DataFault, DataOutcome, HOPS_MAX, SmtpSession, Status};
    use crate::{Capabilities, Config, Error, Policy, RecipientVerdict, SenderPolicy};
    use ams_proto_smtp::{ClientId, DataEvent, Error as SmtpError, Limits, Path};
    use ams_spf::Verdict as SpfVerdict;

    /// L'erreur qu'un tampon de `disponible` octets provoque quand il en faut
    /// `needed`.
    ///
    /// On assère la valeur EXACTE plutôt qu'un `matches!` : ce dernier engendre
    /// un bras `_ => false` que rien n'emprunte, et le 100 % de C2 le compterait
    /// à jamais découvert — exactement comme un `panic!` de destructuration.
    /// La taille du refus permanent d'un destinataire : `550 ` + l'état étendu,
    /// puis le texte et le `\r\n`.
    const REFUS_PERMANENT: usize = 31;

    fn tampon_trop_petit(needed: usize) -> Error {
        Error::Reply(SmtpError::BufferTooSmall { needed })
    }

    /// Une politique qui rend toujours le même verdict, et connaît un compte.
    struct Verdict(RecipientVerdict);

    /// Le seul compte que la politique de test connaisse.
    const COMPTE: &[u8] = b"jean";
    /// Son mot de passe.
    const SECRET: &[u8] = b"ouvre-toi";

    impl crate::Authenticator for Verdict {
        fn authenticate(&self, credentials: &ams_sasl::Credentials<'_>) -> bool {
            credentials.authentication_identity == COMPTE && credentials.password == SECRET
        }
    }

    impl Policy for Verdict {
        fn accepts_recipient(
            &self,
            _forward_path: &Path<'_>,
            _submitter: bool,
        ) -> RecipientVerdict {
            self.0
        }
    }

    fn config() -> Config<'static> {
        Config::new(b"mail.example.com", 2, 10_485_760, Limits::DEFAULT)
            .expect("configurable")
            .with_capabilities(Capabilities {
                starttls: true,
                auth: true,
                dsn: false,
            })
    }

    fn session(verdict: RecipientVerdict) -> SmtpSession<'static, Verdict> {
        SmtpSession::new(config(), Verdict(verdict))
    }

    fn acceptante() -> SmtpSession<'static, Verdict> {
        session(RecipientVerdict::Accept)
    }

    /// Une session acceptante qui ne prend qu'un message de `combien` octets.
    fn session_bornee(combien: u64) -> SmtpSession<'static, Verdict> {
        let config = Config::new(b"mail.example.com", 2, combien, Limits::DEFAULT)
            .expect("configurable")
            .with_capabilities(Capabilities {
                starttls: true,
                auth: true,
                dsn: false,
            });
        SmtpSession::new(config, Verdict(RecipientVerdict::Accept))
    }

    /// Joue une ligne et rend la réponse sous forme de chaîne.
    fn jouer(session: &mut SmtpSession<'_, Verdict>, ligne: &[u8]) -> std::string::String {
        let mut tampon = [0_u8; 512];
        let tour = session.handle(ligne, &mut tampon).expect("réponse");
        std::string::String::from_utf8(tour.reply().to_vec()).expect("réponse ASCII")
    }

    /// Amène une session jusqu'à l'état identifié.
    fn identifier(session: &mut SmtpSession<'_, Verdict>) {
        assert!(jouer(session, b"EHLO client.example\r\n").starts_with("250"));
    }

    /// Amène une session jusqu'au premier `RCPT` accepté.
    fn transaction(session: &mut SmtpSession<'_, Verdict>) {
        identifier(session);
        assert!(jouer(session, b"MAIL FROM:<joe@example.net>\r\n").starts_with("250"));
        assert!(jouer(session, b"RCPT TO:<marie@example.com>\r\n").starts_with("250"));
    }

    /// Donne un morceau entier à la session, et rend ce qu'elle en a fait.
    fn morceau(session: &mut SmtpSession<'_, Verdict>, octets: &[u8]) -> std::vec::Vec<u8> {
        let mut rendu = std::vec::Vec::new();
        let mut reste = octets;
        loop {
            let (evenement, combien) = session.feed_chunk(reste).expect("morceau");
            reste = reste.get(combien..).unwrap_or_default();
            match evenement {
                ChunkEvent::Content(vus) => rendu.extend_from_slice(vus),
                ChunkEvent::NeedMore | ChunkEvent::ChunkComplete | ChunkEvent::Complete => {
                    return rendu;
                }
            }
        }
    }

    // ── LES PARAMÈTRES ESMTP (§4.1.1.11) ────────────────────────────────────

    /// **`SIZE` EST ANNONCÉ, DONC IL EST TENU** (RFC 1870 §6.2).
    ///
    /// Un serveur qui l'offre et ne s'en sert pas fait lire au pair un
    /// mébioctet qu'il a déjà décidé de refuser.
    #[test]
    fn une_taille_annoncee_au_dela_de_la_borne_est_refusee_tout_de_suite() {
        let mut session = session_bornee(1024);
        identifier(&mut session);
        let dit = jouer(&mut session, b"MAIL FROM:<joe@example.net> SIZE=1025\r\n");
        assert!(dit.starts_with("552 5.3.4"), "{dit}");
        // Et la transaction n'est PAS ouverte : le `RCPT` qui suivrait n'aurait
        // pas d'expéditeur.
        assert!(jouer(&mut session, b"RCPT TO:<marie@example.com>\r\n").starts_with("503"));

        // Ce qui tient passe, y compris la borne exacte.
        assert!(
            jouer(&mut session, b"MAIL FROM:<joe@example.net> SIZE=1024\r\n").starts_with("250")
        );
    }

    /// **UNE TAILLE ILLISIBLE N'EST PAS UNE PETITE TAILLE.**
    #[test]
    fn une_taille_mal_ecrite_est_refusee() {
        for mauvais in [
            &b"MAIL FROM:<joe@example.net> SIZE=abc\r\n"[..],
            b"MAIL FROM:<joe@example.net> SIZE\r\n",
            b"MAIL FROM:<joe@example.net> SIZE=-1\r\n",
            // Déborde `u64` : une taille tronquée passerait la vérification.
            b"MAIL FROM:<joe@example.net> SIZE=18446744073709551616\r\n",
        ] {
            let mut session = acceptante();
            identifier(&mut session);
            let dit = jouer(&mut session, mauvais);
            assert!(dit.starts_with("504 5.5.4"), "{mauvais:?} : {dit}");
        }
        // `SIZE=` sans valeur ne nous parvient même pas : la GRAMMAIRE l'a
        // refusé, et c'est une erreur de syntaxe, pas de paramètre.
        let mut session = acceptante();
        identifier(&mut session);
        let dit = jouer(&mut session, b"MAIL FROM:<joe@example.net> SIZE=\r\n");
        assert!(dit.starts_with("501 5.5.2"), "{dit}");
    }

    /// **UN DÉBORDEMENT EST UN REFUS, ET NON UNE TRONCATURE.**
    ///
    /// Une taille annoncée plus petite qu'elle ne l'est passerait la
    /// vérification de §6.2, et le message serait lu tout entier.
    #[test]
    fn une_taille_qui_deborde_n_est_pas_tronquee() {
        assert_eq!(super::decimal_u64(b"0"), Some(0));
        assert_eq!(
            super::decimal_u64(b"18446744073709551615"),
            Some(u64::MAX),
            "la plus grande qui tienne"
        );
        // Celle d'après déborde à l'ADDITION du dernier chiffre…
        assert_eq!(super::decimal_u64(b"18446744073709551616"), None);
        // …et celle-là à la MULTIPLICATION, un chiffre plus tôt.
        assert_eq!(super::decimal_u64(b"99999999999999999999999"), None);
        assert_eq!(super::decimal_u64(b""), None);
        assert_eq!(super::decimal_u64(b"12x"), None);
    }

    /// **`BODY=8BITMIME` ET `BODY=7BIT` SONT COMPRIS** (RFC 6152), et le reste
    /// non.
    #[test]
    fn le_corps_sur_huit_bits_est_compris() {
        for bon in [
            &b"MAIL FROM:<joe@example.net> BODY=8BITMIME\r\n"[..],
            b"MAIL FROM:<joe@example.net> BODY=7bit\r\n",
            // `AUTH=` s'accepte sans qu'on s'y fie (RFC 4954 §5).
            b"MAIL FROM:<joe@example.net> AUTH=<>\r\n",
            b"MAIL FROM:<joe@example.net> SIZE=10 BODY=8BITMIME AUTH=<>\r\n",
        ] {
            let mut session = acceptante();
            identifier(&mut session);
            assert!(jouer(&mut session, bon).starts_with("250"), "{bon:?}");
        }
        for mauvais in [
            &b"MAIL FROM:<joe@example.net> BODY=BINARYMIME\r\n"[..],
            b"MAIL FROM:<joe@example.net> BODY\r\n",
            b"MAIL FROM:<joe@example.net> SMTPUTF8\r\n",
        ] {
            let mut session = acceptante();
            identifier(&mut session);
            let dit = jouer(&mut session, mauvais);
            assert!(dit.starts_with("504 5.5.4"), "{mauvais:?} : {dit}");
        }
    }

    /// **UN PARAMÈTRE ACCEPTÉ EN SILENCE EST UNE PROMESSE QU'ON N'A PAS FAITE.**
    ///
    /// `NOTIFY=NEVER` en est l'exemple qui coûte : l'expéditeur croit avoir
    /// supprimé ses rapports de non-remise, et les recevra quand même.
    #[test]
    fn un_parametre_de_rcpt_est_refuse() {
        let mut session = acceptante();
        transaction(&mut session);
        // La transaction est ouverte ; un second `RCPT` avec paramètre échoue.
        for mauvais in [
            &b"RCPT TO:<marie@example.com> NOTIFY=NEVER\r\n"[..],
            b"RCPT TO:<marie@example.com> ORCPT=rfc822;marie@example.com\r\n",
        ] {
            let dit = jouer(&mut session, mauvais);
            assert!(dit.starts_with("504 5.5.4"), "{mauvais:?} : {dit}");
        }
        // Sans paramètre, il passe.
        assert!(jouer(&mut session, b"RCPT TO:<marie@example.com>\r\n").starts_with("250"));
    }

    // ── DSN (RFC 3461) ──────────────────────────────────────────────────────

    /// Une session qui sait émettre, donc qui annonce `DSN`.
    fn dsn() -> SmtpSession<'static, Verdict> {
        let config = Config::new(b"mail.example.com", 2, 10_485_760, Limits::DEFAULT)
            .expect("configurable")
            .with_capabilities(Capabilities {
                starttls: true,
                auth: true,
                dsn: true,
            });
        SmtpSession::new(config, Verdict(RecipientVerdict::Accept))
    }

    /// **`DSN` NE S'ANNONCE QUE SI L'ON PEUT ÉMETTRE** (§4.2).
    #[test]
    fn dsn_ne_s_annonce_que_si_l_on_peut_emettre() {
        let mut muette = acceptante();
        assert!(!jouer(&mut muette, b"EHLO client.example\r\n").contains("DSN"));
        let mut session = dsn();
        assert!(jouer(&mut session, b"EHLO client.example\r\n").contains("250-DSN\r\n"));
    }

    /// **CE QU'ON N'ANNONCE PAS SE REFUSE**, y compris `NOTIFY`.
    #[test]
    fn sans_annonce_les_parametres_dsn_sont_refuses() {
        let mut session = acceptante();
        identifier(&mut session);
        for mauvais in [
            &b"MAIL FROM:<joe@example.net> RET=HDRS\r\n"[..],
            b"MAIL FROM:<joe@example.net> ENVID=abc\r\n",
        ] {
            assert!(
                jouer(&mut session, mauvais).starts_with("504"),
                "{mauvais:?}"
            );
        }
        assert!(jouer(&mut session, b"MAIL FROM:<joe@example.net>\r\n").starts_with("250"));
        assert!(
            jouer(
                &mut session,
                b"RCPT TO:<marie@example.com> NOTIFY=NEVER\r\n"
            )
            .starts_with("504")
        );
    }

    /// **CE QUE CHAQUE DESTINATAIRE DEMANDE LUI EST PROPRE** (§4.1).
    #[test]
    fn chaque_destinataire_demande_ce_qu_il_veut() {
        let mut session = dsn();
        identifier(&mut session);
        assert!(
            jouer(
                &mut session,
                b"MAIL FROM:<joe@example.net> ENVID=a+2Bb RET=HDRS\r\n"
            )
            .starts_with("250")
        );
        // L'identifiant est rendu DÉCODÉ, une seule fois.
        assert_eq!(session.envelope_id(), Some(&b"a+b"[..]));

        assert!(
            jouer(
                &mut session,
                b"RCPT TO:<marie@example.com> NOTIFY=NEVER\r\n"
            )
            .starts_with("250")
        );
        assert!(
            jouer(
                &mut session,
                b"RCPT TO:<jean@example.com> NOTIFY=SUCCESS ORCPT=rfc822;jean+2Bliste@example.com\r\n"
            )
            .starts_with("250")
        );

        let (premier, orcpt) = session.recipient_report(0).expect("un rapport");
        assert!(premier.never());
        assert!(orcpt.is_empty(), "aucun `ORCPT` n'a été donné");
        let (second, orcpt) = session.recipient_report(1).expect("un rapport");
        assert!(second.on_success() && !second.never());
        assert_eq!(orcpt, b"jean+liste@example.com");
        // Au-delà des destinataires acceptés, il n'y a rien.
        assert_eq!(session.recipient_report(2), None);

        // Et une nouvelle transaction oublie tout.
        assert!(jouer(&mut session, b"RSET\r\n").starts_with("250"));
        assert_eq!(session.envelope_id(), None);
    }

    /// **UNE VALEUR IRRECEVABLE EST REFUSÉE**, et non corrigée.
    #[test]
    fn une_valeur_dsn_irrecevable_est_refusee() {
        let mut session = dsn();
        identifier(&mut session);
        for mauvais in [
            &b"MAIL FROM:<joe@example.net> RET=BODY\r\n"[..],
            b"MAIL FROM:<joe@example.net> RET\r\n",
            b"MAIL FROM:<joe@example.net> ENVID=a+2b\r\n", // minuscule hexadécimale
            b"MAIL FROM:<joe@example.net> ENVID\r\n",
        ] {
            assert!(
                jouer(&mut session, mauvais).starts_with("504"),
                "{mauvais:?}"
            );
        }
        assert!(jouer(&mut session, b"MAIL FROM:<joe@example.net>\r\n").starts_with("250"));
        for mauvais in [
            &b"RCPT TO:<marie@example.com> NOTIFY=NEVER,SUCCESS\r\n"[..],
            b"RCPT TO:<marie@example.com> NOTIFY=MAYBE\r\n",
            b"RCPT TO:<marie@example.com> NOTIFY\r\n",
            b"RCPT TO:<marie@example.com> ORCPT=marie@example.com\r\n",
            b"RCPT TO:<marie@example.com> ORCPT\r\n",
            // **UN MOT-CLÉ QU'ON NE CONNAÎT PAS**, même quand `DSN` est
            // annoncé : ce n'est pas parce qu'on sert deux paramètres qu'on
            // sert tous ceux qui leur ressemblent.
            b"RCPT TO:<marie@example.com> NOTIFYY=NEVER\r\n",
            b"RCPT TO:<marie@example.com> RET=HDRS\r\n",
        ] {
            assert!(
                jouer(&mut session, mauvais).starts_with("504"),
                "{mauvais:?}"
            );
        }
    }

    // ── LES CODES D'ÉTAT ÉTENDUS (RFC 2034, RFC 3463) ───────────────────────

    /// **LA CLASSE VIENT DU CODE, JAMAIS DU TEXTE**, et ce qui n'est pas nommé
    /// prend le sujet « indéfini » (§3.3).
    #[test]
    fn un_texte_inconnu_prend_un_etat_de_la_bonne_classe() {
        for (code, attendu) in [
            (Code::OK, Status::OK),
            (Code::LOCAL_ERROR, Status::LOCAL_ERROR),
            (Code::TRANSACTION_FAILED, Status::POLICY_OTHER),
        ] {
            let vu = super::statut_de(code, b"un texte que la table ne nomme pas")
                .expect("une classe qui en porte un");
            assert_eq!(vu, attendu);
            assert!(vu.agrees_with(code), "la classe contredit le code");
        }
        // **LES `3xx` N'EN PORTENT PAS** : ce sont des invitations à continuer,
        // et RFC 3463 ne définit aucune classe `3`.
        assert_eq!(
            super::statut_de(Code::START_MAIL_INPUT, b"peu importe"),
            None
        );
        assert_eq!(super::statut_de(Code::AUTH_CHALLENGE, b""), None);
    }

    /// **UN ÉTAT QUI CONTREDIRAIT SON CODE EST ÉCARTÉ** : la table peut se
    /// tromper, le code à trois chiffres non.
    #[test]
    fn un_etat_qui_contredit_son_code_est_ecarte() {
        // `Mailbox unavailable` est nommé `5.1.1` ; sous un code `4xx`, il ne
        // peut pas s'appliquer, et c'est l'état générique de la classe qui sort.
        let vu = super::statut_de(Code::MAILBOX_BUSY, b"Mailbox unavailable")
            .expect("une classe qui en porte un");
        assert_eq!(vu, Status::LOCAL_ERROR);
        assert!(vu.agrees_with(Code::MAILBOX_BUSY));
    }

    /// **UNE RÉPONSE AMPUTÉE SERAIT PIRE QU'UNE RÉPONSE SANS CODE ÉTENDU.**
    ///
    /// `LIGNE_MAX` suffit largement au vocabulaire de ce serveur ; ce qui n'y
    /// tiendrait pas part sans son état, et non coupé au milieu.
    #[test]
    fn un_etat_qui_ne_tient_pas_ne_tronque_rien() {
        let mut juste = [0_u8; 8];
        assert_eq!(
            super::prefixer(&mut juste, Status::OK, b"OK"),
            Some(&b"2.0.0 OK"[..])
        );
        // Une place qui ne suffit ni à l'état, ni à l'espace, ni au texte.
        for taille in 0..8 {
            let mut court = std::vec![0_u8; taille];
            assert_eq!(
                super::prefixer(&mut court, Status::OK, b"OK"),
                None,
                "une taille de {taille} a suffi"
            );
        }
    }

    // ── L'EN-TÊTE `Received:` ET LES SAUTS ──────────────────────────────────

    /// **LE MOT DE `with` DIT CE QUI S'EST PASSÉ** (RFC 3848).
    #[test]
    fn le_received_dit_par_ou_le_message_est_passe() {
        let mut session = acceptante();
        let mut trace = [0_u8; 700];
        let client = core::net::IpAddr::V4(core::net::Ipv4Addr::new(192, 0, 2, 1));

        // Sans `EHLO` ni `HELO`, il n'y a pas de nom à écrire.
        assert!(
            session
                .received(client, 1_788_242_400, &mut trace)
                .is_none()
        );

        assert!(jouer(&mut session, b"HELO client.example\r\n").starts_with("250"));
        let vu = session
            .received(client, 1_788_242_400, &mut trace)
            .expect("composable");
        let texte = std::string::String::from_utf8(vu.to_vec()).expect("ASCII");
        assert!(
            texte.starts_with(
                "Received: from client.example ([192.0.2.1])\r\n\tby \
                 mail.example.com with SMTP;\r\n\t"
            ),
            "{texte:?}"
        );
        // **AUCUN DESTINATAIRE N'Y EST NOMMÉ**, jamais.
        assert!(!texte.contains(" for "), "{texte:?}");

        // `EHLO` fait un `ESMTP`, et le chiffrement un `ESMTPS`.
        assert!(jouer(&mut session, b"EHLO client.example\r\n").starts_with("250"));
        let vu = session
            .received(client, 1_788_242_400, &mut trace)
            .expect("composable");
        assert!(
            std::string::String::from_utf8_lossy(vu).contains("with ESMTP;"),
            "{vu:?}"
        );
        session.on_tls_established();
        assert!(jouer(&mut session, b"EHLO client.example\r\n").starts_with("250"));
        let vu = session
            .received(client, 1_788_242_400, &mut trace)
            .expect("composable");
        assert!(
            std::string::String::from_utf8_lossy(vu).contains("with ESMTPS;"),
            "{vu:?}"
        );
        // Et l'authentification ajoute le `A`.
        assert!(jouer(&mut session, b"AUTH PLAIN AGplYW4Ab3V2cmUtdG9p\r\n").starts_with("235"));
        let vu = session
            .received(client, 1_788_242_400, &mut trace)
            .expect("composable");
        assert!(
            std::string::String::from_utf8_lossy(vu).contains("with ESMTPSA;"),
            "{vu:?}"
        );
        // **UN EN-TÊTE QU'ON NE SAIT PAS ÉCRIRE NE S'ÉCRIT PAS.**
        let mut minuscule = [0_u8; 8];
        assert!(
            session
                .received(client, 1_788_242_400, &mut minuscule)
                .is_none()
        );
    }

    /// **UN MESSAGE QUI TOURNE EN BOUCLE FINIT PAR S'ARRÊTER** (§6.3), et le
    /// verdict de l'appelant n'est pas consulté.
    #[test]
    fn un_message_qui_porte_trop_de_traces_est_refuse() {
        let mut session = acceptante();
        transaction(&mut session);
        assert!(jouer(&mut session, b"DATA\r\n").starts_with("354"));

        let mut refuse = false;
        for rang in 0..=HOPS_MAX {
            let ligne = std::format!("Received: par le saut {rang}\r\n");
            if session.feed_data(ligne.as_bytes()).is_err() {
                refuse = true;
                break;
            }
        }
        assert!(refuse, "trente et un sauts sont passés");

        let mut tampon = [0_u8; 512];
        let tour = session
            .on_data_settled(DataOutcome::Accepted, &mut tampon)
            .expect("réponse");
        let dit = std::string::String::from_utf8_lossy(tour.reply()).into_owned();
        assert!(dit.starts_with("554"), "{dit}");
        assert!(dit.contains("Too many hops"), "{dit}");
        // Hors de la phase de données, plus rien ne se sert.
        assert_eq!(
            session.feed_data(b"x").map(|_| ()),
            Err(Error::NotInDataPhase)
        );
    }

    /// **LE COMPTE EST CELUI D'UN MESSAGE**, pas d'une connexion : le second ne
    /// se refuse pas pour les traces du premier.
    #[test]
    fn le_compte_des_sauts_repart_a_chaque_message() {
        let mut session = acceptante();
        transaction(&mut session);
        assert!(jouer(&mut session, b"DATA\r\n").starts_with("354"));
        for rang in 0..HOPS_MAX {
            let ligne = std::format!("Received: par le saut {rang}\r\n");
            session.feed_data(ligne.as_bytes()).expect("accepté");
        }
        session.feed_data(b"\r\n.\r\n").expect("fin");
        let mut tampon = [0_u8; 512];
        assert!(
            session
                .on_data_settled(DataOutcome::Accepted, &mut tampon)
                .expect("réponse")
                .reply()
                .starts_with(b"250")
        );

        // Un second message, avec autant de traces, passe aussi.
        transaction(&mut session);
        assert!(jouer(&mut session, b"DATA\r\n").starts_with("354"));
        for rang in 0..HOPS_MAX {
            let ligne = std::format!("Received: par le saut {rang}\r\n");
            session.feed_data(ligne.as_bytes()).expect("accepté");
        }
    }

    // ── `BDAT` (RFC 3030 §2) ────────────────────────────────────────────────

    /// **LA RÉPONSE NE PART QU'APRÈS LES OCTETS** : le tour d'un `BDAT` est
    /// muet, et c'est le morceau lu qui fait parler la session.
    #[test]
    fn un_bdat_rend_la_main_sans_repondre() {
        let mut session = acceptante();
        transaction(&mut session);
        let mut tampon = [0_u8; 512];
        let tour = session.handle(b"BDAT 5\r\n", &mut tampon).expect("tour");
        assert!(tour.reply().is_empty(), "la session a parlé trop tôt");
        assert_eq!(
            tour.action(),
            Action::ReceiveChunk {
                size: 5,
                last: false
            }
        );
        assert_eq!(morceau(&mut session, b"salut"), b"salut");
        assert_eq!(session.received_octets(), 5);
        assert_eq!(jouer_apres_morceau(&mut session), "250 2.0.0 Chunk ok\r\n");
    }

    /// Rend la réponse d'un morceau non final.
    fn jouer_apres_morceau(session: &mut SmtpSession<'_, Verdict>) -> std::string::String {
        let mut tampon = [0_u8; 512];
        let tour = session.on_chunk_received(&mut tampon).expect("réponse");
        std::string::String::from_utf8(tour.reply().to_vec()).expect("ASCII")
    }

    /// **UN MESSAGE EN DEUX MORCEAUX SE CONCLUT COMME UN `DATA`.**
    #[test]
    fn un_dernier_morceau_se_conclut_comme_un_data() {
        let mut session = acceptante();
        transaction(&mut session);
        assert!(jouer(&mut session, b"BDAT 4\r\n").is_empty());
        assert_eq!(morceau(&mut session, b"abc\r"), b"abc\r");
        assert_eq!(jouer_apres_morceau(&mut session), "250 2.0.0 Chunk ok\r\n");

        // Le `LF` du `CRLF` arrive dans le morceau SUIVANT, et reste licite.
        assert!(jouer(&mut session, b"BDAT 4 LAST\r\n").is_empty());
        assert_eq!(morceau(&mut session, b"\ndef"), b"\ndef");
        let mut tampon = [0_u8; 512];
        let tour = session
            .on_data_settled(DataOutcome::Accepted, &mut tampon)
            .expect("réponse");
        assert!(
            std::string::String::from_utf8_lossy(tour.reply())
                .starts_with("250 2.0.0 Message accepted")
        );
        // La transaction est quittée : les compteurs repartent de zéro.
        assert_eq!(session.received_octets(), 0);
    }

    /// **UN `CR` PENDANT À LA FIN D'UN MESSAGE EST UN `CR` ISOLÉ**, et le
    /// verdict de l'appelant n'est pas consulté.
    #[test]
    fn un_message_qui_finit_sur_un_cr_est_refuse() {
        let mut session = acceptante();
        transaction(&mut session);
        assert!(jouer(&mut session, b"BDAT 2 LAST\r\n").is_empty());
        assert_eq!(morceau(&mut session, b"a\r"), b"a\r");
        // La lecture du dernier octet ne conclut pas : c'est l'appel suivant qui
        // découvre le `CR` pendant.
        assert_eq!(
            session.feed_chunk(&[]).expect("morceau").0,
            ChunkEvent::NeedMore
        );
        let mut tampon = [0_u8; 512];
        let tour = session
            .on_data_settled(DataOutcome::Accepted, &mut tampon)
            .expect("réponse");
        assert!(
            std::string::String::from_utf8_lossy(tour.reply()).contains("Bare CR or LF"),
            "un message refusé a été accepté"
        );
    }

    /// **UNE FAUTE N'ARRÊTE PAS LA LECTURE** : les octets sont annoncés, et ne
    /// pas les consommer laisserait leur queue passer pour des commandes.
    #[test]
    fn une_faute_de_morceau_laisse_consommer_le_reste() {
        let mut session = acceptante();
        transaction(&mut session);
        assert!(jouer(&mut session, b"BDAT 6\r\n").is_empty());
        // Ce qui précède l'octet fautif est rendu…
        assert_eq!(
            session.feed_chunk(b"a\nbcde").expect("morceau"),
            (ChunkEvent::Content(b"a"), 1)
        );
        // …puis le `LF` nu est refusé, et la session avale le reste sans le lire.
        assert_eq!(
            session.feed_chunk(b"\nbcde").expect("morceau"),
            (ChunkEvent::NeedMore, 5)
        );
        assert_eq!(
            session.feed_chunk(b"zzz").expect("morceau"),
            (ChunkEvent::NeedMore, 3),
            "ce qui reste s'avale sans être lu"
        );
        assert_eq!(
            jouer_apres_morceau(&mut session),
            "554 5.6.0 Bare CR or LF in message data\r\n"
        );
    }

    /// **CHAQUE FAUTE A SA RÉPONSE**, et une transaction quittée les oublie.
    #[test]
    fn chaque_faute_de_morceau_a_sa_reponse() {
        // Une ligne trop longue ne peut pas venir d'un `BDAT` — il n'a pas de
        // lignes — mais la réponse existe, et un `_` la cacherait.
        let mut session = acceptante();
        transaction(&mut session);
        let mut tampon = [0_u8; 512];
        for (cause, attendu) in [
            (DataFault::BareLineEnding, "554"),
            (DataFault::LineTooLong { limit: 10 }, "500"),
            (DataFault::MessageTooLarge { limit: 10 }, "552"),
        ] {
            let tour = session
                .refus_de_morceau(cause, &mut tampon)
                .expect("réponse");
            assert!(
                std::string::String::from_utf8_lossy(tour.reply()).starts_with(attendu),
                "{cause:?} n'a pas rendu {attendu}"
            );
        }
    }

    /// **`BDAT` ET `DATA` SE DISPUTENT LE MÊME MESSAGE.**
    #[test]
    fn un_data_apres_un_bdat_est_une_faute_de_sequence() {
        let mut session = acceptante();
        transaction(&mut session);
        assert!(jouer(&mut session, b"BDAT 5\r\n").is_empty());
        assert_eq!(morceau(&mut session, b"salut"), b"salut");
        assert_eq!(jouer_apres_morceau(&mut session), "250 2.0.0 Chunk ok\r\n");
        assert!(
            jouer(&mut session, b"DATA\r\n").starts_with("503 5.5.0 BDAT already started"),
            "un DATA a été servi au milieu d'un BDAT"
        );
    }

    /// **SANS `MAIL` NI `RCPT`, RIEN N'EST LU.**
    #[test]
    fn un_bdat_hors_transaction_est_refuse() {
        let mut session = acceptante();
        identifier(&mut session);
        assert!(jouer(&mut session, b"BDAT 5\r\n").starts_with("503 5.5.0 Need MAIL and RCPT"));
        assert!(jouer(&mut session, b"MAIL FROM:<joe@example.net>\r\n").starts_with("250"));
        assert!(jouer(&mut session, b"BDAT 5\r\n").starts_with("503 5.5.0 Need RCPT"));
    }

    /// **LA TAILLE SE REFUSE À L'ANNONCE**, avant d'avoir lu un octet.
    #[test]
    fn un_morceau_plus_grand_que_le_message_permis_est_refuse() {
        let mut session = session_bornee(16);
        transaction(&mut session);
        assert!(jouer(&mut session, b"BDAT 17 LAST\r\n").starts_with("552"));
        // Et la transaction est quittée : le `BDAT` suivant n'a plus de
        // destinataire.
        assert!(jouer(&mut session, b"BDAT 1 LAST\r\n").starts_with("503"));
    }

    /// **HORS D'UN MORCEAU, ON NE DONNE PAS D'OCTETS.**
    #[test]
    fn nourrir_un_morceau_hors_phase_est_une_erreur() {
        let mut session = acceptante();
        transaction(&mut session);
        assert_eq!(session.feed_chunk(b"x"), Err(Error::NotInDataPhase));
        let mut tampon = [0_u8; 512];
        assert_eq!(
            session.on_chunk_received(&mut tampon).map(|_| ()),
            Err(Error::NotInCommandPhase)
        );
        // Et pendant un morceau, aucune commande ne se sert.
        assert!(jouer(&mut session, b"BDAT 2\r\n").is_empty());
        assert_eq!(
            session.handle(b"NOOP\r\n", &mut tampon).map(|_| ()),
            Err(Error::NotInCommandPhase)
        );
    }

    // ── L'ouverture ─────────────────────────────────────────────────────────

    #[test]
    fn le_refus_de_servir_vient_de_la_session_pas_de_la_boucle() {
        // Un `421` fabriqué par la boucle serait la première fuite de protocole
        // hors des crates sans entrée-sortie.
        let session = acceptante();
        let mut tampon = [0_u8; 128];
        assert_eq!(
            session.unavailable(&mut tampon).expect("réponse"),
            b"421 4.3.2 Service not available, closing transmission channel\r\n"
        );
        let mut minuscule = [0_u8; 4];
        assert_eq!(
            session.unavailable(&mut minuscule),
            Err(tampon_trop_petit(63))
        );
    }

    #[test]
    fn la_banniere_nomme_le_serveur() {
        let session = acceptante();
        let mut tampon = [0_u8; 128];
        let banniere = session.greeting(&mut tampon).expect("bannière");
        assert_eq!(banniere, b"220 mail.example.com ESMTP\r\n");
    }

    #[test]
    fn un_tampon_trop_petit_est_une_faute_de_l_appelant_pas_du_pair() {
        let session = acceptante();
        let mut tampon = [0_u8; 4];
        // « mail.example.com ESMTP » fait 22 octets, plus l'enveloppe de six.
        assert_eq!(session.greeting(&mut tampon), Err(tampon_trop_petit(28)));
    }

    // ── EHLO, et ce qu'il annonce ───────────────────────────────────────────

    #[test]
    fn ehlo_annonce_starttls_mais_pas_auth_avant_chiffrement() {
        // ANNONCER `AUTH` EN CLAIR FERAIT ENVOYER UN MOT DE PASSE EN CLAIR à un
        // client qui aurait cru l'offre.
        let mut session = acceptante();
        let reponse = jouer(&mut session, b"EHLO client.example\r\n");
        assert_eq!(
            reponse,
            "250-mail.example.com\r\n250-SIZE 10485760\r\n250-8BITMIME\r\n250-ENHANCEDSTATUSCODES\r\n250-PIPELINING\r\n250-CHUNKING\r\n250 STARTTLS\r\n"
        );
        assert!(!reponse.contains("AUTH"));
    }

    #[test]
    fn ehlo_annonce_auth_mais_plus_starttls_apres_chiffrement() {
        let mut session = acceptante();
        session.on_tls_established();
        let reponse = jouer(&mut session, b"EHLO client.example\r\n");
        assert_eq!(
            reponse,
            "250-mail.example.com\r\n250-SIZE 10485760\r\n250-8BITMIME\r\n250-ENHANCEDSTATUSCODES\r\n250-PIPELINING\r\n250-CHUNKING\r\n250 AUTH PLAIN\r\n"
        );
        assert!(!reponse.contains("STARTTLS"));
    }

    #[test]
    fn helo_est_accepte_mais_n_annonce_rien() {
        // Une session `HELO` ne peut donc ni chiffrer ni s'authentifier.
        let mut session = acceptante();
        assert_eq!(
            jouer(&mut session, b"HELO client.example\r\n"),
            "250 mail.example.com\r\n"
        );
    }

    #[test]
    fn ehlo_annule_la_transaction_en_cours() {
        // RFC 5321 §4.1.4.
        let mut session = acceptante();
        identifier(&mut session);
        assert!(jouer(&mut session, b"MAIL FROM:<a@b.co>\r\n").starts_with("250"));
        identifier(&mut session);
        // La transaction n'existe plus : `RCPT` redevient hors séquence.
        assert!(jouer(&mut session, b"RCPT TO:<c@d.co>\r\n").starts_with("503"));
    }

    // ── Le séquencement ─────────────────────────────────────────────────────

    #[test]
    fn le_sequencement_est_impose() {
        let mut session = acceptante();
        assert!(jouer(&mut session, b"MAIL FROM:<a@b.co>\r\n").starts_with("503"));
        identifier(&mut session);
        assert!(jouer(&mut session, b"RCPT TO:<c@d.co>\r\n").starts_with("503"));
        assert!(jouer(&mut session, b"DATA\r\n").starts_with("503"));
        assert!(jouer(&mut session, b"MAIL FROM:<a@b.co>\r\n").starts_with("250"));
        assert!(jouer(&mut session, b"MAIL FROM:<a@b.co>\r\n").starts_with("503"));
        assert!(jouer(&mut session, b"DATA\r\n").starts_with("503"));
        assert!(jouer(&mut session, b"RCPT TO:<c@d.co>\r\n").starts_with("250"));
        assert!(jouer(&mut session, b"DATA\r\n").starts_with("354"));
    }

    #[test]
    fn data_rend_la_main_a_l_appelant() {
        let mut session = acceptante();
        identifier(&mut session);
        jouer(&mut session, b"MAIL FROM:<a@b.co>\r\n");
        jouer(&mut session, b"RCPT TO:<c@d.co>\r\n");
        let mut tampon = [0_u8; 128];
        let tour = session.handle(b"DATA\r\n", &mut tampon).expect("réponse");
        assert_eq!(tour.action(), Action::ReceiveData);
        // Et la session n'accepte plus de commande : c'est le message qu'elle
        // attend, pas un verbe.
        assert_eq!(
            session.handle(b"NOOP\r\n", &mut tampon),
            Err(Error::NotInCommandPhase)
        );

        // Le verdict de l'appelant referme la transaction.
        let tour = session
            .on_data_settled(DataOutcome::Accepted, &mut tampon)
            .expect("verdict");
        assert_eq!(tour.reply(), b"250 2.0.0 Message accepted\r\n");
        // On reste identifié : un autre message peut suivre sans nouvel `EHLO`.
        assert!(jouer(&mut session, b"MAIL FROM:<a@b.co>\r\n").starts_with("250"));
    }

    /// Amène une session jusqu'à la phase de données.
    fn jusqu_aux_donnees(session: &mut SmtpSession<'_, Verdict>) {
        identifier(session);
        jouer(session, b"MAIL FROM:<a@b.co>\r\n");
        jouer(session, b"RCPT TO:<c@d.co>\r\n");
        assert!(jouer(session, b"DATA\r\n").starts_with("354"));
    }

    /// Donne un message entier à la session, et rend ce qu'elle en a extrait.
    fn remettre(
        session: &mut SmtpSession<'_, Verdict>,
        flux: &[u8],
    ) -> Result<std::vec::Vec<u8>, Error> {
        let mut recu = std::vec::Vec::new();
        let mut debut = 0_usize;
        while debut < flux.len() {
            let (evenement, consomme) = session.feed_data(&flux[debut..])?;
            match evenement {
                DataEvent::Complete => return Ok(recu),
                DataEvent::Content(morceau) => recu.extend_from_slice(morceau),
                DataEvent::NeedMore => {}
            }
            // L'invariante de progrès du récepteur, éprouvée ici aussi.
            assert!(consomme > 0, "le récepteur n'a ni consommé ni conclu");
            debut = debut.saturating_add(consomme);
        }
        // Le flux s'est arrêté sans `<CRLF>.<CRLF>` : le pair a raccroché.
        Ok(recu)
    }

    // ── La phase de données ─────────────────────────────────────────────────

    #[test]
    fn un_message_traverse_la_session_intact() {
        let mut session = acceptante();
        jusqu_aux_donnees(&mut session);
        assert_eq!(
            remettre(&mut session, b"From: moi\r\n\r\nbonjour\r\n.\r\n").expect("recevable"),
            b"From: moi\r\n\r\nbonjour\r\n"
        );
        assert_eq!(session.received_octets(), 22);

        let mut tampon = [0_u8; 128];
        let tour = session
            .on_data_settled(DataOutcome::Accepted, &mut tampon)
            .expect("verdict");
        assert_eq!(tour.reply(), b"250 2.0.0 Message accepted\r\n");
    }

    #[test]
    fn le_point_echappe_traverse_la_session_comme_le_codec() {
        // RFC 5321 §4.5.2 : la session ne fait que relayer le récepteur, et le
        // point échappé se consomme sans rien rendre — c'est le seul cas où un
        // appel ne produit aucun octet tout en progressant.
        let mut session = acceptante();
        jusqu_aux_donnees(&mut session);
        assert_eq!(
            remettre(&mut session, b"..cache\r\n.\r\n").expect("recevable"),
            b".cache\r\n"
        );
        // Le point échappé compte sur le fil, pas dans le message.
        assert_eq!(session.received_octets(), 8);
    }

    #[test]
    fn un_pair_qui_raccroche_laisse_un_message_inachevé() {
        // La transaction ne se conclut pas d'elle-même : c'est à la boucle de
        // constater la déconnexion, et de ne rien remettre.
        let mut session = acceptante();
        jusqu_aux_donnees(&mut session);
        assert_eq!(
            remettre(&mut session, b"debut sans fin\r\n").expect("recevable"),
            b"debut sans fin\r\n"
        );
        // La session attend toujours la suite du message.
        let mut tampon = [0_u8; 128];
        assert_eq!(
            session.handle(b"NOOP\r\n", &mut tampon),
            Err(Error::NotInCommandPhase)
        );
    }

    #[test]
    fn des_donnees_hors_phase_sont_refusees() {
        let mut session = acceptante();
        assert_eq!(
            session.feed_data(b"peu importe"),
            Err(Error::NotInDataPhase)
        );
    }

    #[test]
    fn un_message_refuse_par_la_grammaire_ne_peut_pas_etre_accepte() {
        // LA PROPRIÉTÉ QUI COMPTE : une boucle distraite ne peut pas remettre un
        // message que le décodeur a rejeté. Le verdict n'est même pas consulté.
        for (contrebande, attendu) in [
            (
                b"corps\r\n\n.\r\nMAIL FROM:<usurpe@x.co>\r\n".as_slice(),
                "554 5.6.0 Bare CR or LF in message data\r\n",
            ),
            (b"a\r.\r\n", "554 5.6.0 Bare CR or LF in message data\r\n"),
        ] {
            let mut session = acceptante();
            jusqu_aux_donnees(&mut session);
            assert_eq!(
                remettre(&mut session, contrebande),
                Err(Error::DataRefused),
                "{contrebande:?}"
            );
            let mut tampon = [0_u8; 128];
            // L'appelant demande l'acceptation ; elle n'est PAS accordée.
            let tour = session
                .on_data_settled(DataOutcome::Accepted, &mut tampon)
                .expect("verdict");
            assert_eq!(
                std::string::String::from_utf8(tour.reply().to_vec()).expect("ASCII"),
                attendu
            );
        }
    }

    #[test]
    fn chaque_faute_de_donnees_a_sa_reponse() {
        let etroite = Config::new(
            b"mail.example.com",
            2,
            8,
            Limits {
                max_text_line_octets: 6,
                ..Limits::DEFAULT
            },
        )
        .expect("configurable");

        for (flux, attendu) in [
            (b"abcdef\r\n.\r\n".as_slice(), "500 5.5.2 Line too long\r\n"),
            (
                b"abcd\r\nabcd\r\n.\r\n",
                "552 5.3.4 Message exceeds maximum size\r\n",
            ),
        ] {
            let mut session = SmtpSession::new(etroite, Verdict(RecipientVerdict::Accept));
            jusqu_aux_donnees(&mut session);
            assert_eq!(
                remettre(&mut session, flux),
                Err(Error::DataRefused),
                "{flux:?}"
            );
            let mut tampon = [0_u8; 128];
            let tour = session
                .on_data_settled(DataOutcome::Accepted, &mut tampon)
                .expect("verdict");
            assert_eq!(
                std::string::String::from_utf8(tour.reply().to_vec()).expect("ASCII"),
                attendu
            );
        }
    }

    #[test]
    fn le_compteur_repart_a_zero_pour_le_message_suivant() {
        // Réutiliser le récepteur ferait refuser le second message pour la
        // taille du premier.
        let mut session = acceptante();
        jusqu_aux_donnees(&mut session);
        remettre(&mut session, b"premier\r\n.\r\n").expect("recevable");
        let mut tampon = [0_u8; 128];
        session
            .on_data_settled(DataOutcome::Accepted, &mut tampon)
            .expect("verdict");

        jouer(&mut session, b"MAIL FROM:<a@b.co>\r\n");
        jouer(&mut session, b"RCPT TO:<c@d.co>\r\n");
        jouer(&mut session, b"DATA\r\n");
        assert_eq!(session.received_octets(), 0);
        assert_eq!(
            remettre(&mut session, b"second\r\n.\r\n").expect("recevable"),
            b"second\r\n"
        );
    }

    #[test]
    fn aucune_commande_n_est_traitee_apres_un_refus_de_donnees() {
        let mut session = acceptante();
        jusqu_aux_donnees(&mut session);
        assert_eq!(remettre(&mut session, b"a\n.\r\n"), Err(Error::DataRefused));
        let mut tampon = [0_u8; 128];
        assert_eq!(
            session.handle(b"NOOP\r\n", &mut tampon),
            Err(Error::NotInCommandPhase)
        );
    }

    #[test]
    fn chaque_verdict_de_message_a_sa_reponse() {
        for (verdict, attendu) in [
            (DataOutcome::Accepted, "250 2.0.0 Message accepted\r\n"),
            (
                DataOutcome::RejectedPermanent,
                "554 5.7.1 Message rejected\r\n",
            ),
            (
                DataOutcome::RejectedTemporary,
                "451 4.3.2 Message not accepted, try again later\r\n",
            ),
        ] {
            let mut session = acceptante();
            identifier(&mut session);
            jouer(&mut session, b"MAIL FROM:<a@b.co>\r\n");
            jouer(&mut session, b"RCPT TO:<c@d.co>\r\n");
            jouer(&mut session, b"DATA\r\n");
            let mut tampon = [0_u8; 128];
            let tour = session
                .on_data_settled(verdict, &mut tampon)
                .expect("verdict");
            assert_eq!(
                std::string::String::from_utf8(tour.reply().to_vec()).expect("ASCII"),
                attendu
            );
        }
    }

    #[test]
    fn un_verdict_rendu_hors_de_sa_phase_est_refuse() {
        // L'appelant ne peut pas conclure ce qui n'a pas commencé.
        let mut session = acceptante();
        let mut tampon = [0_u8; 128];
        assert_eq!(
            session.on_data_settled(DataOutcome::Accepted, &mut tampon),
            Err(Error::NotInCommandPhase)
        );
        assert_eq!(
            session.feed_auth(b"", &mut tampon),
            Err(Error::NotInAuthExchange)
        );
    }

    /// Les destinataires retenus, en clair.
    fn destinataires(session: &SmtpSession<'_, Verdict>) -> std::vec::Vec<std::string::String> {
        session
            .recipients()
            .map(|adresse| std::string::String::from_utf8_lossy(adresse).into_owned())
            .collect()
    }

    #[test]
    fn les_destinataires_acceptes_sont_retenus_sous_forme_complete() {
        let mut session = acceptante();
        identifier(&mut session);
        jouer(&mut session, b"MAIL FROM:<a@b.co>\r\n");
        assert!(destinataires(&session).is_empty());
        jouer(&mut session, b"RCPT TO:<jean@example.com>\r\n");
        jouer(&mut session, b"RCPT TO:<paul@example.org>\r\n");
        assert_eq!(
            destinataires(&session),
            ["jean@example.com", "paul@example.org"]
        );
    }

    #[test]
    fn un_destinataire_refuse_n_est_pas_retenu() {
        let mut session = session(RecipientVerdict::RelayDenied);
        identifier(&mut session);
        jouer(&mut session, b"MAIL FROM:<a@b.co>\r\n");
        assert!(jouer(&mut session, b"RCPT TO:<jean@example.com>\r\n").starts_with("550"));
        assert!(destinataires(&session).is_empty());
    }

    #[test]
    fn le_postmaster_nu_est_resolu_avec_le_domaine_du_serveur() {
        // La RFC 5321 §4.1.1.3 admet `<Postmaster>` sans domaine. Le domaine
        // sous-entendu est celui du serveur, et la session est le seul endroit
        // qui le connaisse : le laisser nu obligerait la remise à deviner.
        let mut session = acceptante();
        identifier(&mut session);
        jouer(&mut session, b"MAIL FROM:<a@b.co>\r\n");
        assert!(jouer(&mut session, b"RCPT TO:<Postmaster>\r\n").starts_with("250"));
        assert_eq!(destinataires(&session), ["postmaster@mail.example.com"]);
    }

    #[test]
    fn cinq_chemins_vident_la_liste_et_aucun_ne_l_oublie() {
        // Celui qui l'oublierait livrerait le message suivant aux destinataires
        // du précédent. Ils passent tous par le même endroit ; ce test le
        // vérifie chemin par chemin plutôt que de faire confiance à la lecture.
        let ouvrir = |session: &mut SmtpSession<'_, Verdict>| {
            jouer(session, b"MAIL FROM:<a@b.co>\r\n");
            jouer(session, b"RCPT TO:<jean@example.com>\r\n");
        };

        // 1. `RSET`
        let mut session = acceptante();
        identifier(&mut session);
        ouvrir(&mut session);
        jouer(&mut session, b"RSET\r\n");
        assert!(destinataires(&session).is_empty(), "RSET");

        // 2. `EHLO` (RFC 5321 §4.1.4)
        ouvrir(&mut session);
        jouer(&mut session, b"EHLO client.example\r\n");
        assert!(destinataires(&session).is_empty(), "EHLO");

        // 3. `HELO`
        ouvrir(&mut session);
        jouer(&mut session, b"HELO client.example\r\n");
        assert!(destinataires(&session).is_empty(), "HELO");

        // 4. la fin d'un message
        ouvrir(&mut session);
        jouer(&mut session, b"DATA\r\n");
        let mut tampon = [0_u8; 128];
        session.feed_data(b"corps\r\n.\r\n").expect("données lues");
        session
            .on_data_settled(DataOutcome::Accepted, &mut tampon)
            .expect("verdict");
        assert!(destinataires(&session).is_empty(), "fin de message");

        // 5. la poignée de main TLS (RFC 3207 §4.2)
        identifier(&mut session);
        ouvrir(&mut session);
        session.on_tls_established();
        assert!(destinataires(&session).is_empty(), "STARTTLS");
    }

    #[test]
    fn la_borne_de_place_repond_452_plutot_que_de_tronquer() {
        // ATTENTION À CE QUE CE TEST MESURE. Avec la configuration ordinaire —
        // deux destinataires au plus — c'est la borne du CONFIG qui répond, et
        // l'arène n'est jamais touchée. Il faut donc une configuration large ET
        // des adresses longues pour atteindre la seconde borne, celle de la
        // place. La première version de ce test se contentait de compter des
        // `452` : elle passait sans avoir jamais rempli l'arène.
        let config = Config::new(b"mail.example.com", 100, 10_485_760, Limits::DEFAULT)
            .expect("configurable");
        let mut session = SmtpSession::new(config, Verdict(RecipientVerdict::Accept));
        jouer(&mut session, b"EHLO client.example\r\n");
        jouer(&mut session, b"MAIL FROM:<a@b.co>\r\n");

        let locale = "a".repeat(60);
        let domaine = [
            "b".repeat(60),
            "c".repeat(60),
            std::string::String::from("example.com"),
        ]
        .join(".");
        let mut acceptes = 0_usize;
        let mut refuses = 0_usize;
        for rang in 0..100 {
            let ligne = std::format!("RCPT TO:<{locale}{rang:03}@{domaine}>\r\n");
            if jouer(&mut session, ligne.as_bytes()).starts_with("452") {
                refuses = refuses.saturating_add(1);
            } else {
                acceptes = acceptes.saturating_add(1);
            }
        }
        assert!(refuses > 0, "la borne de place n'a jamais été atteinte");
        assert!(
            acceptes < 100,
            "c'est la borne de nombre qui a répondu, pas celle de place"
        );
        // Et tout ce qui a été retenu est ENTIER : une adresse tronquée
        // livrerait le message à quelqu'un d'autre.
        assert_eq!(destinataires(&session).len(), acceptes);
        for adresse in destinataires(&session) {
            assert!(adresse.ends_with(&domaine), "{adresse}");
        }
    }

    #[test]
    fn un_chemin_nul_ne_se_retient_pas() {
        // `on_rcpt` ne peut pas le recevoir — la grammaire refuse `<>` en
        // destinataire — mais `retenir` doit tout de même dire non plutôt que
        // d'inventer une adresse. Le test passe par la fonction privée, parce
        // qu'aucun dialogue ne peut l'y amener.
        let mut session = acceptante();
        assert!(!session.retenir(&Path::Null));
        assert!(destinataires(&session).is_empty());
    }

    #[test]
    fn rset_annule_la_transaction_sans_desidentifier() {
        let mut session = acceptante();
        identifier(&mut session);
        jouer(&mut session, b"MAIL FROM:<a@b.co>\r\n");
        assert!(jouer(&mut session, b"RSET\r\n").starts_with("250"));
        // Hors transaction, `RSET` reste licite et ne défait rien.
        assert!(jouer(&mut session, b"RSET\r\n").starts_with("250"));
        // On est toujours identifié : `MAIL` repasse.
        assert!(jouer(&mut session, b"MAIL FROM:<a@b.co>\r\n").starts_with("250"));
    }

    #[test]
    fn quit_ferme_et_la_session_ne_repond_plus() {
        let mut session = acceptante();
        let mut tampon = [0_u8; 128];
        let tour = session.handle(b"QUIT\r\n", &mut tampon).expect("réponse");
        assert_eq!(tour.reply(), b"221 2.0.0 Bye\r\n");
        assert_eq!(tour.action(), Action::Close);
        assert_eq!(
            session.handle(b"NOOP\r\n", &mut tampon),
            Err(Error::SessionClosed)
        );
    }

    // ── Les destinataires ───────────────────────────────────────────────────

    #[test]
    fn chaque_verdict_a_sa_reponse() {
        for (verdict, attendu) in [
            (RecipientVerdict::Accept, "250"),
            (RecipientVerdict::RejectPermanent, "550"),
            (RecipientVerdict::RejectTemporary, "450"),
            (RecipientVerdict::RelayDenied, "550"),
        ] {
            let mut session = session(verdict);
            identifier(&mut session);
            jouer(&mut session, b"MAIL FROM:<a@b.co>\r\n");
            let reponse = jouer(&mut session, b"RCPT TO:<c@d.co>\r\n");
            assert!(
                reponse.starts_with(attendu),
                "{verdict:?} : « {reponse} » n'est pas un {attendu}"
            );
        }
    }

    /// **UN REFUS DE DESTINATAIRE SE SIGNALE, ET N'EST PAS UNE FAUTE.**
    ///
    /// Un expéditeur qui se trompe d'adresse n'est pas un attaquant : `peer_fault`
    /// reste faux, et il doit le rester. Mais une rafale de refus est la signature
    /// d'une récolte d'adresses — le pair cherche à savoir QUI EXISTE —, et la
    /// boucle a besoin des deux signaux pour les compter séparément.
    ///
    /// **UN REFUS TEMPORAIRE N'EN EST PAS UN** : un `450` dit que NOUS ne pouvons
    /// pas, pas que l'adresse n'existe pas. Il n'apprend rien à qui récolte, et le
    /// compter punirait un pair pour nos propres embarras.
    /// **LA SESSION DIT À LA POLITIQUE SI LE PAIR S'EST AUTHENTIFIÉ.**
    ///
    /// C'est la seule chose qui sépare un relais d'un relais ouvert, et la
    /// politique ne peut pas la deviner : elle est PARTAGÉE par toutes les
    /// connexions, et n'a aucun état propre à celle-ci. Le lui faire déduire
    /// d'autre chose serait la façon d'ouvrir un relais sans s'en apercevoir.
    #[test]
    fn la_politique_apprend_si_le_pair_s_est_authentifie() {
        use crate::{Authenticator, Policy};
        use ams_sasl::Credentials;
        use core::cell::Cell;

        /// Retient ce que la session lui a dit, et accepte tout.
        struct Espionne(Cell<Option<bool>>);
        impl Authenticator for Espionne {
            fn authenticate(&self, _credentials: &Credentials<'_>) -> bool {
                true
            }
        }
        impl Policy for Espionne {
            fn accepts_recipient(
                &self,
                _forward_path: &Path<'_>,
                submitter: bool,
            ) -> RecipientVerdict {
                self.0.set(Some(submitter));
                RecipientVerdict::Accept
            }
        }

        let config = Config::new(b"mail.example.com", 10, 10_485_760, Limits::DEFAULT)
            .expect("configurable")
            .with_capabilities(Capabilities {
                starttls: false,
                auth: true,
                dsn: false,
            });
        let espionne = Espionne(Cell::new(None));
        let mut session = SmtpSession::new(config, &espionne);
        let mut tampon = [0_u8; 512];
        session.greeting(&mut tampon).expect("bannière");
        // On force le chiffrement : `AUTH` est refusé sans lui, sans réglage.
        session.on_tls_established();
        let dire = |session: &mut SmtpSession<'_, &Espionne>, ligne: &[u8]| {
            let mut place = [0_u8; 512];
            session.handle(ligne, &mut place).expect("une réponse");
        };
        dire(&mut session, b"EHLO client.example\r\n");
        dire(&mut session, b"MAIL FROM:<a@b.co>\r\n");
        dire(&mut session, b"RCPT TO:<c@d.co>\r\n");
        assert_eq!(espionne.0.get(), Some(false), "avant l'AUTH");

        // `\0jean\0ouvre-toi` en base64.
        dire(&mut session, b"AUTH PLAIN AGplYW4Ab3V2cmUtdG9p\r\n");
        assert!(session.is_authenticated());
        dire(&mut session, b"MAIL FROM:<a@b.co>\r\n");
        dire(&mut session, b"RCPT TO:<c@d.co>\r\n");
        assert_eq!(espionne.0.get(), Some(true), "après l'AUTH");
    }

    // ── Le chemin de retour ─────────────────────────────────────────────────

    /// **CE QUE LE PAIR A ÉCRIT, ET RIEN D'AUTRE.**
    ///
    /// C'est l'adresse à laquelle un rapport de non-remise reviendra. Elle ne se
    /// confond pas avec l'identité que SPF vérifie — celle-là vaut
    /// `postmaster@<HELO>` pour un chemin nul, ce que le pair n'a pas écrit.
    #[test]
    fn le_chemin_de_retour_est_celui_que_le_pair_a_ecrit() {
        let mut session = acceptante();
        identifier(&mut session);
        assert_eq!(session.return_path(), None, "hors transaction");
        jouer(&mut session, b"MAIL FROM:<jean@example.com>\r\n");
        assert_eq!(session.return_path(), Some(&b"jean@example.com"[..]));
    }

    /// **UN CHEMIN NUL NE SE RETIENT PAS**, et un littéral d'adresse non plus.
    ///
    /// `<>` est l'expéditeur des notifications, et §6.1 de RFC 5321 interdit
    /// qu'une notification en engendre une autre : il n'y a personne à qui rendre
    /// compte. `jean@[192.0.2.1]` ne désigne aucune zone.
    #[test]
    fn ni_le_chemin_nul_ni_un_litteral_ne_se_retiennent() {
        for ligne in [
            &b"MAIL FROM:<>\r\n"[..],
            b"MAIL FROM:<jean@[192.0.2.1]>\r\n",
        ] {
            let mut session = acceptante();
            identifier(&mut session);
            jouer(&mut session, ligne);
            // Le message se construit AVANT l'assertion : un argument de
            // `assert!` n'est évalué qu'à l'échec, et C2 compterait sa région
            // découverte à jamais.
            let quoi = std::format!("« {} »", std::string::String::from_utf8_lossy(ligne));
            assert_eq!(session.return_path(), None, "{quoi}");
        }
    }

    /// **IL EST CELUI D'UNE TRANSACTION, PAS D'UNE CONNEXION.**
    ///
    /// Le laisser derrière ferait rendre compte du message suivant à
    /// l'expéditeur du précédent.
    #[test]
    fn le_chemin_de_retour_s_oublie_avec_la_transaction() {
        let mut session = acceptante();
        identifier(&mut session);
        jouer(&mut session, b"MAIL FROM:<jean@example.com>\r\n");
        jouer(&mut session, b"RSET\r\n");
        assert_eq!(session.return_path(), None, "après un RSET");

        jouer(&mut session, b"MAIL FROM:<marie@example.com>\r\n");
        assert_eq!(session.return_path(), Some(&b"marie@example.com"[..]));
        // Et un second `EHLO` remet tout à zéro comme un `RSET`.
        jouer(&mut session, b"EHLO client.example\r\n");
        assert_eq!(session.return_path(), None, "après un second EHLO");
    }

    #[test]
    fn seul_un_refus_definitif_signale_une_recolte() {
        for (verdict, signale) in [
            (RecipientVerdict::Accept, false),
            (RecipientVerdict::RejectPermanent, true),
            (RecipientVerdict::RelayDenied, true),
            (RecipientVerdict::RejectTemporary, false),
        ] {
            let mut session = session(verdict);
            identifier(&mut session);
            jouer(&mut session, b"MAIL FROM:<a@b.co>\r\n");
            let mut tampon = [0_u8; 512];
            let tour = session
                .handle(b"RCPT TO:<c@d.co>\r\n", &mut tampon)
                .expect("une réponse");
            assert_eq!(
                tour.refused_recipient(),
                signale,
                "{verdict:?} : le signal de récolte"
            );
            assert!(
                !tour.peer_fault(),
                "{verdict:?} : un refus n'est JAMAIS une faute du pair"
            );
        }
    }

    /// **CE QUI N'EST PAS UN `RCPT` NE SIGNALE RIEN.**
    ///
    /// Une commande hors séquence est une faute ; une commande ordinaire n'est
    /// rien. Ni l'une ni l'autre n'apprend une adresse à qui récolte.
    #[test]
    fn seul_un_rcpt_peut_signaler_une_recolte() {
        let mut session = session(RecipientVerdict::RejectPermanent);
        let mut tampon = [0_u8; 512];
        for ligne in [&b"EHLO client.example\r\n"[..], b"NOOP\r\n", b"DATA\r\n"] {
            let tour = session.handle(ligne, &mut tampon).expect("une réponse");
            // Le message est construit AVANT l'assertion : un `format!` en
            // argument d'`assert!` n'est évalué qu'à l'échec, et C2 compterait
            // sa région à jamais découverte.
            let quoi = std::format!(
                "« {} » ne refuse aucun destinataire",
                std::string::String::from_utf8_lossy(ligne)
            );
            assert!(!tour.refused_recipient(), "{quoi}");
        }
    }

    #[test]
    fn le_relais_refuse_se_distingue_de_la_boite_absente() {
        // Même code, textes différents : un expéditeur légitime qui se trompe de
        // serveur doit pouvoir le comprendre sans lire les journaux d'en face.
        let mut absente = session(RecipientVerdict::RejectPermanent);
        identifier(&mut absente);
        jouer(&mut absente, b"MAIL FROM:<a@b.co>\r\n");
        let sans_boite = jouer(&mut absente, b"RCPT TO:<c@d.co>\r\n");

        let mut relais = session(RecipientVerdict::RelayDenied);
        identifier(&mut relais);
        jouer(&mut relais, b"MAIL FROM:<a@b.co>\r\n");
        let sans_relais = jouer(&mut relais, b"RCPT TO:<c@d.co>\r\n");

        assert_ne!(sans_boite, sans_relais);
    }

    #[test]
    fn le_nombre_de_destinataires_est_borne() {
        let mut session = acceptante();
        identifier(&mut session);
        jouer(&mut session, b"MAIL FROM:<a@b.co>\r\n");
        assert!(jouer(&mut session, b"RCPT TO:<un@d.co>\r\n").starts_with("250"));
        assert!(jouer(&mut session, b"RCPT TO:<deux@d.co>\r\n").starts_with("250"));
        // La configuration en autorise deux.
        assert!(jouer(&mut session, b"RCPT TO:<trois@d.co>\r\n").starts_with("452"));
    }

    // ── TLS ─────────────────────────────────────────────────────────────────

    #[test]
    fn starttls_exige_ehlo_et_ne_se_repete_pas() {
        let mut session = acceptante();
        assert!(jouer(&mut session, b"STARTTLS\r\n").starts_with("503"));
        identifier(&mut session);
        let mut tampon = [0_u8; 128];
        let tour = session
            .handle(b"STARTTLS\r\n", &mut tampon)
            .expect("réponse");
        assert_eq!(tour.reply(), b"220 2.0.0 Ready to start TLS\r\n");
        assert_eq!(tour.action(), Action::StartTls);

        session.on_tls_established();
        identifier(&mut session);
        assert!(jouer(&mut session, b"STARTTLS\r\n").starts_with("503"));
    }

    #[test]
    fn la_poignee_de_main_remet_toute_la_session_a_zero() {
        // RFC 3207 §4.2. Ce qu'un pair a dit EN CLAIR a pu être dit par quelqu'un
        // d'autre : le conserver après chiffrement authentifierait de la parole
        // non protégée.
        let mut session = acceptante();
        identifier(&mut session);
        jouer(&mut session, b"MAIL FROM:<a@b.co>\r\n");
        assert!(!session.is_encrypted());

        session.on_tls_established();
        assert!(session.is_encrypted());
        assert!(!session.is_authenticated());
        // Ni l'identification ni la transaction n'ont survécu.
        assert!(jouer(&mut session, b"MAIL FROM:<a@b.co>\r\n").starts_with("503"));
    }

    // ── AUTH : le refus emblématique ────────────────────────────────────────

    #[test]
    fn auth_est_refuse_hors_chiffrement_et_ce_n_est_pas_reglable() {
        let mut session = acceptante();
        identifier(&mut session);
        assert_eq!(
            jouer(&mut session, b"AUTH PLAIN\r\n"),
            "538 5.7.1 Encryption required for authentication\r\n"
        );
    }

    /// `\0jean\0ouvre-toi` en base64 : la réponse `PLAIN` qui ouvre.
    const REPONSE_JUSTE: &[u8] = b"AGplYW4Ab3V2cmUtdG9p";

    #[test]
    fn une_reponse_initiale_est_reglee_sans_defi() {
        // RFC 4954 §4 : avec une réponse initiale, le serveur NE DOIT PAS
        // envoyer de `334`. Le défi de trop désynchroniserait la conversation —
        // le client attendrait un verdict, le serveur une réponse.
        let mut session = acceptante();
        session.on_tls_established();
        identifier(&mut session);
        let mut tampon = [0_u8; 128];
        let tour = session
            .handle(b"AUTH PLAIN AGplYW4Ab3V2cmUtdG9p\r\n", &mut tampon)
            .expect("réponse");
        assert_eq!(tour.reply(), b"235 2.7.0 Authentication successful\r\n");
        assert_eq!(tour.action(), Action::Continue);
        assert!(session.is_authenticated());
        // Et l'on ne s'authentifie pas deux fois.
        assert!(jouer(&mut session, b"AUTH PLAIN\r\n").starts_with("503"));
    }

    #[test]
    fn sans_reponse_initiale_le_defi_est_vide_puis_la_reponse_suit() {
        let mut session = acceptante();
        session.on_tls_established();
        identifier(&mut session);
        let mut tampon = [0_u8; 128];
        let tour = session
            .handle(b"AUTH PLAIN\r\n", &mut tampon)
            .expect("réponse");
        // Le défi de `PLAIN` est vide : `334 ` et rien de plus. C'est pourquoi
        // `ams_sasl` n'a pas d'encodeur base64.
        assert_eq!(tour.reply(), b"334 \r\n");
        assert_eq!(tour.action(), Action::ReadAuthResponse);
        // La session n'accepte plus de commande : elle attend une RÉPONSE.
        assert_eq!(
            session.handle(b"NOOP\r\n", &mut tampon),
            Err(Error::NotInCommandPhase)
        );

        let tour = session
            .feed_auth(REPONSE_JUSTE, &mut tampon)
            .expect("verdict");
        assert_eq!(tour.reply(), b"235 2.7.0 Authentication successful\r\n");
        assert!(session.is_authenticated());
    }

    #[test]
    fn un_mot_de_passe_faux_est_refuse_et_compte_comme_une_faute() {
        // `\0jean\0autre` : le compte existe, le mot de passe non.
        let mut session = acceptante();
        session.on_tls_established();
        identifier(&mut session);
        let mut tampon = [0_u8; 128];
        session
            .handle(b"AUTH PLAIN\r\n", &mut tampon)
            .expect("défi");
        let tour = session
            .feed_auth(b"AGplYW4AYXV0cmU=", &mut tampon)
            .expect("verdict");
        // Le refus ne dit PAS ce qui a manqué : la différence entre « utilisateur
        // inconnu » et « mot de passe faux » est un annuaire pour qui la mesure.
        assert_eq!(
            tour.reply(),
            b"535 5.7.1 Authentication credentials invalid\r\n"
        );
        // ET c'est une faute au sens de C8 : mille essais par minute doivent
        // finir par fermer la porte. Une faute de frappe, elle, n'atteint aucun
        // seuil.
        assert!(tour.peer_fault());
        assert!(!session.is_authenticated());
        // La connexion, elle, reste ouverte : c'est au garde d'en décider.
        assert!(jouer(&mut session, b"NOOP\r\n").starts_with("250"));
    }

    #[test]
    fn un_compte_inconnu_obtient_exactement_la_meme_reponse() {
        // `\0paul\0ouvre-toi`. Deux réponses différentes feraient de ce serveur
        // un annuaire de comptes valides, interrogeable sans mot de passe.
        let mut session = acceptante();
        session.on_tls_established();
        identifier(&mut session);
        let mut tampon = [0_u8; 128];
        session
            .handle(b"AUTH PLAIN\r\n", &mut tampon)
            .expect("défi");
        let tour = session
            .feed_auth(b"AHBhdWwAb3V2cmUtdG9p", &mut tampon)
            .expect("verdict");
        assert_eq!(
            tour.reply(),
            b"535 5.7.1 Authentication credentials invalid\r\n"
        );
    }

    #[test]
    fn une_reponse_illisible_est_refusee_comme_une_autre() {
        // Base64 invalide, `PLAIN` mal formé, tampon dépassé : le pair n'apprend
        // pas LEQUEL. Ce qui est illisible n'ouvre pas de session, et n'en dit
        // pas plus.
        for reponse in [
            &b"pas du base64!"[..],
            b"Zm9v",         // lisible, mais pas du `PLAIN`
            b"AGplYW4=",     // un seul séparateur
            b"AABzZWNyZXQ=", // nom de compte vide
        ] {
            let mut session = acceptante();
            session.on_tls_established();
            identifier(&mut session);
            let mut tampon = [0_u8; 128];
            session
                .handle(b"AUTH PLAIN\r\n", &mut tampon)
                .expect("défi");
            let tour = session.feed_auth(reponse, &mut tampon).expect("verdict");
            assert_eq!(
                tour.reply(),
                b"535 5.7.1 Authentication credentials invalid\r\n",
                "{reponse:?}"
            );
            assert!(!session.is_authenticated());
        }
    }

    #[test]
    fn une_reponse_initiale_reduite_a_un_signe_egal_vaut_le_vide() {
        // RFC 4954 §4 : sans cette convention, « rien » et « une chaîne vide »
        // s'écriraient pareil. Le vide n'est pas du `PLAIN`, donc c'est un refus
        // — mais un refus, pas un défi.
        let mut session = acceptante();
        session.on_tls_established();
        identifier(&mut session);
        let mut tampon = [0_u8; 128];
        let tour = session
            .handle(b"AUTH PLAIN =\r\n", &mut tampon)
            .expect("réponse");
        assert_eq!(
            tour.reply(),
            b"535 5.7.1 Authentication credentials invalid\r\n"
        );
        assert_eq!(tour.action(), Action::Continue);
    }

    #[test]
    fn le_pair_peut_annuler_et_ce_n_est_pas_une_faute() {
        // RFC 4954 §4 : `*` annule. Un client dont l'utilisateur ferme la
        // fenêtre fait exactement ce que la RFC prévoit ; le compter au garde
        // punirait la conformité.
        let mut session = acceptante();
        session.on_tls_established();
        identifier(&mut session);
        let mut tampon = [0_u8; 128];
        session
            .handle(b"AUTH PLAIN\r\n", &mut tampon)
            .expect("défi");
        let tour = session.feed_auth(b"*", &mut tampon).expect("annulation");
        assert_eq!(tour.reply(), b"501 5.7.0 Authentication aborted\r\n");
        assert!(!tour.peer_fault());
        assert!(!session.is_authenticated());
        // Et la session reprend là où elle en était.
        assert!(jouer(&mut session, b"NOOP\r\n").starts_with("250"));
    }

    #[test]
    fn un_mecanisme_inconnu_obtient_504_et_non_502() {
        // `502` laisserait croire qu'`AUTH` n'existe pas ici, et un client qui
        // sait faire `PLAIN` renoncerait pour rien.
        let mut session = acceptante();
        session.on_tls_established();
        identifier(&mut session);
        for ligne in [
            &b"AUTH CRAM-MD5\r\n"[..],
            b"AUTH LOGIN\r\n",
            b"AUTH SCRAM-SHA-256\r\n",
        ] {
            assert_eq!(
                jouer(&mut session, ligne),
                "504 5.7.0 Unrecognized authentication type\r\n",
                "{ligne:?}"
            );
        }
        // Un nom en minuscules, lui, n'arrive JAMAIS jusqu'ici : la RFC 4422
        // §3.1 impose des majuscules, et la grammaire le refuse en amont. C'est
        // dit ici pour qu'on sache où vit cette décision.
        assert!(jouer(&mut session, b"AUTH plain\r\n").starts_with("501"));
    }

    #[test]
    fn auth_juste_apres_la_poignee_de_main_exige_un_nouvel_ehlo() {
        let mut session = acceptante();
        session.on_tls_established();
        assert_eq!(
            jouer(&mut session, b"AUTH PLAIN\r\n"),
            "503 5.5.0 Send EHLO first\r\n"
        );
    }

    // ── Les commandes sans effet, et les refus ──────────────────────────────

    #[test]
    fn noop_vrfy_expn_et_help_repondent_sans_rien_reveler() {
        let mut session = acceptante();
        assert_eq!(jouer(&mut session, b"NOOP\r\n"), "250 2.0.0 OK\r\n");
        // `VRFY` ne dit pas si la boîte existe (RFC 5321 §7.3).
        assert_eq!(
            jouer(&mut session, b"VRFY jean\r\n"),
            "252 2.0.0 Cannot verify; message will be attempted\r\n"
        );
        // `EXPN` publierait les membres d'une liste.
        assert_eq!(
            jouer(&mut session, b"EXPN liste\r\n"),
            "502 5.5.4 EXPN not available\r\n"
        );
        assert_eq!(
            jouer(&mut session, b"HELP\r\n"),
            "214 2.0.0 See RFC 5321\r\n"
        );
    }

    #[test]
    fn chaque_famille_d_erreur_d_analyse_a_son_code() {
        let mut session = acceptante();
        let bornes = [
            (
                b"XYZZY\r\n".as_slice(),
                "500 5.5.1 Command not recognised\r\n",
            ),
            (b"TURN\r\n", "502 5.5.4 Command not implemented\r\n"),
            (b"QUIT", "500 5.5.2 Line must end with CRLF\r\n"),
            (
                b"MAIL FROM:<pas-une-boite>\r\n",
                "501 5.5.2 Syntax error in parameters or arguments\r\n",
            ),
        ];
        for (ligne, attendu) in bornes {
            assert_eq!(jouer(&mut session, ligne), attendu, "sur {ligne:?}");
        }

        // La ligne trop longue a sa borne propre.
        let mut longue = std::vec::Vec::from(b"NOOP ".as_slice());
        longue.extend(std::iter::repeat_n(b'a', 600));
        longue.extend_from_slice(b"\r\n");
        assert_eq!(jouer(&mut session, &longue), "500 5.5.2 Line too long\r\n");
    }

    #[test]
    fn aucune_reponse_ne_reprend_ce_que_le_pair_a_envoye() {
        // L'INJECTION DE RÉPONSE DEVIENT INEXPRIMABLE, et pas seulement refusée
        // par l'encodeur : la session ne compose ses réponses qu'avec des textes
        // constants et son propre domaine.
        let mut session = acceptante();
        let sonde = b"MAIL FROM:<zzmarqueurzz@example.invalid>\r\n";
        let reponse = jouer(&mut session, sonde);
        assert!(!reponse.contains("zzmarqueurzz"), "{reponse}");
    }

    // ── Les types ───────────────────────────────────────────────────────────

    #[test]
    fn ce_qui_n_est_pas_declare_n_est_ni_annonce_ni_servi() {
        // UN SERVEUR N'OFFRE QUE CE QUE QUELQU'UN SAIT CONDUIRE. Annoncer
        // `STARTTLS` sans savoir chiffrer ferait attendre un chiffrement qui ne
        // viendrait pas ; annoncer `AUTH` ferait envoyer un mot de passe.
        let nue = Config::new(b"mail.example.com", 2, 1024, Limits::DEFAULT).expect("configurable");
        let mut session = SmtpSession::new(nue, Verdict(RecipientVerdict::Accept));

        let annonce = jouer(&mut session, b"EHLO client.example\r\n");
        assert_eq!(
            annonce,
            "250-mail.example.com\r\n250-SIZE 1024\r\n250-8BITMIME\r\n250-ENHANCEDSTATUSCODES\r\n250-PIPELINING\r\n250 CHUNKING\r\n"
        );
        assert!(!annonce.contains("STARTTLS"));
        assert!(!annonce.contains("AUTH"));

        // Et les commandes correspondantes sont refusées comme non servies.
        assert_eq!(
            jouer(&mut session, b"STARTTLS\r\n"),
            "502 5.5.4 Command not implemented\r\n"
        );
        assert_eq!(
            jouer(&mut session, b"AUTH PLAIN\r\n"),
            "502 5.5.4 Command not implemented\r\n"
        );
    }

    #[test]
    fn la_session_distingue_une_faute_du_pair_d_un_refus_legitime() {
        // C8 compte les « trames invalides ». La boucle ne peut pas le déduire
        // d'un code : `502` sanctionne un verbe retiré — une faute — mais aussi
        // un `EXPN` qu'on décline, qui n'en est pas une.
        let mut session = acceptante();
        let mut tampon = [0_u8; 512];

        for (ligne, attendu) in [
            (b"XYZZY\r\n".as_slice(), true), // verbe inconnu
            (b"TURN\r\n", true),             // verbe retiré
            (b"MAIL FROM:<x>\r\n", true),    // syntaxe d'argument
            (b"RCPT TO:<c@d.co>\r\n", true), // hors séquence
            (b"NOOP\r\n", false),            // rien de fautif
            (b"EXPN liste\r\n", false),      // décliné, pas fautif
            (b"VRFY jean\r\n", false),
            (b"EHLO client.example\r\n", false),
        ] {
            let tour = session.handle(ligne, &mut tampon).expect("réponse");
            assert_eq!(tour.peer_fault(), attendu, "sur {ligne:?}");
        }
    }

    #[test]
    fn un_destinataire_refuse_n_est_pas_une_faute_du_pair() {
        // Un expéditeur qui se trompe d'adresse n'est pas un attaquant. La
        // récolte d'adresses mérite un compteur à soi ; le mêler à celui-ci
        // bannirait des expéditeurs légitimes.
        let mut session = session(RecipientVerdict::RelayDenied);
        let mut tampon = [0_u8; 512];
        identifier(&mut session);
        jouer(&mut session, b"MAIL FROM:<a@b.co>\r\n");
        let tour = session
            .handle(b"RCPT TO:<c@d.co>\r\n", &mut tampon)
            .expect("réponse");
        assert!(tour.reply().starts_with(b"550 "));
        assert!(!tour.peer_fault());
    }

    #[test]
    fn des_donnees_refusees_sont_une_faute_du_pair() {
        let mut session = acceptante();
        jusqu_aux_donnees(&mut session);
        assert_eq!(remettre(&mut session, b"a\n.\r\n"), Err(Error::DataRefused));
        let mut tampon = [0_u8; 128];
        let tour = session
            .on_data_settled(DataOutcome::Accepted, &mut tampon)
            .expect("verdict");
        assert!(tour.peer_fault());

        // Un message accepté, lui, n'a rien de fautif.
        let mut propre = acceptante();
        jusqu_aux_donnees(&mut propre);
        remettre(&mut propre, b"corps\r\n.\r\n").expect("recevable");
        let tour = propre
            .on_data_settled(DataOutcome::Accepted, &mut tampon)
            .expect("verdict");
        assert!(!tour.peer_fault());
    }

    #[test]
    fn les_types_publics_se_copient_et_se_deboguent() {
        let mut session = acceptante();
        let mut tampon = [0_u8; 128];
        let tour = session.handle(b"NOOP\r\n", &mut tampon).expect("réponse");
        let copie = tour;
        assert_eq!(copie, tour);
        assert!(!std::format!("{tour:?}").is_empty());
        assert!(!std::format!("{:?}", tour.action()).is_empty());
        assert_ne!(Action::Continue, Action::Close);
        assert!(!std::format!("{:?}", RecipientVerdict::Accept).is_empty());
        assert_ne!(RecipientVerdict::Accept, RecipientVerdict::RelayDenied);
        assert!(!std::format!("{:?}", DataOutcome::Accepted).is_empty());
        assert_ne!(DataOutcome::Accepted, DataOutcome::RejectedPermanent);
    }

    #[test]
    fn une_reponse_qui_ne_tient_pas_dans_le_tampon_est_une_erreur() {
        let mut session = acceptante();
        let mut minuscule = [0_u8; 4];
        assert_eq!(
            session.handle(b"NOOP\r\n", &mut minuscule),
            Err(tampon_trop_petit(14))
        );
        // Y compris pour l'`EHLO`, qui est multiligne : 22 + 19 + 14 + 25 + 16
        // + 14 + 14. Il ne porte AUCUN code étendu — c'est lui qui les négocie.
        assert_eq!(
            session.handle(b"EHLO client.example\r\n", &mut minuscule),
            Err(tampon_trop_petit(124))
        );
        // Et pour `HELO`, qui ne l'est pas.
        assert_eq!(
            session.handle(b"HELO client.example\r\n", &mut minuscule),
            Err(tampon_trop_petit(22))
        );
        // Et pour un REFUS DE DESTINATAIRE, qui emprunte un autre chemin de
        // composition que les réponses ordinaires — c'est lui qui pose le
        // signal de récolte, et il doit échouer comme les autres plutôt que de
        // rendre un tour tronqué.
        let mut refusante = super::tests::session(RecipientVerdict::RejectPermanent);
        identifier(&mut refusante);
        jouer(&mut refusante, b"MAIL FROM:<a@b.co>\r\n");
        assert_eq!(
            refusante.handle(b"RCPT TO:<c@d.co>\r\n", &mut minuscule),
            Err(tampon_trop_petit(REFUS_PERMANENT))
        );
    }

    // ── SPF : ce que la session demande, et ce qu'elle fait du verdict ──────

    fn session_spf(politique: SenderPolicy) -> SmtpSession<'static, Verdict> {
        let config = Config::new(b"mail.example.com", 2, 10_485_760, Limits::DEFAULT)
            .expect("configurable")
            .with_sender_policy(politique);
        SmtpSession::new(config, Verdict(RecipientVerdict::Accept))
    }

    /// Joue `EHLO` puis `MAIL FROM:`, et rend la session prête à recevoir un
    /// verdict.
    fn jusqu_au_mail(
        session: &mut SmtpSession<'_, Verdict>,
        helo: &[u8],
        mail: &[u8],
    ) -> (std::string::String, Action) {
        let mut tampon = [0_u8; 512];
        let mut ligne = std::vec::Vec::from(b"EHLO ".as_slice());
        ligne.extend_from_slice(helo);
        ligne.extend_from_slice(b"\r\n");
        session.handle(&ligne, &mut tampon).expect("EHLO");
        let mut ligne = std::vec::Vec::from(b"MAIL FROM:".as_slice());
        ligne.extend_from_slice(mail);
        ligne.extend_from_slice(b"\r\n");
        let tour = session.handle(&ligne, &mut tampon).expect("MAIL");
        let reponse = std::string::String::from_utf8(tour.reply().to_vec()).expect("ASCII");
        (reponse, tour.action())
    }

    #[test]
    fn sans_politique_d_expediteur_la_session_ne_demande_rien() {
        // Elle ne réclame que ce que quelqu'un a déclaré savoir faire : demander
        // une résolution DNS à une boucle qui n'en fait pas ferait attendre pour
        // rien.
        let mut session = session_spf(SenderPolicy::Ignore);
        let (reponse, action) =
            jusqu_au_mail(&mut session, b"client.example.net", b"<jean@example.com>");
        assert_eq!(action, Action::Continue);
        assert!(reponse.starts_with("250"), "{reponse}");
        assert!(session.sender_identity().is_none());
        assert!(session.sender_verdict().is_none());
    }

    #[test]
    fn la_session_rend_la_main_sans_repondre() {
        // Le tour ne porte AUCUNE réponse : elle n'a rien à dire tant qu'elle ne
        // sait pas. C'est l'appelant qui résout, puis elle compose.
        let mut session = session_spf(SenderPolicy::Enforce);
        let (reponse, action) =
            jusqu_au_mail(&mut session, b"client.example.net", b"<jean@example.com>");
        assert_eq!(action, Action::CheckSender);
        assert_eq!(reponse, "", "un tour qui diffère ne répond pas");

        let identite = session.sender_identity().expect("identité");
        assert_eq!(identite.domain, b"example.com");
        assert_eq!(identite.sender, b"jean@example.com");
        assert_eq!(identite.helo, b"client.example.net");
    }

    #[test]
    fn un_expediteur_nul_se_verifie_sur_le_helo() {
        // RFC 7208 §2.4. Sans cette règle, un avis de non-remise échapperait
        // entièrement à SPF — et c'est la forme qu'emprunte la rétrodiffusion.
        let mut session = session_spf(SenderPolicy::Enforce);
        let (_, action) = jusqu_au_mail(&mut session, b"client.example.net", b"<>");
        assert_eq!(action, Action::CheckSender);
        let identite = session.sender_identity().expect("identité");
        assert_eq!(identite.domain, b"client.example.net");
        assert_eq!(identite.sender, b"postmaster@client.example.net");
    }

    #[test]
    fn un_litteral_d_adresse_ne_se_verifie_pas() {
        // `jean@[192.0.2.1]` ne désigne aucune zone : SPF n'a rien à y lire, et
        // interroger `[192.0.2.1]` comme un nom serait interroger n'importe quoi.
        let mut session = session_spf(SenderPolicy::Enforce);
        let (reponse, action) =
            jusqu_au_mail(&mut session, b"client.example.net", b"<jean@[192.0.2.1]>");
        assert_eq!(action, Action::Continue);
        assert!(reponse.starts_with("250"), "{reponse}");

        // Et un `HELO` littéral suivi d'un expéditeur nul : il ne reste RIEN à
        // interroger.
        let mut session = session_spf(SenderPolicy::Enforce);
        let (reponse, action) = jusqu_au_mail(&mut session, b"[192.0.2.1]", b"<>");
        assert_eq!(action, Action::Continue);
        assert!(reponse.starts_with("250"), "{reponse}");
    }

    #[test]
    fn un_second_helo_litteral_efface_le_premier() {
        // Un `HELO` remplace le précédent, Y COMPRIS PAR RIEN : garder l'ancien
        // ferait vérifier un nom que le pair a cessé d'annoncer.
        let mut session = session_spf(SenderPolicy::Enforce);
        let mut tampon = [0_u8; 512];
        session
            .handle(b"EHLO client.example.net\r\n", &mut tampon)
            .expect("EHLO");
        session
            .handle(b"EHLO [192.0.2.1]\r\n", &mut tampon)
            .expect("EHLO");
        let tour = session
            .handle(b"MAIL FROM:<>\r\n", &mut tampon)
            .expect("MAIL");
        assert_eq!(tour.action(), Action::Continue);
    }

    #[test]
    fn un_fail_est_refuse_et_la_transaction_abandonnee() {
        let mut session = session_spf(SenderPolicy::Enforce);
        jusqu_au_mail(&mut session, b"client.example.net", b"<jean@example.com>");
        let mut tampon = [0_u8; 512];
        let tour = session
            .sender_checked(SpfVerdict::Fail, &mut tampon)
            .expect("réponse");
        let reponse = std::string::String::from_utf8(tour.reply().to_vec()).expect("ASCII");
        assert!(reponse.starts_with("550 5.7.23"), "{reponse}");
        assert!(
            tour.peer_fault(),
            "un expéditeur usurpé est une faute du pair"
        );
        assert_eq!(session.sender_verdict(), Some(SpfVerdict::Fail));

        // La transaction est abandonnée : le destinataire qui suit n'a plus de
        // `MAIL` devant lui.
        let refus = jouer(&mut session, b"RCPT TO:<marie@example.com>\r\n");
        assert!(refus.starts_with("503"), "{refus}");
        // Et l'identité ne survit pas : elle est celle d'une TRANSACTION.
        assert!(session.sender_identity().is_none());
    }

    #[test]
    fn une_panne_de_resolution_ajourne() {
        // 451, JAMAIS 550 : un message ajourné revient, un message refusé est
        // perdu.
        let mut session = session_spf(SenderPolicy::Enforce);
        jusqu_au_mail(&mut session, b"client.example.net", b"<jean@example.com>");
        let mut tampon = [0_u8; 512];
        let tour = session
            .sender_checked(SpfVerdict::TempError, &mut tampon)
            .expect("réponse");
        let reponse = std::string::String::from_utf8(tour.reply().to_vec()).expect("ASCII");
        assert!(reponse.starts_with("451 4.4.3"), "{reponse}");
        assert!(!tour.peer_fault(), "une panne chez nous n'est pas sa faute");
    }

    /// **UNE SOUMISSION AUTHENTIFIÉE NE SE VÉRIFIE PAS PAR SPF.**
    ///
    /// SPF demande si l'adresse QUI SE CONNECTE a le droit d'écrire pour ce
    /// domaine. Celui qui soumet le fait depuis un portable ou un téléphone,
    /// jamais depuis une machine que sa propre politique nomme : `fail` est donc
    /// le résultat NORMAL d'une soumission légitime.
    ///
    /// La vérifier tout de même apposait `Received-SPF: fail` sur le message —
    /// qui partait AVEC LUI vers le destinataire, lequel lisait un échec que
    /// nous avions écrit à propos de notre propre utilisateur.
    #[test]
    fn un_pair_authentifie_ne_fait_pas_interroger_spf() {
        // **LA MÊME POLITIQUE QUE LES AUTRES ÉPREUVES SPF.** Elle authentifie
        // déjà `jean` ; en écrire une seconde n'apprendrait rien et ferait une
        // instanciation de plus.
        let config = Config::new(b"mail.example.com", 2, 10_485_760, Limits::DEFAULT)
            .expect("configurable")
            .with_sender_policy(SenderPolicy::Enforce)
            .with_capabilities(Capabilities {
                starttls: false,
                auth: true,
                dsn: false,
            });
        let mut session = SmtpSession::new(config, Verdict(RecipientVerdict::Accept));
        let mut tampon = [0_u8; 512];
        session.greeting(&mut tampon).expect("bannière");
        // `AUTH` est refusé sans chiffrement, et sans réglage.
        session.on_tls_established();
        let dire = |session: &mut SmtpSession<'_, Verdict>, ligne: &[u8]| -> Action {
            let mut place = [0_u8; 512];
            session
                .handle(ligne, &mut place)
                .expect("une réponse")
                .action()
        };
        dire(&mut session, b"EHLO portable.example\r\n");

        // **AVANT L'AUTHENTIFICATION**, la session demande la vérification.
        assert_eq!(
            dire(&mut session, b"MAIL FROM:<jean@example.com>\r\n"),
            Action::CheckSender,
            "un pair anonyme se vérifie : c'est tout l'objet de SPF"
        );
        dire(&mut session, b"RSET\r\n");

        // `\0jean\0ouvre-toi` en base64.
        dire(&mut session, b"AUTH PLAIN AGplYW4Ab3V2cmUtdG9p\r\n");
        assert!(session.is_authenticated());

        // **APRÈS**, il n'y a plus rien à demander.
        assert_ne!(
            dire(&mut session, b"MAIL FROM:<jean@example.com>\r\n"),
            Action::CheckSender,
            "un déposant authentifié ne se vérifie pas par SPF"
        );
        // La transaction se joue jusqu'au bout : ce qu'on éprouve est une
        // soumission, et non un `MAIL FROM:` resté en l'air.
        dire(&mut session, b"RCPT TO:<marie@example.com>\r\n");
        assert_eq!(
            session.sender_verdict(),
            None,
            "aucun verdict, donc aucun `Received-SPF` à écrire"
        );
    }
    #[test]
    fn les_autres_verdicts_laissent_passer() {
        // `softfail` dit « probablement pas » et la RFC 7208 §8.5 veut qu'on n'en
        // fasse pas un refus ; `permerror` punirait l'expéditeur pour la faute de
        // son administrateur.
        for verdict in [
            SpfVerdict::Pass,
            SpfVerdict::Neutral,
            SpfVerdict::None,
            SpfVerdict::SoftFail,
            SpfVerdict::PermError,
        ] {
            let mut session = session_spf(SenderPolicy::Enforce);
            jusqu_au_mail(&mut session, b"client.example.net", b"<jean@example.com>");
            let mut tampon = [0_u8; 512];
            let tour = session
                .sender_checked(verdict, &mut tampon)
                .expect("réponse");
            let reponse = std::string::String::from_utf8(tour.reply().to_vec()).expect("ASCII");
            assert!(reponse.starts_with("250"), "{verdict:?} : {reponse}");
            assert_eq!(session.sender_verdict(), Some(verdict));
        }
    }

    #[test]
    fn en_observation_rien_n_est_oppose_mais_tout_est_retenu() {
        let mut session = session_spf(SenderPolicy::Observe);
        let (_, action) = jusqu_au_mail(&mut session, b"client.example.net", b"<jean@example.com>");
        assert_eq!(action, Action::CheckSender);
        let mut tampon = [0_u8; 512];
        let tour = session
            .sender_checked(SpfVerdict::Fail, &mut tampon)
            .expect("réponse");
        let reponse = std::string::String::from_utf8(tour.reply().to_vec()).expect("ASCII");
        assert!(reponse.starts_with("250"), "{reponse}");
        // RETENU : c'est ce qui permet de découvrir ce qu'une politique
        // refuserait avant de la laisser refuser.
        assert_eq!(session.sender_verdict(), Some(SpfVerdict::Fail));
    }

    #[test]
    fn une_identite_plus_longue_qu_un_nom_ne_se_verifie_pas() {
        // Un contenu tronqué désignerait AUTRE CHOSE, et vérifier autre chose ne
        // vérifie rien. Le domaine du serveur est borné à 255 ; celui d'un pair
        // peut aller jusqu'à la borne du décodeur.
        let bornes = Limits {
            max_domain_octets: 512,
            max_path_octets: 1024,
            ..Limits::DEFAULT
        };
        let config = Config::new(b"mail.example.com", 2, 10_485_760, bornes)
            .expect("configurable")
            .with_sender_policy(SenderPolicy::Enforce);
        let mut session = SmtpSession::new(config, Verdict(RecipientVerdict::Accept));
        // Cinq étiquettes de soixante : un domaine grammaticalement valide de
        // 304 octets, plus long que ce qu'un nom peut faire.
        let long = [
            "a".repeat(60),
            "b".repeat(60),
            "c".repeat(60),
            "d".repeat(60),
            "e".repeat(60),
        ]
        .join(".");
        let mut mail = std::vec::Vec::from(b"<jean@".as_slice());
        mail.extend_from_slice(long.as_bytes());
        mail.extend_from_slice(b">");
        let (reponse, action) = jusqu_au_mail(&mut session, b"client.example.net", &mail);
        assert_eq!(action, Action::Continue);
        assert!(reponse.starts_with("250"), "{reponse}");
    }

    #[test]
    fn un_postmaster_nu_n_est_pas_un_expediteur() {
        // La grammaire refuse `<Postmaster>` en `MAIL FROM:` avant d'arriver ici
        // — c'est `RCPT TO:` qui l'admet (RFC 5321 §4.1.1.3). On éprouve donc la
        // fonction elle-même : elle est TOTALE sur son type d'entrée, et rien
        // n'y suppose ce que la grammaire aura filtré.
        let mut session = session_spf(SenderPolicy::Enforce);
        assert!(!session.retenir_l_expediteur(&Path::Postmaster));
        assert!(session.sender_identity().is_none());
    }

    #[test]
    fn le_helo_ne_retient_que_ce_qui_est_un_nom() {
        let mut session = session_spf(SenderPolicy::Enforce);
        session.retenir_le_helo(&ClientId::Domain(b"mx.example.net"));
        assert_eq!(session.helo.as_bytes(), b"mx.example.net");
        session.retenir_le_helo(&ClientId::AddressLiteral(b"[192.0.2.1]"));
        assert!(session.helo.est_vide());
    }

    // ── L'en-tête `Received-SPF` ────────────────────────────────────────────

    fn pair() -> core::net::IpAddr {
        "192.0.2.1".parse().expect("adresse")
    }

    fn trace(session: &SmtpSession<'_, Verdict>) -> Option<std::string::String> {
        let mut tampon = [0_u8; crate::RECEIVED_SPF_MAX];
        session
            .received_spf(pair(), &mut tampon)
            .map(|octets| std::string::String::from_utf8_lossy(octets).replace("\r\n ", " "))
    }

    #[test]
    fn sans_verdict_aucune_trace() {
        // Un en-tête qui dirait `none` sans qu'aucune résolution ait eu lieu
        // mentirait sur ce qu'on a fait.
        let mut session = session_spf(SenderPolicy::Ignore);
        jusqu_au_mail(&mut session, b"client.example.net", b"<jean@example.com>");
        assert!(trace(&session).is_none());
    }

    #[test]
    fn la_trace_porte_le_verdict_et_l_identite() {
        let mut session = session_spf(SenderPolicy::Observe);
        jusqu_au_mail(&mut session, b"client.example.net", b"<jean@example.com>");
        let mut tampon = [0_u8; 512];
        session
            .sender_checked(SpfVerdict::Fail, &mut tampon)
            .expect("réponse");
        let ecrit = trace(&session).expect("trace");
        assert!(ecrit.starts_with("Received-SPF: fail "), "{ecrit}");
        assert!(
            ecrit.contains("envelope-from=\"jean@example.com\""),
            "{ecrit}"
        );
        assert!(ecrit.contains("helo=\"client.example.net\""), "{ecrit}");
        assert!(ecrit.contains("identity=mailfrom"), "{ecrit}");
        assert!(ecrit.contains("receiver=\"mail.example.com\""), "{ecrit}");
        assert!(ecrit.contains("client-ip=192.0.2.1"), "{ecrit}");
    }

    #[test]
    fn une_trace_sur_l_expediteur_nul_nomme_le_helo() {
        // RFC 7208 §2.4 : c'est le `HELO` qui a été vérifié. Ne pas le dire
        // ferait croire que l'adresse de l'enveloppe l'a été.
        let mut session = session_spf(SenderPolicy::Observe);
        jusqu_au_mail(&mut session, b"client.example.net", b"<>");
        let mut tampon = [0_u8; 512];
        session
            .sender_checked(SpfVerdict::Pass, &mut tampon)
            .expect("réponse");
        let ecrit = trace(&session).expect("trace");
        assert!(ecrit.contains("identity=helo"), "{ecrit}");
        assert!(
            ecrit.contains("envelope-from=\"postmaster@client.example.net\""),
            "{ecrit}"
        );
    }

    #[test]
    fn la_trace_ne_survit_pas_a_la_transaction() {
        // Elle appartient au message qu'on est en train de recevoir. La laisser
        // derrière ferait écrire, dans le message suivant, ce qu'on a conclu du
        // précédent.
        let mut session = session_spf(SenderPolicy::Observe);
        jusqu_au_mail(&mut session, b"client.example.net", b"<jean@example.com>");
        let mut tampon = [0_u8; 512];
        session
            .sender_checked(SpfVerdict::Pass, &mut tampon)
            .expect("réponse");
        assert!(trace(&session).is_some());
        jouer(&mut session, b"RSET\r\n");
        assert!(trace(&session).is_none());
    }

    #[test]
    fn un_en_tete_qui_ne_tient_pas_ne_s_ecrit_pas() {
        // La composition refuse ce qui ne tient pas dans une ligne. Le message
        // part alors SANS TRACE plutôt qu'avec une trace douteuse — et surtout
        // pas avec un en-tête coupé, qui se lirait comme un en-tête entier
        // disant autre chose.
        let mut session = session_spf(SenderPolicy::Observe);
        jusqu_au_mail(&mut session, b"client.example.net", b"<jean@example.com>");
        let mut tampon = [0_u8; 512];
        session
            .sender_checked(SpfVerdict::Pass, &mut tampon)
            .expect("réponse");
        let mut minuscule = [0_u8; 8];
        assert!(session.received_spf(pair(), &mut minuscule).is_none());
    }

    #[test]
    fn un_refus_par_politique_ne_dit_pas_la_meme_chose_qu_une_faute() {
        // Le pair n'a rien fait de mal : son message est correct, et la remise
        // aurait réussi. Lui dire « transaction échouée » l'enverrait chercher
        // la faute là où elle n'est pas. RFC 7489 §10.3 veut un `550 5.7.1`.
        let mut session = acceptante();
        identifier(&mut session);
        jouer(&mut session, b"MAIL FROM:<jean@example.com>\r\n");
        jouer(&mut session, b"RCPT TO:<marie@example.com>\r\n");
        jouer(&mut session, b"DATA\r\n");
        session
            .feed_data(b"From: jean@example.com\r\n\r\ncorps\r\n.\r\n")
            .expect("données");

        let mut tampon = [0_u8; 512];
        let tour = session
            .on_data_settled(DataOutcome::RejectedByPolicy, &mut tampon)
            .expect("réponse");
        let reponse = std::string::String::from_utf8(tour.reply().to_vec()).expect("ASCII");
        assert!(reponse.starts_with("550 5.7.1"), "{reponse}");
        assert!(reponse.contains("DMARC"), "{reponse}");
        // Ce n'est PAS une faute du pair : son message était bien formé.
        assert!(!tour.peer_fault(), "{reponse}");
    }

    // ── LE `Return-Path:` DE LA REMISE FINALE (RFC 5321 §4.4) ───────────────

    /// Ce que la session écrirait comme `Return-Path:` après ce `MAIL FROM:`.
    fn chemin_apres(mail_from: &[u8]) -> Option<std::string::String> {
        let mut session = session(RecipientVerdict::Accept);
        identifier(&mut session);
        assert!(
            jouer(&mut session, mail_from).starts_with("250"),
            "{mail_from:?}"
        );
        let mut place = [0_u8; ams_mime::RETURN_PATH_MAX];
        session
            .received_return_path(&mut place)
            .map(|ecrit| std::string::String::from_utf8_lossy(ecrit).into_owned())
    }

    /// **UN LITTÉRAL D'ADRESSE N'EST PAS UN CHEMIN NUL**, et les confondre
    /// ferait taire un répondeur devant un message ordinaire.
    ///
    /// `chemin_de_retour` laisse tomber le littéral — aucun rapport ne pourrait
    /// y revenir — mais le `Return-Path:` ne consigne pas où l'on répondrait, il
    /// consigne CE QUE LE PAIR A DIT. Écrire `<>` reviendrait à annoncer « ceci
    /// est un rapport » (§2 de RFC 3834) sur un message qui n'en est pas un.
    #[test]
    fn un_litteral_d_adresse_ne_devient_pas_un_chemin_nul() {
        assert_eq!(
            chemin_apres(b"MAIL FROM:<jean@[192.0.2.1]>\r\n").as_deref(),
            Some("Return-Path: <jean@[192.0.2.1]>\r\n")
        );
        // Alors que l'adresse de RAPPORT, elle, reste absente : aucun rebond ne
        // pourrait atteindre un littéral.
        let mut session = session(RecipientVerdict::Accept);
        identifier(&mut session);
        assert!(jouer(&mut session, b"MAIL FROM:<jean@[192.0.2.1]>\r\n").starts_with("250"));
        assert_eq!(session.return_path(), None);
    }

    /// **`<>` S'ÉCRIT, ET « RIEN » NE S'ÉCRIT PAS.**
    ///
    /// Les deux laissent le tampon vide ; seul l'un des deux mérite un en-tête.
    #[test]
    fn le_chemin_nul_s_ecrit_mais_pas_l_absence_de_transaction() {
        assert_eq!(
            chemin_apres(b"MAIL FROM:<>\r\n").as_deref(),
            Some("Return-Path: <>\r\n")
        );
        assert_eq!(
            chemin_apres(b"MAIL FROM:<jean@example.com>\r\n").as_deref(),
            Some("Return-Path: <jean@example.com>\r\n")
        );
        // Avant tout `MAIL FROM:`, il n'y a rien à consigner.
        let mut session = session(RecipientVerdict::Accept);
        identifier(&mut session);
        let mut place = [0_u8; ams_mime::RETURN_PATH_MAX];
        assert_eq!(session.received_return_path(&mut place), None);
    }

    /// **UN `RSET` EFFACE LE CHEMIN**, comme le reste de la transaction.
    ///
    /// Le laisser derrière ferait consigner sur le message suivant l'expéditeur
    /// d'enveloppe du précédent.
    #[test]
    fn un_rset_efface_le_chemin_de_retour() {
        let mut session = session(RecipientVerdict::Accept);
        identifier(&mut session);
        assert!(jouer(&mut session, b"MAIL FROM:<jean@example.com>\r\n").starts_with("250"));
        assert!(jouer(&mut session, b"RSET\r\n").starts_with("250"));
        let mut place = [0_u8; ams_mime::RETURN_PATH_MAX];
        assert_eq!(session.received_return_path(&mut place), None);
    }

    /// **LE PLUS LONG CHEMIN QUE LA GRAMMAIRE ACCEPTE TIENT ENCORE.**
    ///
    /// C'est ce qui rend la garde inutile : un tampon trop court laisserait
    /// `depose` vide, donc écrirait `<>` pour une vraie adresse — « ceci est un
    /// rapport » sur un message qui n'en est pas un. La borne est exacte, et cet
    /// essai est ce qui le vérifie plutôt que de le supposer.
    #[test]
    fn le_plus_long_chemin_recevable_tient_encore() {
        // **LA VRAIE BORNE EST CELLE DU CHEMIN ENTIER** : §4.5.3.1.3 le limite à
        // 256 octets, chevrons compris — donc 254 pour `locale@domaine`. Elle
        // est plus serrée que la somme des deux bornes de §4.5.3.1.1 et
        // §4.5.3.1.2, et c'est elle qui décide.
        let locale = std::vec![b'x'; 64];
        let mut domaine = std::vec::Vec::new();
        while domaine.len() + 12 <= 189 {
            domaine.extend_from_slice(b"exemple-abc.");
        }
        domaine.extend(std::iter::repeat_n(b'z', 189 - domaine.len()));
        assert_eq!(locale.len() + 1 + domaine.len(), 254);

        let mut ligne = std::vec::Vec::from(&b"MAIL FROM:<"[..]);
        ligne.extend_from_slice(&locale);
        ligne.push(b'@');
        ligne.extend_from_slice(&domaine);
        ligne.extend_from_slice(b">\r\n");

        let mut session = session(RecipientVerdict::Accept);
        identifier(&mut session);
        let reponse = jouer(&mut session, &ligne);
        assert!(reponse.starts_with("250"), "{reponse}");
        let mut place = [0_u8; ams_mime::RETURN_PATH_MAX];
        let ecrit = session
            .received_return_path(&mut place)
            .expect("un `MAIL FROM:` accepté se consigne");
        assert_ne!(
            ecrit, b"Return-Path: <>",
            "une adresse est devenue un chemin nul"
        );
        assert_eq!(ecrit.len(), 14 + 254 + 3);
        // Et il tient dans la borne annoncée, qui prévoit large.
        assert!(ecrit.len() <= ams_mime::RETURN_PATH_MAX);
    }

    // ── QUI S'EST AUTHENTIFIÉ, ET NON SEULEMENT QUE QUELQU'UN L'A FAIT ──────

    /// **LE BOOLÉEN OUVRE LA PORTE, LE NOM DIT CE QU'ON PEUT AFFIRMER.**
    ///
    /// « Authentifié » suffit à décider si l'on relaie. Il ne suffit pas à
    /// décider au nom de QUI : sans le nom, un compte qui écrit
    /// `From: patron@example.com` obtiendrait notre signature DKIM sur une
    /// adresse qui n'est pas la sienne.
    /// Une session chiffrée et présentée, prête pour un `AUTH`.
    fn session_authentifiable() -> SmtpSession<'static, Verdict> {
        let mut session = session(RecipientVerdict::Accept);
        session.on_tls_established();
        assert!(jouer(&mut session, b"EHLO client.example\r\n").starts_with("250"));
        session
    }

    #[test]
    fn le_compte_authentifie_est_retenu() {
        let mut session = session_authentifiable();
        assert_eq!(session.submitter(), None, "personne ne s'est encore nommé");
        // `AGplYW4Ab3V2cmUtdG9p` est `\0jean\0ouvre-toi`.
        assert!(jouer(&mut session, b"AUTH PLAIN AGplYW4Ab3V2cmUtdG9p\r\n").starts_with("235"));
        assert_eq!(session.submitter(), Some(&b"jean"[..]));
    }

    /// **UN REFUS NE NOMME PERSONNE**, et une authentification manquée ne laisse
    /// pas le nom essayé derrière elle.
    #[test]
    fn une_authentification_refusee_ne_nomme_personne() {
        let mut session = session_authentifiable();
        // Le même nom, un autre mot de passe.
        assert!(jouer(&mut session, b"AUTH PLAIN AGplYW4AZmF1eA==\r\n").starts_with("535"));
        assert_eq!(session.submitter(), None);
    }

    /// **`STARTTLS` REMET TOUT À ZÉRO** (§4.2 de RFC 3207), l'identité comprise.
    ///
    /// Ce qu'un pair a dit en clair a pu être dit par quelqu'un d'autre. Garder
    /// le nom ferait écrire au nom d'un compte qu'on n'a plus vérifié.
    #[test]
    fn le_chiffrement_oublie_l_identite() {
        let mut session = session_authentifiable();
        assert!(jouer(&mut session, b"AUTH PLAIN AGplYW4Ab3V2cmUtdG9p\r\n").starts_with("235"));
        assert_eq!(session.submitter(), Some(&b"jean"[..]));
        // Une seconde montée en chiffrement remet tout à zéro (§4.2 de RFC 3207).
        session.on_tls_established();
        assert_eq!(
            session.submitter(),
            None,
            "l'identité a survécu au chiffrement"
        );
    }
}
