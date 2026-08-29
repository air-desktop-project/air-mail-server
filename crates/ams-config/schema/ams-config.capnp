@0xd4576288f6eef740;

# Configuration d'air-mail-server (C11).
#
# CE FICHIER EST LA DÉFINITION NORMATIVE de ce qui est configurable. Le fichier
# de configuration en est une instance BINAIRE : pas de TOML, pas de YAML, pas de
# JSON. La conséquence est directe — la configuration n'est pas éditable à la
# main, et c'est ce qui rend `air-mail-admin` obligatoire plutôt que confortable
# (C12).
#
# POURQUOI DU BINAIRE PLUTÔT QUE DU TEXTE. Un format textuel se lit avec un
# analyseur, et un analyseur admet des variantes : espaces, guillemets, ordres,
# encodages. Chaque variante est un endroit où deux lecteurs peuvent diverger.
# Un format à schéma n'en admet aucune : un champ absent est absent, un entier
# est un entier, et il n'y a rien à interpréter.
#
# RÈGLE D'ÉVOLUTION (Cap'n Proto) : on n'enlève JAMAIS un champ et on ne réutilise
# JAMAIS un numéro. Un champ retiré devient obsolète et son numéro reste brûlé —
# sans quoi un ancien fichier serait relu comme s'il disait autre chose.

struct Configuration {
  # Le nom que le serveur annonce. Il franchit la même grammaire qu'un domaine
  # de client : deux validateurs pour une grammaire finissent par diverger.
  domain @0 :Text;

  # Où écouter, sous la forme « adresse:port ». JAMAIS un port privilégié : C10
  # interdit d'exécuter le serveur en superutilisateur, et les ports sous 1024
  # s'atteignent par une règle de redirection du pare-feu.
  listen @1 :Text;

  # La racine de la boîte Maildir.
  maildir @2 :Text;

  # Les domaines pour lesquels du courrier est accepté. VIDE, le serveur
  # n'accepte pour personne : un défaut qui accepterait tout serait un relais
  # ouvert, que C6 exclut.
  hosted @3 :List(Text);

  maxRecipients @4 :UInt32;
  maxMessageOctets @5 :UInt64;
  maxConnections @6 :UInt32;

  limits @7 :Limits;
  guard @8 :Guard;
  timeouts @9 :Timeouts;
  tls @10 :Tls;

  # Le fichier de COMPTES, ou une chaîne vide.
  #
  # Séparé de ce fichier-ci, et pour trois raisons : les deux ne changent pas au
  # même rythme, ils ne méritent pas les mêmes permissions, et une fuite de l'un
  # n'est pas une fuite de l'autre. Voir `ams-accounts.capnp`.
  #
  # VIDE, le serveur n'annonce pas `AUTH` : il n'a personne à qui répondre oui.
  accounts @11 :Text;

  # Où écouter en POP3, ou une chaîne vide.
  #
  # VIDE, POP3 n'est pas servi. Et comme pour SMTP : JAMAIS un port privilégié —
  # C10 interdit d'exécuter le serveur en superutilisateur, et le 110 (ou le 995)
  # s'atteint par une règle de redirection du pare-feu.
  #
  # SANS CERTIFICAT, CE PORT NE SERT PERSONNE : la session POP3 refuse
  # `USER`/`PASS` hors chiffrement, sans réglage possible (C6). Le serveur le dit
  # au démarrage plutôt que de laisser le découvrir.
  listenPop3 @12 :Text;

  spf @13 :Spf;

  dmarc @14 :Dmarc;

  # Où écouter en IMAP (RFC 9051), ou une chaîne vide.
  #
  # Vide, IMAP n'est pas servi. Comme `listen` et `listenPop3`, cette crate ne
  # l'interprète pas : `core` ne sait pas lire une adresse de socket.
  #
  # SANS CERTIFICAT, CE PORT NE SERT PERSONNE : la session IMAP refuse `LOGIN`
  # et `AUTHENTICATE` hors chiffrement, sans réglage possible (C6).
  listenImap @15 :Text;
}

# TLS (C4, C14). Deux CHEMINS, et pas le matériel lui-même : une clé privée
# recopiée dans le fichier de configuration hériterait des permissions de
# celui-ci, et le renouvellement automatique d'un certificat — qui remplace un
# fichier — obligerait à réécrire la configuration entière.
#
# LE CHIFFREMENT EST OFFERT SI ET SEULEMENT SI LES DEUX CHEMINS SONT RENSEIGNÉS.
# Il n'y a pas de drapeau `enabled`, et c'est délibéré : un drapeau créerait deux
# états faux — « activé sans certificat », qui ferait mentir la bannière, et
# « certificat sans activation », qui ne chiffrerait rien en donnant l'inverse à
# lire. Un seul chemin sur deux est refusé au chargement.
struct Tls {
  # La chaîne de certificats, au format PEM.
  certificateChainPath @0 :Text;

  # La clé privée, au format PEM (PKCS#8, SEC1 ou RSA).
  #
  # Le serveur REFUSE DE DÉMARRER si ce fichier est lisible par tout le monde :
  # une clé privée que n'importe quel compte de la machine peut lire n'est plus
  # une clé privée. Le partage par GROUPE, lui, reste permis — c'est la façon
  # dont les certificats se partagent sur un système bien tenu.
  privateKeyPath @1 :Text;
}

# SPF (C9). Comme TLS : PAS DE DRAPEAU. La vérification a lieu si et seulement
# si des résolveurs sont nommés — un drapeau créerait « activé sans résolveur »,
# qui ajournerait tout le courrier, et « résolveurs sans activation », qui
# donnerait à lire le contraire de ce qui se passe.
struct Spf {
  # Les résolveurs à interroger, « adresse:port ». VIDE, SPF N'EST PAS VÉRIFIÉ.
  #
  # ILS DOIVENT ÊTRE DE CONFIANCE. Ce serveur ne valide pas DNSSEC : un `pass`
  # ne vaut que ce que vaut le chemin jusqu'au résolveur. Un résolveur local, ou
  # joint par un lien qu'on maîtrise, est ce que cette absence suppose.
  #
  # Ils sont interrogés DANS L'ORDRE, et le premier qui répond décide : deux
  # résolveurs qui ne disent pas la même chose ne se départagent pas en prenant
  # celui qui plaît.
  resolvers @0 :List(Text);

  # Ce qu'on fait d'un `fail`.
  enforcement @1 :Enforcement;

  # Le temps accordé à UNE question, en millisecondes.
  #
  # Ce n'est pas le temps d'une évaluation : une politique peut en demander dix.
  # Le produit des deux borne ce qu'un domaine hostile peut faire attendre un
  # `MAIL FROM:`, et c'est ce produit-là qu'il faut regarder.
  timeoutMillis @2 :UInt32;

  enum Enforcement {
    # On vérifie, on retient, on n'oppose rien. L'état où l'on découvre ce
    # qu'une politique refuserait AVANT de la laisser refuser.
    observe @0;
    # Un `fail` est refusé (550), une panne de résolution ajournée (451).
    enforce @1;
  }
}

# DMARC (C9). Comme TLS et SPF : PAS DE DRAPEAU. DMARC est évalué si et
# seulement si une liste de suffixes publics est nommée — ET que des résolveurs
# le sont, puisqu'il faut aller chercher la politique.
struct Dmarc {
  # Le fichier de la liste des suffixes publics, ou une chaîne vide.
  #
  # Celui de <https://publicsuffix.org>, tel quel. VIDE, DMARC N'EST PAS ÉVALUÉ.
  #
  # POURQUOI UN FICHIER ET NON UNE LISTE EMBARQUÉE. Elle pèse quelques centaines
  # de kibioctets et change toutes les semaines : embarquée, elle vieillirait
  # avec le binaire, et personne ne saurait de quand date la sienne. L'alignement
  # relâché de DMARC en dépend — s'y tromper fait aligner deux domaines
  # étrangers, ce que DMARC existe précisément pour empêcher.
  publicSuffixList @0 :Text;

  # Ce qu'on fait d'un message que la politique condamne.
  enforcement @1 :Enforcement;

  # Le dossier où DÉPOSER les rapports agrégés (RFC 7489 §7.2), ou une chaîne
  # vide.
  #
  # VIDE, AUCUN RAPPORT N'EST COMPOSÉ. C'est la même règle que partout ailleurs
  # ici : pas de drapeau, l'absence de valeur EST l'absence de service.
  #
  # Les rapports sont déposés, jamais envoyés : envoyer demande un client SMTP
  # sortant que ce serveur n'a pas encore. Chaque rapport est accompagné d'un
  # fichier `.destinations` qui dit à qui il revient — après la vérification de
  # §7.1, sans laquelle DMARC serait un amplificateur.
  reportDirectory @2 :Text;

  # Le nom sous lequel ce receveur se présente dans ses rapports (`<org_name>`).
  #
  # Il devient aussi le premier morceau du nom de fichier (§7.2.1.1), donc il ne
  # peut porter que des lettres, des chiffres, un tiret, un point ou un souligné.
  # Vide, le nom annoncé par le serveur (`domain`) en tient lieu.
  reportOrgName @3 :Text;

  # L'adresse à laquelle nous joindre à propos d'un rapport (`<email>`).
  #
  # Vide, `postmaster@` suivi du nom annoncé en tient lieu.
  reportEmail @4 :Text;

  # Tous les combien vider le journal, en secondes.
  #
  # C'est l'intervalle DU RECEVEUR, et il vaut pour tous les domaines. Le `ri=`
  # que chaque domaine publie est une demande (« au mieux », §7.2) : les honorer
  # un par un demanderait un journal par intervalle, pour une exactitude que
  # personne n'attend. Zéro vaut le défaut de `ri=` : un jour.
  reportIntervalSeconds @5 :UInt32;

  # Remet-on les rapports, ou se contente-t-on de les déposer ?
  #
  # ÉMETTRE DU COURRIER VERS DES TIERS NE SE DÉCIDE PAS À LA PLACE DE CELUI QUI
  # EXPLOITE LA MACHINE. Faux — le défaut — dépose les rapports dans le dossier
  # et n'en envoie aucun ; un opérateur peut les relever lui-même. Vrai les
  # remet, aux destinations qui ont consenti (§7.1) et à elles seules.
  sendReports @6 :Bool;

  # Compose-t-on des rapports d'ÉCHEC (`ruf=`, RFC 6591) ?
  #
  # ILS PORTENT LE COURRIER DE QUELQU'UN. Un rapport agrégé est un
  # dénombrement ; celui-ci dit tout d'un message précis, et il part chez le
  # domaine qu'on rapporte — c'est-à-dire, quand ça compte, chez celui qui
  # usurpe. Ce qu'on y met, on le lui donne.
  #
  # Ce serveur n'y met ni le corps, ni le destinataire, ni les en-têtes de
  # routage : seule une liste blanche d'en-têtes sort. Cela ne rend pas la
  # décision anodine, et c'est pourquoi le défaut est FAUX.
  failureReports @7 :Bool;

  enum Enforcement {
    # On évalue, on retient, on n'oppose rien. L'état où l'on découvre ce qu'une
    # politique refuserait AVANT de la laisser refuser — et il faut y rester
    # quelque temps : un domaine qui publie `p=reject` refuse aussi le courrier
    # de ses propres listes de diffusion.
    observe @0;
    # Un `p=reject` est opposé (550). `p=quarantine` ne l'est pas : ce serveur
    # n'a pas de dossier de quarantaine, et refuser à la place serait faire plus
    # que ce que le domaine a demandé.
    enforce @1;
  }
}

# Les bornes du décodeur (C3). Six des sept viennent de la RFC 5321 §4.5.3.1.
struct Limits {
  maxCommandOctets @0 :UInt32;
  maxLocalPartOctets @1 :UInt32;
  maxDomainOctets @2 :UInt32;
  maxPathOctets @3 :UInt32;
  maxReplyOctets @4 :UInt32;
  maxTextLineOctets @5 :UInt32;
  maxParameters @6 :UInt32;
}

# Le garde anti-flooding (C8). Rien ici n'est une constante : c'est tout l'objet
# de cette contrainte.
struct Guard {
  connectionsPerMinute @0 :UInt32;
  commandsPerMinute @1 :UInt32;

  # Le « x » de C8 : trames invalides tolérées par minute.
  invalidFramesPerMinute @2 :UInt32;
  # Le « y » de C8 : durée du bannissement.
  banSeconds @3 :UInt32;

  # Les longueurs de préfixe sous lesquelles une source est comptée. Bannir une
  # adresse IPv6 SEULE ne sert à rien : le plus petit bloc attribué est un /64,
  # et le pair banni revient à l'adresse suivante.
  ipv4PrefixBits @4 :UInt8;
  ipv6PrefixBits @5 :UInt8;

  # Le nombre de sources suivies en même temps. La mémoire du garde est bornée
  # par construction : une table qui grandit avec le nombre de sources est un
  # épuisement de mémoire offert à qui dispose d'un /64.
  trackedSources @6 :UInt32;
}

# Les délais appartiennent à la boucle : une machine à états qui n'attend jamais
# n'a pas d'horloge à consulter.
struct Timeouts {
  commandSeconds @0 :UInt32;
  dataSeconds @1 :UInt32;
}
