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

  # DKIM (RFC 6376) : de quoi SIGNER ce que ce serveur émet.
  dkim @16 :Dkim;

  # Où écouter en HTTP/2 (RFC 9113), ou une chaîne vide.
  #
  # Vide, l'API REST n'est pas servie. Comme les autres écoutes, cette crate ne
  # l'interprète pas : `core` ne sait pas lire une adresse de socket.
  #
  # SANS CERTIFICAT, CE PORT N'EXISTE PAS DU TOUT — et c'est la différence avec
  # les trois autres. SMTP, POP3 et IMAP montent en TLS par `STARTTLS` et servent
  # en clair sans certificat ; l'API, elle, porte des jetons porteurs, et un jeton
  # qui traverse un réseau en clair est un jeton volé. Le serveur refuse donc
  # d'ouvrir ce port plutôt que de servir sans chiffrement (C4).
  listenHttp @17 :Text;

  # Le secret qui scelle les jetons de l'API, en hexadécimal — trente-deux octets,
  # donc soixante-quatre caractères.
  #
  # VIDE, L'API N'EST PAS SERVIE, même si `listenHttp` est renseigné : sans clé,
  # aucun jeton ne peut être scellé ni vérifié, et le serveur le dit au démarrage
  # plutôt que de laisser le découvrir à la première requête.
  #
  # IL VIT ICI, ET NON DANS LE FICHIER DE COMPTES : ce n'est pas un secret de
  # compte, c'est un secret de serveur. Le changer révoque tous les jetons en
  # cours d'un seul coup — ce qui est parfois exactement ce qu'on veut.
  tokenKey @18 :Text;

  # L'adresse d'écoute de l'API en HTTP/3, sur UDP — vide pour ne pas la servir.
  #
  # # POURQUOI UNE ADRESSE À PART, ET NON LE MÊME PORT QUE `listenHttp`
  #
  # HTTP/3 se découvre par `Alt-Svc` et se sert conventionnellement sur le même
  # numéro de port, en UDP. On pourrait donc l'ouvrir tout seul dès que
  # `listenHttp` l'est — et ce serait ouvrir un port que l'exploitant n'a pas
  # demandé, derrière un pare-feu qu'il n'a pas ouvert. **UN PORT QUI S'OUVRE
  # SANS QU'ON L'AIT DIT EST UNE SURPRISE**, et une surprise sur un port est un
  # incident.
  #
  # Les mêmes conditions que `listenHttp` s'appliquent, et pour les mêmes
  # raisons : sans certificat ni secret de scellement, ce port ne s'ouvre pas.
  # QUIC chiffre toujours (§5 de RFC 9001) — il n'y a donc même pas de mode en
  # clair à refuser.
  listenH3 @19 :Text;

  # La file de réémission sortante — ce que ce serveur émet POUR SES COMPTES.
  #
  # **UN CHAMP AJOUTÉ APRÈS COUP DÉCODE ZÉRO**, et `enabled` à faux est
  # exactement ce qu'une configuration écrite avant lui doit signifier : rien ne
  # sort, comme avant.
  relay @20 :Relay;

  # MTA-STS (RFC 8461) — la politique qu'un domaine publie en HTTPS.
  #
  # **UN CHAMP AJOUTÉ APRÈS COUP DÉCODE DEUX CHAÎNES VIDES**, et deux chaînes
  # vides veulent dire « pas évalué ». Une configuration existante se comporte
  # donc exactement comme avant.
  mtasts @21 :Mtasts;

  # TLSRPT (RFC 8460) — ce qu'on rapporte du chiffrement sortant.
  #
  # **UN CHAMP AJOUTÉ APRÈS COUP DÉCODE UNE CHAÎNE VIDE ET UN FAUX**, et cela
  # veut dire « aucun rapport n'est composé, et rien n'est remis ».
  tlsrpt @22 :Tlsrpt;

  # La file d'attente du serveur — TOUT ce qui sort passe par elle.
  #
  # **UN FICHIER ÉCRIT AVANT CE CHAMP DÉCODE UN DOSSIER VIDE**, et le serveur
  # refuse alors de démarrer dès que quelque chose doit sortir. C'est délibéré :
  # les réglages ont déménagé de `Relay`, et reprendre l'ancienne valeur en
  # silence ferait déposer des rapports dans un répertoire que l'exploitant
  # croyait réservé au courrier.
  queue @23 :Queue;
}

# TLSRPT (RFC 8460) : ce qu'on rend au domaine d'en face.
#
# C'est le seul mécanisme de ce serveur dont le BÉNÉFICIAIRE EST QUELQU'UN
# D'AUTRE : un domaine qui publie une politique MTA-STS en `testing`, ou des
# `TLSA`, n'apprend qu'ainsi que ses remises échouent.
struct Tlsrpt {
  # Le dossier où DÉPOSER les rapports, ou une chaîne vide.
  #
  # VIDE, AUCUN RAPPORT N'EST COMPOSÉ. Pas de drapeau : l'absence de valeur EST
  # l'absence de service, comme le dossier des rapports DMARC.
  directory @0 :Text;

  # Remet-on les rapports, ou se contente-t-on de les déposer ?
  #
  # **FAUX PAR DÉFAUT**, comme `sendReports` de DMARC : émettre du courrier vers
  # des tiers ne se décide pas à la place de celui qui exploite la machine. Sans
  # ce drapeau, les rapports s'accumulent dans le dossier et un opérateur les
  # relève — ce qui lui permet aussi de lire ce qu'il enverrait.
  send @1 :Bool;
}

# MTA-STS (RFC 8461) : ce qu'un domaine exige de qui lui écrit.
#
# **DANE L'EMPORTE** quand un domaine publie les deux (§2). MTA-STS n'est
# consulté que lorsqu'aucun `TLSA` utilisable n'engage.
struct Mtasts {
  # Le fichier PEM des autorités, ou une chaîne vide.
  #
  # VIDE, MTA-STS N'EST PAS ÉVALUÉ. Pas de drapeau : l'absence de valeur EST
  # l'absence de service, comme la liste des suffixes publics pour DMARC.
  #
  # POURQUOI UN FICHIER ET NON DES RACINES EMBARQUÉES. Embarquées, elles
  # vieilliraient avec le binaire et personne ne saurait de quand datent les
  # siennes. Lues dans `/etc/ssl/certs` sans qu'on l'ait dit, ce serait une
  # confiance héritée en silence — ce que ce serveur refuse déjà pour
  # `/etc/resolv.conf`. Nommez celui de votre distribution.
  anchors @0 :Text;

  # Le dossier où les politiques récupérées sont gardées, ou une chaîne vide.
  #
  # EXIGÉ AVEC `anchors` : §5 fait du cache la PROTECTION, pas une
  # optimisation. Un attaquant qui peut bloquer le `https://` obtiendrait, sans
  # cache, une remise sans politique — c'est-à-dire le déclassement que MTA-STS
  # existe pour fermer. Un cache en mémoire seule rouvrirait cette fenêtre à
  # chaque redémarrage.
  #
  # Il est distinct de la file : une politique n'est pas du courrier, et elle ne
  # s'efface pas à la remise.
  cache @1 :Text;
}

# Ce que ce serveur émet pour ses comptes, et comment il insiste.
struct Relay {
  # Relaie-t-on, ou non ?
  #
  # **FAUX PAR DÉFAUT, ET C'EST UNE DÉCISION.** Émettre du courrier vers des
  # tiers ne se décide pas à la place de celui qui exploite la machine — la même
  # règle que pour les rapports DMARC. Sans ce drapeau, un destinataire qui n'est
  # pas d'ici reste refusé par un 550, y compris pour un compte authentifié.
  #
  # C'est aussi ce qui fait qu'une mise à jour ne transforme personne en relais :
  # un fichier écrit avant que ce champ n'existe décode faux.
  enabled @0 :Bool;

  # ── CINQ CHAMPS RETIRÉS, ET QUI NE PEUVENT PAS DISPARAÎTRE ────────────────
  #
  # La file d'attente était celle du RELAIS. Elle est devenue celle du serveur —
  # les rapports DMARC et TLS l'empruntent aussi — et ses réglages ont donc
  # déménagé dans `Queue`, hors de cette structure.
  #
  # Cap'n Proto identifie un champ par son NUMÉRO, jamais par son nom : les
  # retirer décalerait tout ce qui suit, et un fichier ancien se lirait de
  # travers. Ils restent donc ici, sous un nom qui dit ce qu'ils sont, et
  # **rien ne les lit**.
  #
  # Un fichier écrit avant ce déménagement décode donc `Queue.spool` À VIDE, et
  # le serveur REFUSE DE DÉMARRER en le disant : la nouvelle file ne sert plus
  # au seul relais, et laisser l'ancienne valeur en place ferait déposer des
  # rapports dans un répertoire que l'exploitant croyait réservé au courrier.
  spoolRetire @1 :Text;
  retrySecondsRetire @2 :UInt32;
  maxRetrySecondsRetire @3 :UInt32;
  expireSecondsRetire @4 :UInt32;
}

# La file d'attente du serveur — TOUT ce qui sort passe par elle.
#
# # POURQUOI ELLE N'APPARTIENT PLUS AU RELAIS
#
# Il y avait TROIS politiques de reprise dans ce produit : celle-ci, et deux
# écrites à la main pour les rapports DMARC et TLS — qui réessayaient à chaque
# tour de leur intervalle quotidien et s'effaçaient en silence au bout de sept
# jours. Trois politiques, c'est trois vérités qui divergent, et deux d'entre
# elles n'avaient jamais été éprouvées.
#
# Il n'y en a plus qu'une, couverte à 100 % dans `ams-queue` : une attente qui
# DOUBLE jusqu'à un plafond, une péremption, et un rapport de non-remise remis
# localement quand on renonce.
struct Queue {
  # Le dossier de la file, ou une chaîne vide.
  #
  # VIDE ALORS QUE QUELQUE CHOSE SORT — le relais, les rapports DMARC, les
  # rapports TLS —, le serveur refuse de démarrer : accepter un message qu'on
  # n'a nulle part où poser serait le perdre en silence.
  #
  # Il est distinct du Maildir : ce qui attend d'être émis n'est pas du courrier
  # reçu, et les mélanger ferait apparaître dans une boîte ce qui n'y est jamais
  # arrivé.
  spool @0 :Text;

  # L'attente après le PREMIER échec, en secondes.
  #
  # Elle DOUBLE ensuite, jusqu'à `maxRetrySeconds`. Zéro prend le défaut : une
  # attente nulle ferait réessayer aussi vite que le disque tourne.
  retrySeconds @1 :UInt32;

  # Le plafond de l'attente, en secondes. Zéro prend le défaut.
  maxRetrySeconds @2 :UInt32;

  # Le temps accordé à un message depuis son dépôt, en secondes.
  #
  # §4.5.4.1 de RFC 5321 demande au moins quatre à cinq jours avant d'abandonner.
  # Zéro prend le défaut. **Elle vaut pour TOUT ce qui sort** : un rapport n'est
  # pas moins un message qu'un autre, et lui accorder une durée à part
  # redonnerait deux vérités.
  expireSeconds @3 :UInt32;
}

# DKIM : SIGNER, et non vérifier.
#
# La vérification ne se règle pas : elle a lieu sur tout ce qui arrive, parce
# que DMARC en dépend. Signer, en revanche, demande une clé qu'un
# administrateur a publiée dans le DNS — c'est pourquoi cela se configure.
struct Dkim {
  # `s=` — le sélecteur qui nomme la clé dans le DNS, sous
  # `<sélecteur>._domainkey.<domaine>`.
  #
  # VIDE, ON NE SIGNE PAS. Comme partout ici, l'absence de valeur EST l'absence
  # de service : il n'y a pas de drapeau pour la contredire, et donc pas d'état
  # où l'on croirait signer sans le faire.
  selector @0 :Text;

  # Le chemin de la clé privée, en PEM (`PRIVATE KEY` ou `RSA PRIVATE KEY`).
  #
  # Un CHEMIN, et non la clé : recopiée ici, elle hériterait des permissions de
  # ce fichier — la même raison que pour TLS. Le serveur refuse de démarrer si
  # elle est lisible par tout le monde.
  privateKeyPath @1 :Text;
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
  # Les rapports sont DÉPOSÉS ici ; `sendReports` décide s'ils partent. Chaque
  # rapport est accompagné d'un fichier `.destinations` qui dit à qui il revient
  # — après la vérification de §7.1, sans laquelle DMARC serait un amplificateur.
  #
  # Quand ils partent, ils passent par la FILE D'ATTENTE du serveur (`Queue`),
  # comme n'importe quel message : un rapport n'est pas moins un message qu'un
  # autre, et il n'y a qu'une politique de reprise dans ce produit.
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

  # Destinataires refusés DÉFINITIVEMENT, tolérés par minute et par source. Une
  # rafale de refus est la signature d'une récolte d'adresses : le pair ne cherche
  # pas à écrire, il cherche à savoir qui existe.
  #
  # ZÉRO ÉTEINT CE COMPTEUR, et ce n'est pas un oubli : ce champ a été AJOUTÉ, et
  # un fichier écrit avant lui décode zéro. L'inverse aurait banni tout le monde
  # chez tous ceux qui ne réécrivent pas leur configuration. Le serveur annonce au
  # démarrage quand il vaut zéro.
  refusedRecipientsPerMinute @7 :UInt32;
}

# Les délais appartiennent à la boucle : une machine à états qui n'attend jamais
# n'a pas d'horloge à consulter.
struct Timeouts {
  commandSeconds @0 :UInt32;
  dataSeconds @1 :UInt32;
}
