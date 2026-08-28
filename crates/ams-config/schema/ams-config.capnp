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
