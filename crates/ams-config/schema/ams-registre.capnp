@0xb8d8bbc1fd280610;

# Le REGISTRE DE RÉCEPTION (0.2.44) — voir `docs/registre-de-reception.md`.
#
# CE N'EST PAS UN JOURNAL : il se CONSERVE. Il garde, pour chaque session SMTP
# et chaque message, ce que le serveur savait À CET INSTANT — le DNS tel qu'il
# répondait, ce que TLS a négocié, ce que SPF, DKIM et DMARC ont dit — pour
# expliquer après coup un verdict et juger la réputation d'un émetteur.
#
# UN FICHIER PAR JOUR UTC, fait de TRAMES : quatre octets de longueur (petit
# boutien), puis un message Cap'n Proto d'un `Enregistrement`. Le premier est
# un `Entete` qui porte le condensat du fichier précédent ; le dernier, posé à
# minuit, un `Sceau` qui porte celui de tout ce qui le précède. Une archive
# retouchée ou retirée se voit.
#
# RIEN NE SE MODIFIE : une information venue plus tard s'AJOUTE et renvoie à
# ce qu'elle complète.
#
# Même règle d'évolution que partout : on n'enlève JAMAIS un champ, et on ne
# réutilise JAMAIS un numéro. Les textes viennent de l'extérieur : ils sont
# bornés à l'écriture, et une troncature se note.

struct Enregistrement {
  union {
    entete @0 :Entete;
    session @1 :Session;
    transaction @2 :Transaction;
    abandon @3 :Abandon;
    sceau @4 :Sceau;
  }
}

# Le premier enregistrement d'un fichier.
struct Entete {
  # La version du format ; 1 aujourd'hui.
  format @0 :UInt16;
  # Le jour UTC que couvre le fichier, `AAAA-MM-JJ`.
  jour @1 :Text;
  # Le SHA-256 du fichier précédent, en entier — sceau compris. Vide pour le
  # tout premier.
  precedent @2 :Data;
  # Le serveur qui l'a ouvert.
  version @3 :Text;
  # L'heure d'ouverture, en millisecondes depuis l'époque.
  ouvert @4 :UInt64;
}

# Le dernier enregistrement d'un fichier : il le ferme.
struct Sceau {
  # Combien d'enregistrements le précèdent, entête compris.
  enregistrements @0 :UInt64;
  # Le SHA-256 de tous les octets qui le précèdent.
  condensat @1 :Data;
  # L'heure du scellement.
  scelle @2 :UInt64;
  # Un fichier retrouvé coupé au redémarrage a été tronqué à sa dernière trame
  # entière : combien d'octets ont été retirés. Zéro d'ordinaire.
  tronques @3 :UInt64;
}

# Ce que la résolution inverse a répondu.
struct Inverse {
  statut @0 :StatutDns;
  # Les noms que le `PTR` désigne, tels que rendus.
  noms @1 :List(Text);
  # Le plus petit TTL vu, en secondes.
  ttl @2 :UInt32;
  # La réponse portait-elle le bit `AD` d'un résolveur valideur ?
  authentifiee @3 :Bool;
  # Un des noms résout-il vers l'adresse du pair (FCrDNS) ?
  confirmee @4 :Bool;
}

enum StatutDns {
  nonCherche @0;
  trouve @1;
  absent @2;
  panne @3;
}

# Le nom que le pair a annoncé par HELO ou EHLO, et ce qu'il vaut.
struct Salut {
  # Tel qu'écrit, borné.
  nom @0 :Text;
  statut @1 :StatutSalut;
  # Les adresses vers lesquelles il résout.
  adresses @2 :List(Data);
}

enum StatutSalut {
  nonVerifie @0;
  # Un littéral d'adresse, `[192.0.2.1]`.
  litteral @1;
  # Il résout, et vers l'adresse du pair.
  pointeLePair @2;
  # Il résout, mais ailleurs.
  pointeAilleurs @3;
  # Il ne résout pas.
  neResoutPas @4;
  # La résolution a échoué.
  panne @5;
}

struct Tls {
  version @0 :Text;
  suite @1 :Text;
}

enum IssueSession {
  servie @0;
  ralentie @1;
  injection @2;
  interrompue @3;
}

# Une connexion SMTP, même sans message. Écrite à sa fermeture.
struct Session {
  # Seize octets : l'heure d'ouverture en millisecondes, puis un compteur.
  id @0 :Data;
  ouverte @1 :UInt64;
  fermee @2 :UInt64;
  # L'écoute, `adresse:port`.
  ecoute @3 :Text;
  # L'adresse du pair : quatre ou seize octets.
  pair @4 :Data;
  port @5 :UInt16;
  inverse @6 :Inverse;
  salut @7 :Salut;
  # Absent : la connexion ne s'est pas chiffrée.
  tls @8 :Tls;
  commandes @9 :UInt64;
  messages @10 :UInt64;
  authentifiee @11 :Bool;
  # Le mécanisme SASL, s'il y en a eu un.
  mecanisme @12 :Text;
  issue @13 :IssueSession;
  # Ce qui a interrompu la connexion, quand elle l'a été.
  erreur @14 :Text;
  version @15 :Text;
  # Ce que le pair a dit de lui par `XABOUT` (0.2.45) — `air-mail-server
  # version x.y.z` quand c'est un des nôtres. Vide s'il ne s'est pas présenté.
  presentation @16 :Text;
}

enum Resultat {
  none @0;
  pass @1;
  fail @2;
  softFail @3;
  neutral @4;
  tempError @5;
  permError @6;
  # La signature tient, mais une politique locale la récuse (RFC 8601 §2.7.1).
  policy @7;
}

struct Spf {
  resultat @0 :Resultat;
  # Vrai : l'identité vérifiée est le HELO ; faux : le MAIL FROM.
  helo @1 :Bool;
  domaine @2 :Text;
}

struct Dkim {
  resultat @0 :Resultat;
  domaine @1 :Text;
  selecteur @2 :Text;
}

struct Dmarc {
  resultat @0 :Resultat;
  domaine @1 :Text;
  # La politique publiée : `none`, `quarantine`, `reject`.
  politique @2 :Text;
  # Appliquée, et non seulement publiée.
  appliquee @3 :Bool;
  # Mise en quarantaine.
  ecartee @4 :Bool;
}

# Un destinataire, et où le message est allé.
struct Destinataire {
  adresse @0 :Text;
  # Le compte local, vide pour un destinataire relayé.
  compte @1 :Text;
  # La partie UNIQUE du nom Maildir — celle qui ne change jamais, quand les
  # drapeaux et la taille, eux, changent le reste du nom.
  unique @2 :Text;
  # Mis en quarantaine.
  ecarte @3 :Bool;
  # Relayé vers l'extérieur, et non remis ici.
  relaye @4 :Bool;
}

# Les en-têtes utiles, tels que le message les porte. INDICES : rien ne les
# authentifie en soi.
struct EnTetes {
  messageId @0 :Text;
  date @1 :Text;
  from @2 :Text;
  sender @3 :Text;
  replyTo @4 :Text;
  listId @5 :Text;
  listUnsubscribe @6 :Bool;
  arc @7 :Bool;
  # Le SHA-256 de l'objet — jamais l'objet.
  objet @8 :Data;
  # Combien d'adresses dans To et Cc.
  destinatairesVisibles @9 :UInt32;
  # Combien de `Received:` le message portait en arrivant.
  sauts @10 :UInt32;
  # Un en-tête a-t-il été tronqué à l'écriture ?
  tronque @11 :Bool;
}

enum IssueTransaction {
  acceptee @0;
  refuseePolitique @1;
  refuseeDefinitive @2;
  refuseeTemporaire @3;
}

# Un message.
struct Transaction {
  session @0 :Data;
  # Son rang dans la session, à partir de un.
  numero @1 :UInt32;
  recue @2 :UInt64;
  # Une soumission authentifiée, et non du courrier entrant.
  soumission @3 :Bool;
  # Le MAIL FROM ; vide pour un chemin nul.
  mailFrom @4 :Text;
  destinataires @5 :List(Destinataire);
  octets @6 :UInt64;
  entetes @7 :EnTetes;
  spf @8 :Spf;
  dkim @9 :List(Dkim);
  dmarc @10 :Dmarc;
  # L'en-tête `Authentication-Results` écrit dans le message.
  authentification @11 :Text;
  issue @12 :IssueTransaction;
  # La résolution inverse, attendue AVANT d'écrire : chaque message porte le
  # DNS tel qu'il répondait.
  inverse @13 :Inverse;
  salut @14 :Salut;
  pair @15 :Data;
  tls @16 :Tls;
  # Ce que le pair a dit de lui par `XABOUT` (0.2.45).
  presentation @17 :Text;
}

# Une transaction écrite `acceptee`, que la remise n'a finalement pas pu
# conclure : le pair a reçu un refus temporaire.
struct Abandon {
  session @0 :Data;
  numero @1 :UInt32;
  quand @2 :UInt64;
  raison @3 :Text;
}
