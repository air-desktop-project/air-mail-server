@0x9580af564834fd53;

# Le JOURNAL DES CHANGEMENTS d'une boîte (phase 4 de la feuille de route).
#
# Il sert UNE question : « qu'est-ce qui a changé dans cette boîte depuis le
# point N ? ». C'est le MODSEQ de CONDSTORE (RFC 7162) et le VANISHED de
# QRESYNC, rangés pour l'API REST — et réemployables un jour par IMAP.
#
# IL N'EST PAS UNE SOURCE DE VÉRITÉ. Les fichiers le sont : l'UID et les
# drapeaux vivent dans le nom de chacun. Le journal se DÉDUIT en comparant ce
# que le répertoire montre à ce qu'il avait vu la fois précédente — c'est
# pourquoi aucun des chemins qui écrivent dans la boîte n'a à le tenir, et
# pourquoi un changement fait hors du serveur, ou perdu dans un plantage, se
# retrouve à la comparaison suivante.
#
# PERDU, IL SE RECONSTRUIT : un journal neuf part d'un point plus grand que tout
# ce qu'un client a pu voir (l'heure, en millisecondes), et répond « trop
# ancien » à tous les curseurs d'avant. Les clients relisent alors la boîte
# entière — une fois.
#
# Même règle d'évolution que partout : on n'enlève JAMAIS un champ, et on ne
# réutilise JAMAIS un numéro.

struct Journal {
  # L'UIDVALIDITY de la boîte quand le journal a été tenu. S'il change, les UID
  # ne désignent plus les mêmes messages : le journal repart de zéro.
  uidValidity @0 :UInt32;

  # Le dernier point attribué.
  modseq @1 :UInt64;

  # Le plus ancien point encore connu. Un curseur plus ancien ne peut plus être
  # servi — des suppressions d'avant lui ont été oubliées.
  floor @2 :UInt64;

  # Les messages présents, par UID croissant, chacun avec ses drapeaux et le
  # point de son dernier changement.
  messages @3 :List(Present);

  # Les messages disparus, par point croissant — bornés : les plus anciens
  # s'oublient, et le plancher monte d'autant.
  vanished @4 :List(Disparu);
}

struct Present {
  uid @0 :UInt32;
  flags @1 :UInt16;
  modseq @2 :UInt64;
}

struct Disparu {
  uid @0 :UInt32;
  modseq @1 :UInt64;
}
