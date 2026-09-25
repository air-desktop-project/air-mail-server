@0xd48f2b71c6a39e05;

# Les APPAREILS enrôlés d'air-mail-server (C11, C12).
#
# Un appareil, c'est une clef publique que son propriétaire a enrôlée pour
# ouvrir des sessions sans donner son mot de passe. La clef privée, elle, vit
# dans l'enclave sécurisée du téléphone ou du poste et n'en sort jamais.
#
# POURQUOI UN FICHIER SÉPARÉ des comptes. Trois raisons :
#
#   1. Ils ne changent pas au même rythme. Un utilisateur enrôle et révoque des
#      appareils bien plus souvent qu'il ne change d'adresse.
#   2. Ce fichier ne porte AUCUN SECRET, contrairement à celui des comptes : une
#      clef publique se publie par définition. Ses permissions n'ont donc pas à
#      être les mêmes, et les confondre ferait traiter l'un comme l'autre.
#   3. Perdre ce fichier coûte un réenrôlement ; perdre celui des comptes coûte
#      les comptes. Deux valeurs différentes méritent deux sauvegardes.
#
# CE QU'IL NE CONTIENT JAMAIS, ET C'EST DÉLIBÉRÉ
#
# Aucun identifiant matériel : ni IMEI, ni numéro de série, ni identifiant
# publicitaire. Un serveur de courrier n'a aucune raison de savoir quel
# téléphone vous tenez — il lui suffit de reconnaître une clef. Les retenir en
# ferait un fichier de traçage que personne n'a demandé, et qu'une fuite
# transformerait en annuaire des appareils de ses utilisateurs.
#
# Même règle d'évolution que partout : on n'enlève JAMAIS un champ, et on ne
# réutilise JAMAIS un numéro.

struct Devices {
  devices @0 :List(Device);
}

struct Device {
  # Le compte dont cet appareil ouvre les sessions.
  #
  # Un appareil appartient à UN compte. Un même téléphone qui servirait deux
  # comptes porte deux clefs — et c'est ce qu'on veut : révoquer l'un ne doit
  # pas révoquer l'autre.
  login @0 :Text;

  # Ce qui désigne cet appareil dans une URL et dans un défi.
  #
  # IL EST TIRÉ PAR LE SERVEUR, jamais par le client : un identifiant que
  # l'appelant choisit est un identifiant qu'il peut faire entrer en collision
  # avec celui d'un autre.
  id @1 :Text;

  # Le nom que l'utilisateur lui a donné — « iPhone de Marie », « portable du
  # bureau ».
  #
  # IL NE SERT QU'À L'HUMAIN qui choisit lequel révoquer. Rien ne s'y décide, et
  # il n'a donc à être ni unique, ni stable, ni vérifié — seulement affichable.
  name @2 :Text;

  # La clef publique, en forme non compressée SEC 1 (§2.3.3) : l'octet 0x04,
  # puis x et y sur trente-deux octets chacun. Soixante-cinq octets.
  #
  # ECDSA P-256, et rien d'autre. Ce n'est pas un choix de goût : la Secure
  # Enclave d'Apple ne génère que cette courbe, et une clef qui ne peut pas
  # naître dans l'enclave ne peut pas être protégée par la biométrie.
  publicKey @3 :Data;

  # Quand il a été enrôlé, en secondes depuis l'époque.
  enrolled @4 :UInt64;

  # Quand il a ouvert une session pour la dernière fois, en MILLISECONDES
  # depuis l'époque. Zéro s'il ne l'a jamais fait.
  #
  # ELLE SERT DEUX FOIS. À l'utilisateur, d'abord : « ce portable n'a rien
  # ouvert depuis huit mois » est la seule information qui lui dise lequel
  # révoquer sans risque. Au serveur, ensuite : un défi n'est recevable que
  # s'il a été émis APRÈS cette date, et c'est tout l'usage unique. D'où la
  # milliseconde — en secondes, deux sessions enchaînées dans la même seconde
  # se prenaient pour un rejeu.
  lastSeen @5 :UInt64;
}
