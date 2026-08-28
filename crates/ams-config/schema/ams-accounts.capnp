@0xb3f1a0c9d2e64851;

# Le fichier de COMPTES d'air-mail-server (C11, C12).
#
# POURQUOI UN FICHIER SÉPARÉ de la configuration. Trois raisons, et chacune
# suffirait :
#
#   1. Les deux ne changent pas au même rythme. On ajoute un compte sans
#      toucher aux seuils du garde, et l'inverse aussi.
#   2. Ils ne méritent pas les mêmes permissions. Une configuration se lit ;
#      un fichier d'empreintes ne se lit que par le serveur.
#   3. Une fuite de la configuration n'est pas une fuite des comptes.
#
# CE FICHIER NE CONTIENT AUCUN MOT DE PASSE. Il porte des empreintes Argon2id au
# format PHC, d'où l'on ne remonte pas au mot de passe — c'est l'unique raison
# d'être d'une fonction de dérivation.
#
# Même règle d'évolution que la configuration : on n'enlève JAMAIS un champ, et
# on ne réutilise JAMAIS un numéro.

struct Accounts {
  accounts @0 :List(Account);
}

struct Account {
  # Le nom de compte, tel que le pair l'enverra dans sa réponse SASL.
  login @0 :Text;

  # L'empreinte du mot de passe, au format PHC :
  #
  #   $argon2id$v=19$m=19456,t=2,p=1$<sel base64>$<empreinte base64>
  #
  # Les paramètres sont DANS l'empreinte, et c'est ce qui permet de les faire
  # évoluer sans invalider les comptes existants. C'est aussi pourquoi le
  # serveur refuse au chargement toute empreinte sous son plancher : une
  # vérification emploie les paramètres inscrits ici, pas les siens.
  hash @1 :Text;

  # Les adresses d'enveloppe qui arrivent dans la boîte de ce compte.
  #
  # VIDE EST LICITE : un compte qui se connecte sans rien recevoir est un compte
  # de soumission, et c'est une situation réelle. Ce n'est pas un oubli qu'il
  # faudrait deviner.
  #
  # Une adresse ne peut appartenir qu'à UN compte : deux boîtes pour une adresse
  # est une question sans réponse, et le premier arrivé l'emporterait en silence.
  addresses @2 :List(Text);
}
