@0xe4a7c81f35d20b96;

# Le magasin des VÉRIFICATEURS SCRAM d'air-mail-server (C11, C12).
#
# POURQUOI UN TROISIÈME FICHIER, alors qu'il y a déjà `comptes.bin`.
#
# Ce n'est pas un rangement : c'est la CONDITION à laquelle SCRAM a été accepté.
# Le 2026-09-06, ce dépôt avait refusé SCRAM-SHA-256, en écrivant ses trois
# conditions de renversement. La troisième disait : « un magasin où le
# vérificateur SCRAM vivrait SÉPARÉMENT, chiffré par une clé que le fichier de
# comptes ne porte pas ».
#
# La raison tient en deux phrases de RFC 5802 §9. Une `ServerKey` permet
# d'usurper le SERVEUR auprès des clients ; une conversation écoutée suffit
# alors à reconstituer `ClientKey`, donc à usurper l'utilisateur. Là où une
# empreinte Argon2id demande d'abord d'être cassée, celle-là s'emploie telle
# quelle. Elle ne peut donc pas vivre à côté des empreintes, ni en clair.
#
# CE QUI EST CHIFFRÉ, ET CE QUI NE L'EST PAS.
#
# Chiffré : les deux clés, sous `ChaCha20-Poly1305`, par une clé de
# trente-deux octets que l'exploitant range ailleurs (`--scram-key`). Ni ce
# fichier ni `comptes.bin` ne la portent.
#
# En clair : le sel et le compte d'itérations. C'est VOULU — le serveur les
# annonce lui-même au client dans le `server-first`, avant toute preuve. Les
# chiffrer n'aurait rien protégé et aurait donné l'illusion contraire.
#
# CE FICHIER SEUL NE DONNE RIEN, et c'est tout ce qu'on en promet. Un serveur
# en marche tient la clé en mémoire : le scellement protège de la fuite d'un
# fichier, pas de la compromission d'une machine.
#
# Même règle d'évolution que les deux autres : on n'enlève JAMAIS un champ, et
# on ne réutilise JAMAIS un numéro.

struct ScramStore {
  verifiers @0 :List(ScramVerifier);
}

struct ScramVerifier {
  # Le compte auquel ce vérificateur appartient — le même nom que dans
  # `comptes.bin`, et soumis aux mêmes contrôles (`check_login`).
  #
  # IL ENTRE AUSSI DANS LES DONNÉES ASSOCIÉES DU SCELLEMENT, et ce n'est pas
  # une redondance : sans cela, qui peut écrire ce fichier sans connaître la clé
  # donnerait à `contact` le vérificateur d'un compte dont il connaît le mot de
  # passe. Déplacer une entrée d'un compte à l'autre ne l'ouvre pas.
  login @0 :Text;

  # Le sel, seize octets, en clair. RFC 5802 §5.1 n'impose pas de taille ; un
  # sel n'est pas un secret, il est UNIQUE.
  salt @1 :Data;

  # Le compte d'itérations de PBKDF2, en clair.
  #
  # RFC 7677 §3.1 exige au moins 4 096 ; ce produit en pose 32 768 aux comptes
  # neufs. Il est INSCRIT ICI plutôt que déduit d'une constante, exactement pour
  # la raison qui fait inscrire les paramètres dans une empreinte PHC : on doit
  # pouvoir le faire évoluer sans invalider les comptes existants. Une
  # vérification emploie le nombre écrit ici, jamais celui du code.
  iterations @2 :UInt32;

  # Le nonce du scellement — douze octets, RFC 8439.
  #
  # IL NE SE RÉEMPLOIE JAMAIS avec la même clé : chaque écriture d'un
  # vérificateur en tire un neuf. Réemployer un nonce en `ChaCha20-Poly1305`
  # révèle le ou-exclusif des deux clairs, et ici les deux clairs sont des clés.
  nonce @3 :Data;

  # `StoredKey ‖ ServerKey`, scellées : soixante-quatre octets et le sceau.
  #
  # Le sceau de Poly1305 est ce qui fait échouer l'ouverture quand la clé est
  # fausse, quand les octets ont bougé, ou quand l'entrée a changé de compte.
  sealed @4 :Data;
}
