@0xa7d4e2b8c1f36092;

# L'INDEX d'une boîte Maildir (C13).
#
# CE FICHIER NE PORTE QUE CE QUE LES NOMS DE FICHIERS NE PORTENT PAS. C'est sa
# règle de conception, et elle explique pourquoi il est si court.
#
# Un index Maildir classique recopie la liste des messages pour éviter un
# parcours de répertoire. Celui-ci ne le fait pas, et le refus est délibéré :
# recopier ce que les noms disent déjà créerait une SECONDE SOURCE DE VÉRITÉ,
# capable de diverger de la première sans que rien ne le signale. L'UID, les
# drapeaux et la taille sont dans les noms — ils y restent.
#
# Ce que les noms ne peuvent pas porter, en revanche :
#
#   - l'UIDVALIDITY, qui appartient à la BOÎTE et non à un message ;
#   - le filigrane des UID, qui doit survivre à l'effacement du message qui
#     portait le plus grand. Sans lui, effacer le dernier message ferait
#     recommencer la numérotation, et un client verrait sous un numéro qu'il
#     croit connaître un message qui n'est pas celui-là.
#
# Perdre ce fichier ne perd donc aucun message et aucun UID : cela oblige
# seulement à changer l'UIDVALIDITY, c'est-à-dire à demander aux clients de
# resynchroniser. C'est ce que « reconstructible » veut dire.
#
# Même règle d'évolution que les autres schémas : on n'enlève JAMAIS un champ, et
# on ne réutilise JAMAIS un numéro.

struct Index {
  # L'UIDVALIDITY (RFC 9051 §2.3.1.1). JAMAIS nulle : la RFC l'interdit, et un
  # zéro serait indistinguable d'un champ absent.
  uidValidity @0 :UInt32;

  # Le filigrane haut des UID : aucun UID déjà servi n'est supérieur ou égal à
  # celui-ci. Ce n'est PAS « le prochain UID » — il est écrit en avance, par
  # tranches, pour ne pas coûter un `fsync` à chaque message. Un arrêt brutal
  # laisse donc des TROUS dans la numérotation, ce que la RFC autorise
  # explicitement. Un trou ne coûte rien ; un UID réattribué coûte cher.
  uidNext @1 :UInt32;
}
