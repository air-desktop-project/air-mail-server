@0xb6337e9419843500;

# Les MOTS DE PASSE APPLICATIFS d'air-mail-server (C11, C12).
#
# Un secret par client de messagerie, et non un par compte : Thunderbird au
# bureau, Apple Mail sur le portable. Chacun est nommé, daté, et se révoque SEUL
# — perdre un poste ne force plus à changer le mot de passe du compte, donc à
# reconfigurer tous les autres clients.
#
# CE QUI EST RANGÉ N'EST PAS LE SECRET, mais son condensat SHA-256. Le secret
# est TIRÉ PAR LE SERVEUR — cent vingt-huit bits du noyau —, et aucun
# dictionnaire ne l'atteint : un hachage lent n'ajouterait rien. Il est montré
# UNE fois, à sa création.
#
# POURQUOI UN FICHIER SÉPARÉ des comptes : il change bien plus souvent, et un
# compte se relit à chaque connexion. Le mêler aux comptes ferait réécrire
# ceux-ci à chaque « dernière utilisation ». Ses permissions sont néanmoins
# celles d'un fichier de SECRETS : un condensat de secret reste à protéger.
#
# Même règle d'évolution que partout : on n'enlève JAMAIS un champ, et on ne
# réutilise JAMAIS un numéro.

struct AppPasswords {
  appPasswords @0 :List(AppPassword);
}

struct AppPassword {
  # Le compte qu'il ouvre.
  login @0 :Text;

  # Son identifiant : les seize chiffres hexadécimaux minuscules que le mot de
  # passe porte lui-même (`amsp-<identifiant>-<secret>`). C'est ce qui permet
  # de trouver l'entrée SANS essayer les autres — donc de ne pas laisser le
  # temps d'un refus dire combien le compte en a.
  id @1 :Text;

  # Le nom que son propriétaire lui a donné. Il ne sert qu'à l'humain qui
  # choisit lequel révoquer.
  name @2 :Text;

  # Quand il a été créé, en secondes depuis l'époque.
  created @3 :UInt64;

  # Quand il a servi pour la dernière fois, en secondes — À L'HEURE PRÈS : on
  # ne réécrit pas le fichier à chaque relève de courrier. Zéro : jamais servi.
  lastUsed @4 :UInt64;

  # Le condensat SHA-256 du mot de passe entier, préfixe compris. Trente-deux
  # octets exactement.
  digest @5 :Data;
}
