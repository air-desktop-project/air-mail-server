@0xebe3ff6de8432560;

# Les DÉLÉGATIONS d'air-mail-server (phase 3 de la feuille de route).
#
# Une délégation dit qu'un compte — le DÉLÉGUÉ — peut atteindre la boîte d'un
# autre — le TITULAIRE —, et avec quels droits. C'est ce qui permet à trois
# personnes de relever support@ chacune avec ses propres identifiants, au lieu
# de se passer un mot de passe partagé.
#
# ELLE N'ENTRE JAMAIS DANS UN JETON : ce fichier se consulte à CHAQUE requête.
# Retirer une délégation vaut donc immédiatement, sans révoquer aucun jeton.
#
# ELLE NE SE POSE QUE PAR L'ADMINISTRATION : les boîtes partagées n'ont pas de
# titulaire humain pour en décider, et un compte compromis ne doit pas pouvoir
# s'ouvrir d'accès.
#
# Même règle d'évolution que partout : on n'enlève JAMAIS un champ, et on ne
# réutilise JAMAIS un numéro.

struct Delegations {
  delegations @0 :List(Delegation);
}

struct Delegation {
  # Le compte qui reçoit l'accès.
  delegate @0 :Text;

  # Le compte dont la boîte est atteinte.
  owner @1 :Text;

  # Les droits, en bits : 1 LECTURE, 2 ÉCRITURE (drapeaux, déplacer,
  # supprimer), 4 ENVOI (soumettre un message au nom du titulaire). ÉCRITURE et
  # ENVOI IMPLIQUENT LECTURE : écrire dans une boîte qu'on ne peut pas lire, ou
  # répondre à un courrier qu'on n'a pas vu, n'a pas de sens.
  rights @2 :UInt8;
}
