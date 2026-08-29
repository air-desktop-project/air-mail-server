# air-mail-server

Serveur de courrier écrit en Rust : **SMTP**, **POP3**, **IMAP** et **HTTP**.

> ## État : trois protocoles servis, HTTP non
>
> Ce dépôt compile, il est linté, et il porte quatre gates de CI. Il sert
> **SMTP**, **POP3** et **IMAP** ; `ams-proto-http` reste un emplacement réservé,
> et son en-tête le dit.
>
> **`air-mail-server` tourne.** Il écoute sur un port, reçoit du courrier en
> clair pour les domaines qu'on lui nomme, le dépose dans une boîte Maildir, et
> refuse les sources qui abusent.
>
> **Il relève** : POP3 sur un second port, `STLS` puis `USER`/`PASS`, la boîte
> verrouillée le temps d'une session, et le `QUIT` qui efface — lui seul.
>
> **Il chiffre** : nommez-lui un certificat et une clé, il annonce `STARTTLS` et
> monte en TLS 1.3, échange de clés post-quantique en tête. Sans certificat, il
> sert en clair — et ne l'annonce pas, faute de quoi il mentirait. Les deux
> moitiés de cette phrase sont éprouvées sur l'exécutable lui-même, face à un
> vrai OpenSSL.
>
> **Il authentifie** : `AUTH PLAIN` sous TLS, contre des empreintes Argon2id
> rangées dans un fichier séparé qu'`air-mail-admin` écrit. Sans comptes, il ne
> l'annonce pas.
>
> **Une boîte par compte** : seules les adresses qu'un compte déclare sont
> acceptées, et chacune mène à `<maildir>/<compte>/`. Sans comptes, le serveur
> n'accepte de courrier pour personne — ce n'est plus un fourre-tout.
>
> **Il ouvre les boîtes** : IMAP sur un troisième port, `STARTTLS` puis `LOGIN`
> ou `AUTHENTICATE PLAIN`, `SELECT`, `LIST`, `STATUS`, `FETCH`, `STORE`,
> `EXPUNGE`, `SEARCH`, `COPY`, `MOVE`, `APPEND`, `CREATE`, `DELETE` et `RENAME` — un message traverse la socket sans jamais tenir en
> mémoire, les drapeaux s'écrivent dans les noms de fichiers Maildir, et un
> effacement n'a jamais lieu sur une marque périmée.
>
> Dix-neuf crates sur vingt portent du code ; `ams-proto-http` est le seul
> emplacement réservé, et il le dit dans sa documentation.
>
> Ce que ce dépôt affirme, il le tient. Rien de plus n'est promis ici.

## Les contraintes

Le projet est gouverné par un **registre de contraintes** :
[`docs/contraintes.md`](docs/contraintes.md). Chaque entrée dit la règle, ce
qu'elle interdit, et — le plus important — **ce qui la fait respecter
aujourd'hui**. Quand la réponse est « rien », c'est écrit.

En résumé, et sans rien promettre : aucune entrée-sortie dans les protocoles *ni
dans le serveur*, 100 % de couverture sur tout ce qui décide, TLS 1.3 sans repli
et **`X25519MLKEM768` toujours offert et préféré**, aucune version ancienne de
protocole, jamais de privilèges superutilisateur, configuration binaire Cap'n
Proto, stockage Maildir, DKIM/SPF/DMARC, et détection de flooding avec
bannissement par source.

La cryptographie est **pure Rust, sans une ligne de C** : `rustls` sur
`rustls-rustcrypto`, et un échange de clés hybride que le projet devra écrire
lui-même — aucun fournisseur pur Rust ne l'offre.

## Le découpage

Trois étages, et la frontière entre le deuxième et le troisième est la seule qui
compte.

### Étage 1 — grammaires, sans entrée-sortie

Des octets vers des commandes, et retour. Aucune socket, aucun fichier, aucune
horloge.

| Crate | Périmètre | État |
| --- | --- | --- |
| `ams-mime` | RFC 5322 et MIME — le socle des quatre protocoles | **squelette du message, domaine d'un `From:`, et composition d'un rapport** |
| `ams-proto-smtp` | RFC 5321 | **commandes, réponses écrites ET lues, phase de données, point-farcissage** |
| `ams-sasl` | RFC 4422/4616 : `PLAIN` et son base64 | **implémenté** |
| `ams-proto-pop3` | RFC 1939 | **commandes et réponses** |
| `ams-dns` | RFC 1035 : le codec d'un message | **question encodée, réponse décodée** |
| `ams-proto-imap` | RFC 9051 (IMAP4rev2) | **découpage, tag, littéraux, arguments, ensembles de séquences, éléments de `FETCH`, drapeaux de `STORE`, critères de `SEARCH`, ligne d'`APPEND`, date-heure, noms de boîtes, réponses** |
| `ams-proto-http` | RFC 9110 / 9112 | vide |

### Étage 2 — décisions, sans entrée-sortie

Des machines à états. Elles reçoivent des octets **et l'heure** ; elles rendent
des octets **et des actions**. Elles n'attendent jamais.

| Crate | Périmètre | État |
| --- | --- | --- |
| `ams-session` | les sessions, serveur ET cliente | **SMTP, POP3 et IMAP en réception, SMTP à l'émission** |
| `ams-guard` | flooding et bannissement par source | **implémenté** |
| `ams-auth` | le magasin d'identifiants, vérification Argon2id | **implémenté** |
| `ams-tls` | TLS 1.3 uniquement, échange de clés post-quantique | **implémenté, en entrant et en sortant** |
| `ams-dkim` | RFC 6376 | **vérifiées, câblées, et posées** |
| `ams-spf` | RFC 7208 | **évalué, câblé, et écrit dans le message** |
| `ams-dmarc` | RFC 7489 | **alignement, politique, et câblé dans la boucle** |
| `ams-config` | les trois formats binaires : configuration, comptes, index | **implémenté** |
| `ams-index` | noms Maildir, drapeaux, reconstruction, `UIDVALIDITY` | **implémenté** |

### Étage 3 — exécution

Les seules crates qui lisent, écrivent et attendent. Elles ne décident de rien.

| Crate | Périmètre | État |
| --- | --- | --- |
| `ams-loop-tokio` | les boucles Unix, sur tokio | **SMTP et POP3** |
| `ams-store` | Maildir : les fichiers, seule source de vérité | **implémenté** |
| `ams-server` | le binaire `air-mail-server` | **il tourne** |
| `ams-admin` | le binaire `air-mail-admin` | **`summary`** |

**Dix-huit crates portent du code.** `ams-mime` : le squelette d'un message — la
ligne, le pliage, la séparation en-tête/corps, le découpage en champs. Les champs
structurés, les adresses, les dates et MIME restent à écrire.
`ams-proto-smtp` : les commandes, l'encodage des réponses multilignes, et **la
phase de données** — `<CRLF>.<CRLF>`, le point échappé, et le refus de tout `CR`
ou `LF` isolé. `BDAT`/`CHUNKING`, l'échappement à l'émission et la validation
complète d'une adresse IPv6 restent à écrire.

`ams-proto-pop3` : les commandes de la RFC 1939 et leurs réponses. `APOP`
n'existe pas ici — MD5, et surtout l'obligation de garder le mot de passe **en
clair** côté serveur pour calculer le condensat : un mécanisme qui interdit de
stocker une empreinte aggrave la fuite qu'il prétend éviter (C6). Le doublement
du point d'une réponse multiligne vit à **un seul endroit** : l'écrire deux fois,
c'est se donner deux occasions de l'écrire différemment, et un point non doublé
termine le message au milieu. La boucle POP3 les emploie.

`ams-sasl` : le mécanisme `PLAIN` et le base64 **strict** qui le transporte —
décodage seul, sans allocation. Strict veut dire : une seule écriture par
valeur. `Zg==` et `Zh==` décodent tous deux vers `f` ; accepter le second
donnerait plusieurs formes pour un même identifiant, de quoi passer à côté d'un
filtre ou d'un comptage. `LOGIN` et `CRAM-MD5` ne sont pas servis, et la crate
dit pourquoi plutôt que de se taire.

`ams-spf` : la lecture d'un enregistrement `v=spf1`, l'expansion des macros
(§7) et l'évaluation d'une politique entière. **La validation a lieu d'un seul
tenant** : un terme fautif en queue fait échouer tout l'enregistrement, parce
qu'un parcours s'arrêtant au premier terme utile appliquerait la moitié d'une
politique — et deux pairs verraient deux politiques différentes pour le même
domaine, selon celui qui correspond en premier.

**L'évaluateur pose des questions ; il n'interroge personne.** `poll` rend soit
un verdict, soit une question — un nom, et ce qu'on veut en savoir — que
l'appelant résout comme il l'entend avant de rendre la réponse par `answer`.
C'est C1, et ce n'est pas seulement une affaire de principe : **la limite des
dix résolutions (§4.6.4) se compte ici**, sur une machine à états qu'on peut
éprouver, plutôt que dans un résolveur où elle se perdrait. Elle existe pour
empêcher qu'un enregistrement hostile fasse travailler le résolveur d'autrui.

Ce qu'on demande n'est pas une requête, c'est une **question** : `MxAddresses`
veut « les adresses des serveurs de courrier de ce domaine », deux tours de DNS
que l'appelant enchaîne. Ce découpage est celui de la RFC, qui compte **un**
mécanisme `mx` comme **une** résolution — et il évite à la crate de retenir une
liste de noms entre deux réponses, donc d'allouer.

La règle la plus contre-intuitive de SPF y est éprouvée nommément : un `include`
correspond **si et seulement si** la politique incluse rend `pass`. Une incluse
qui dit `fail` ne fait pas échouer l'évaluation — elle ne correspond pas, et
c'est le terme suivant de l'appelante qui décide. Un `redirect=`, lui,
**remplace** la politique : son verdict devient le nôtre, qualificateurs
compris.

**Le verdict est écrit dans le message**, en tête, sous la forme d'un en-tête
`Received-SPF` (RFC 7208 §9.1). Sans lui, un message accepté ne porte aucune
trace de ce qu'on a vérifié : ni le lecteur, ni un filtre en aval, ni DMARC ne
peuvent le savoir. Cet en-tête porte deux valeurs **que le pair choisit** — son
expéditeur d'enveloppe et son `HELO` — et il est écrit dans le message qu'on
remet : deux règles le ferment. Tout octet hors de l'ASCII imprimable fait
**refuser l'en-tête entier**, sans échappement de secours ; et les quatre octets
qui ont un sens syntaxique — `"`, `\`, `(`, `)` — sont préfixés d'une
contre-oblique. Le pliage (RFC 5322 §2.2.3) n'est pas cosmétique non plus : la
borne des 998 octets par ligne est **vérifiée à l'écriture**, et un en-tête qui
la dépasserait est refusé plutôt qu'émis — un en-tête coupé en aval se lit comme
un en-tête entier qui dit autre chose.

`ams-dkim` : ce qu'une signature **couvre**, et ce qu'elle **dit** — la
grammaire des listes `tag=valeur` (§3.2), le champ `DKIM-Signature` (§3.5),
l'enregistrement de clé publique (§3.6.1), et **la canonicalisation** (§3.4).
Cette dernière est la définition exacte des octets qu'une signature couvre : une
erreur d'un octet n'y produit aucun symptôme visible, elle rend simplement toutes
les signatures invalides — ou, bien pire, en valide qui ne devraient pas l'être.
Les épreuves sont donc **les vecteurs de la RFC elle-même** (§3.4.5), et pas des
exemples inventés ici.

Le corps se canonicalise **en flux** : c'est ce qu'un pair envoie de plus gros,
et le rassembler lui laisserait choisir combien de mémoire on lui consacre. La
machine ne retient jamais que deux choses, et aucune ne grandit avec le message :
combien de fins de ligne attendent — les lignes vides de la fin s'ignorent, et on
ne sait qu'une ligne était finale qu'en voyant qu'il n'y a plus rien — et qu'un
blanc attend d'être réduit.

Trois refus y sont écrits plutôt que supposés. **`rsa-sha1` est refusé** : RFC
8301 §3.1 l'interdit aux signataires comme aux vérificateurs, et l'accepter
reviendrait à valider ce qu'on sait falsifiable. **Une signature qui ne couvre
pas `from` est refusée** : elle ne dit rien de l'auteur, et c'est pourtant lui
que l'humain lira. **Un `p=` vide est une révocation**, pas un enregistrement
illisible — le détenteur du domaine dit que cette clé ne doit plus rien signer.

**Une signature se vérifie maintenant de bout en bout** : le condensat du corps
(SHA-256 sur le corps canonicalisé, en flux), celui des en-têtes signés, et la
signature elle-même — `rsa-sha256` (RFC 6376) ou `ed25519-sha256` (RFC 8463).

L'ordre des opérations n'est pas indifférent : **le condensat du corps se compare
AVANT la signature**. C'est gratuit — trente-deux octets — là où vérifier une
signature RSA coûte une exponentiation modulaire. Un message dont le corps a
changé est ainsi rejeté sans qu'on ait payé la cryptographie, et un pair qui
envoie mille messages falsifiés ne fait pas travailler la machine pour autant.

Deux bornes sur les clés RSA, et aucune n'est décorative. **Moins de 1024 bits :
refusé** — une telle clé se factorise, la RFC 8301 §3.2 l'interdit aux
signataires, et l'accepter en vérification reviendrait à valider ce qu'on sait
falsifiable. **Plus de 4096 bits : refusé aussi** — elle ne protège personne de
plus, et coûte à *nous* : c'est une zone hostile qui la publierait, pour faire
brûler du calcul à qui lui écrit.

La cryptographie vient de `rsa`, `sha2` et `ed25519-dalek` — **trois crates déjà
présentes dans l'arbre**, tirées par `rustls-rustcrypto`. Les déclarer en direct
n'a ajouté aucun paquet au `Cargo.lock` : trois arêtes, et rien d'autre. C'est
pur Rust (C4), et c'est ce qui a fait pencher la balance contre une bibliothèque
DKIM toute faite.

**La vérification est câblée dans la boucle** : le bloc d'en-tête est retenu
pendant que le corps s'écoule, le condensat se calcule en flux, la clé se
cherche sous `<sélecteur>._domainkey.<domaine>`, et le verdict rejoint le résumé
de la connexion — que le serveur annonce à l'arrêt.

**Le verdict n'arrive qu'après le corps, et cela change tout.** SPF conclut au
`MAIL FROM:`, avant que le message existe ; DKIM signe le corps, donc son verdict
ne peut pas être connu avant le dernier octet. Deux conséquences : le condensat
se calcule morceau par morceau — rassembler le message laisserait un pair choisir
combien de mémoire on lui consacre — et **rien n'est écrit dans le message**. Un
en-tête de résultat se pose en tête, or à ce moment-là le corps n'a pas été lu :
l'écrire demanderait de garder tout le message ou de le récrire, et ces deux
décisions appartiennent à DMARC, qui les portera avec le reste.

**DKIM ne décide de rien tout seul, et ne refuse aucun message.** Une signature
qui échoue ne dit pas qu'un message est faux : une liste de diffusion qui ajoute
un pied de page casse une signature parfaitement honnête. RFC 7489 le pose —
c'est DMARC qui rapproche un `pass` du domaine de l'en-tête `From:`, et lui seul
qui décide.

Deux bornes protègent le vérificateur de qui l'emploierait comme amplificateur :
**le bloc d'en-tête est borné** (au-delà, on renonce à vérifier plutôt que de
laisser un pair choisir la mémoire), et **cinq signatures au plus sont
vérifiées** — chacune coûte une résolution DNS et une exponentiation modulaire,
et un message qui en porterait cent ferait travailler la machine cent fois pour
un seul envoi. On ne vérifie pas non plus ce qu'on refuse.

**La signature à l'émission est là aussi** : `Signer` compose le champ
`DKIM-Signature`, le relit, condense ce qu'il vient d'écrire et le signe — en
`rsa-sha256` ou `ed25519-sha256`.

Signer, c'est écrire exactement ce que le vérificateur relira. Un signataire et
un vérificateur qui divergent d'un octet ne se le disent jamais : les signatures
échouent, et personne ne sait pourquoi. Le signataire **ne compose donc pas son
propre condensat** — il écrit le champ, le relit avec le même analyseur, et le
donne à condenser au même code que la vérification. Cette relecture n'est pas une
politesse : c'est le seul endroit où l'on vérifie que ce qu'on vient d'écrire est
ce qu'on croit avoir écrit, et c'est elle qui refuse une signature qui ne
couvrirait pas `from`.

Deux choses ne s'écrivent pas. **`l=`** : la borne de corps laisse ajouter ce
qu'on veut après les `n` premiers octets sans invalider la signature (§8.2) — la
crate sait la lire, elle n'en écrit pas. **L'heure** : `t=` et `x=` viennent de
l'appelant, parce que cette crate n'a pas d'horloge (C1).

**Rien n'appelle encore le signataire, et c'est normal** : ce serveur reçoit du
courrier, il n'en émet pas. Le relais est refusé explicitement, et une signature
n'a de sens qu'à l'émission. Le signataire attend donc le chemin de soumission —
et C9, qui demande « DKIM en signature ET en vérification », est tenue des deux
côtés le jour où ce chemin existera.

`ams-dmarc` : ce que SPF et DKIM ne disent pas. SPF autorise un domaine
d'**enveloppe** ; DKIM en fait signer un autre. **Ni l'un ni l'autre ne parle du
`From:`** — la seule ligne que l'humain lira. Un message peut donc passer les
deux sans que rien ne dise quoi que ce soit de son auteur affiché : il suffit
d'émettre depuis un domaine qu'on détient, de le signer, et d'écrire ce qu'on
veut dans le `From:`. C'est l'usurpation la plus ordinaire, et c'est celle que
DMARC ferme.

**Un seul mécanisme suffit** (§6.6.2) : SPF ou DKIM, pourvu qu'il réussisse ET
s'aligne. C'est ce qui laisse un message survivre à une redirection — qui casse
SPF mais laisse la signature — ou à une liste de diffusion, qui casse la
signature mais réémet depuis un domaine qu'elle contrôle.

**Le domaine organisationnel ne se devine pas.** L'alignement relâché compare
`mail.example.com` et `example.com` par leur domaine organisationnel — et il
n'existe aucune règle syntaxique pour le trouver : `example.co.uk` en est un,
`co.uk` n'en est pas un. Il faut la liste des suffixes publics, une donnée qui
change et qui vit hors du code. Cette crate ne la devine donc pas : **elle la
demande**, par un trait. Une implémentation naïve — « les deux dernières
étiquettes » — ferait aligner `attaquant.co.uk` avec `victime.co.uk`,
c'est-à-dire exactement l'usurpation que DMARC existe pour empêcher ; c'est
pourquoi la crate n'en fournit aucune, et pourquoi une épreuve porte ce nom-là.

Elle ne tire pas au sort non plus : `pct=` échantillonne l'application d'une
politique, et choisir demande de l'aléa — que C1 laisse à l'étage 3. Le verdict
rend le pourcentage ; l'appelant tire, **et il tire uniformément** : un octet
modulo cent biaiserait le tirage, puisque 256 ne se divise pas par 100, et un
domaine qui demande `pct=10` a le droit d'obtenir dix pour cent, pas onze.

**DMARC est câblé dans la boucle, et c'est le seul endroit du serveur où un
message est refusé pour ce qu'il PRÉTEND être.** SPF refuse une enveloppe, le
garde refuse un débit, la session refuse une syntaxe ; DMARC refuse un `From:`
qui ne correspond à rien de ce qui a été authentifié — et seulement si le
domaine de ce `From:` le demande. La réponse le dit : `550 5.7.1 Message
rejected: sender domain policy (DMARC)`, et non le `554` générique — le pair n'a
rien à corriger chez lui, et l'envoyer chercher la faute au mauvais endroit ne
sert personne.

**La liste des suffixes publics est un fichier**, nommé dans la configuration.
Elle n'est pas embarquée : elle pèse quelques centaines de kibioctets, change
toutes les semaines, et l'alignement relâché en dépend. Embarquée, elle
vieillirait avec le binaire sans que personne ne sache de quand date la sienne.
Sans elle, DMARC n'est pas évalué — et le serveur le dit au démarrage.

**Les rapports agrégés (§7.2) sont composés, nommés, compressés et déposés.**
Sans eux, un domaine durcit sa politique à l'aveugle : il découvre ses
prestataires oubliés en même temps que ses correspondants découvrent que son
courrier ne passe plus. Un rapport est un dénombrement, jamais une copie — deux
messages qui se ressemblent ne font qu'une ligne, et rien n'y désigne un message
en particulier. **On y rapporte ce qu'on a FAIT**, jamais ce qui était demandé :
un message que `p=quarantine` visait et que ce serveur a remis se rapporte
`none`, parce que c'est la vérité.

**Ils sont déposés, puis remis** — et les deux gestes sont séparés par un
dossier. Ce n'est pas une commodité : c'est ce qui fait qu'un rapport composé
survit à un redémarrage, à une panne de réseau, à un serveur d'en face qui ne
répond pas ce jour-là. Ce qui est remis est retiré ; ce qu'un domaine refuse
définitivement l'est aussi, parce qu'insister remplirait le dossier de messages
que personne ne veut ; ce qui n'a pas abouti reste, et repart plus tard ; et un
rapport de plus de sept jours s'efface, parce que le compte d'une journée qu'on
remettrait un mois après n'apprend plus rien à personne.

**Remettre ne se décide pas à la place de celui qui exploite la machine.** Sans
`--dmarc-send`, les rapports s'accumulent dans le dossier et un opérateur les
relève ; avec, ils partent. Émettre du courrier vers des tiers en son nom est
une décision, et elle se prend une fois, explicitement.

Chaque rapport est accompagné d'un fichier `.destinations`, et ce fichier est le
résultat d'un contrôle sans lequel DMARC serait une arme.

## Les rapports d'échec, et pourquoi ils demandent des précautions

`ruf=` est servi (RFC 6591). **Un rapport agrégé est un dénombrement ; un rapport
d'échec porte le courrier de quelqu'un.** Il dit tout d'un message précis, et il
part chez le domaine qu'on rapporte — c'est-à-dire, quand cela compte, chez celui
qui usurpe. Ce qu'on y met, on le lui donne.

**On ne recopie pas le corps** : la pièce jointe est un `text/rfc822-headers`, pas
un `message/rfc822`. Le corps est ce qu'une personne a écrit ; il n'apprend rien
sur une authentification.

**On ne recopie même pas tous les en-têtes.** `EXPOSES` est une liste BLANCHE :
ce qui reste sert à comprendre un échec — ce que le message prétendait être, les
traces de ce qu'on a vérifié — ce qui tombe parle de tiers (`To`, `Cc`) ou de nos
machines (chaque `Received` décrit un chemin interne). Une liste noire aurait été
plus douce et se serait trompée : le jour où un en-tête nouveau porte une donnée
personnelle, une liste noire le laisse passer. Le `Original-Rcpt-To` de la
RFC 6591 n'est pas écrit non plus.

**Sans plafond, une usurpation en masse deviendrait un déluge** : un rapport part
par message, et cent mille usurpations feraient cent mille messages vers un
domaine qui n'a rien demandé. Cent par période et par domaine.

`fo=` dit quand un rapport est dû, et son défaut est le plus étroit. Le défaut de
ce serveur, lui, n'en compose aucun : `--dmarc-failure-reports` le demande.

**SANS LA VÉRIFICATION DE §7.1, DMARC EST UN AMPLIFICATEUR.** N'importe qui peut
publier `rua=mailto:victime@banque.test` sous un domaine qu'il détient, puis
émettre en masse en son nom : tous les receveurs du monde composeraient alors un
rapport et l'enverraient à la victime. La parade : quand la destination n'est pas
dans le domaine qui l'a demandée, **c'est à la destination de consentir**, en
publiant `<demandeur>._report._dmarc.<sa-zone>` — un nom que l'attaquant ne peut
pas écrire, puisqu'il est chez la victime. Une panne de résolution ne vaut pas un
consentement.

## IMAP : découper une commande avant de la comprendre

**IMAP n'est pas un protocole de lignes**, et c'est ce qui le rend délicat. SMTP
et POP3 se lisent ligne par ligne : un `CRLF`, une commande. IMAP non — une
commande peut porter un **littéral**, `{42}` suivi d'un `CRLF` puis de
quarante-deux octets bruts qui peuvent contenir tout ce qu'on veut, `CRLF`
compris, et la commande continue après :

```text
a001 LOGIN {5}
toto
 MOTDEPASSE
```

Chercher le premier `CRLF` pour découper cela, c'est offrir à un client de faire
lire n'importe quoi comme une commande. Ce découpage-là est donc la première
chose écrite, avant tout vocabulaire : un serveur IMAP qui découpe mal est un
serveur qu'on fait lire ce qu'on veut, **avant toute authentification**.

**Deux formes de littéral, et une seule est sûre par construction.** `{42}` est
synchronisant : le client attend un `+` du serveur, qui peut donc refuser avant
de rien lire. `{42+}` (RFC 7888) ne l'est pas — les octets suivent
immédiatement, et le serveur n'a aucun moyen de dire non. C'est pourquoi la
RFC 9051 §6.3.11 les borne à quatre kibioctets, et pourquoi cette borne-là n'est
pas la nôtre à choisir. `{4294967295}` est une ligne de treize octets qui demande
quatre gibioctets ; elle est refusée avant que rien ne soit lu.

**L'accolade se cherche en dehors des guillemets.** `a001 LOGIN "toto{5}" x` ne
porte aucun littéral : l'accolade y est dans une chaîne. La chercher sans suivre
les guillemets laisserait le client choisir où l'on découpe.

**LE TAG EST RECOPIÉ DANS LA RÉPONSE**, et c'est l'autre surface. IMAP entrelace
les commandes ; c'est le tag qui dit à quelle commande une réponse répond, et le
serveur le recopie verbatim. Un `CRLF` dedans écrirait une réponse entière de la
main du client ; un `*` en ferait une réponse non sollicitée ; un `+` une demande
de continuation. Ce ne sont pas des cas particuliers — ce sont les trois formes
que prend une réponse IMAP, et la grammaire de la RFC les exclut déjà du tag.

**Les arguments se lisent sous leurs trois écritures.** Un argument IMAP est un
atome (`INBOX`), une chaîne (`"Mon dossier"`, avec `\"` et `\\`), ou un
littéral. Un serveur qui n'en lit que deux refuse du courrier légitime ; un
serveur qui les confond laisse le client décider de ce qu'il lit. La valeur ne se
rend pas par emprunt — `"a\"b"` vaut trois octets là où la source en porte cinq —
et s'écrit donc dans le tampon de l'appelant, comme tout ce qui produit des
octets sans allouer.

## La session IMAP : quatre états, et c'est l'état qui décide

IMAP est le seul des trois protocoles dont le vocabulaire dépend entièrement d'où
l'on en est (§3). **`SELECT` avant authentification est une commande parfaitement
formée** : c'est l'état qui la refuse, pas la grammaire. Mélanger les deux ferait
un analyseur qui doit connaître l'état, et un état qui doit connaître la
grammaire.

**UN MOT DE PASSE NE TRAVERSE PAS UNE CONNEXION EN CLAIR.** `LOGIN` envoie
l'identifiant et le mot de passe tels quels, et `AUTHENTICATE PLAIN` fait la même
chose en base64 — qui n'est pas un chiffrement. La RFC 9051 §6.2.3 impose
d'annoncer `LOGINDISABLED` tant que la connexion n'est pas protégée ; cette
session va au bout de la même idée et **refuse les deux**, avec le code
`[PRIVACYREQUIRED]` que la RFC prévoit pour cela. Annoncer sans refuser
laisserait un client mal écrit envoyer le mot de passe quand même, et l'annonce
n'aurait servi qu'à se donner bonne conscience.

De cet invariant découle une simplification qui se lit dans le code : **on ne
peut pas être authentifié sans être chiffré**, donc `STARTTLS` n'a pas à
vérifier l'état — une session authentifiée est déjà repartie par « TLS is already
active ». Le fuzz éprouve l'invariant sur des suites de commandes arbitraires.

**`STARTTLS` efface tout ce qui précède** (§6.2.1) : ce qui a été dit en clair a
pu être dit par quelqu'un d'autre. La session repart de l'état non authentifié,
et oublie l'utilisateur comme le tag en cours.

**Quand le tag est illisible, la réponse est non sollicitée.** Une réponse
conclut la commande que son tag désigne ; si le tag lui-même est irrecevable, il
n'y a rien à désigner — et le recopier pour le dire serait précisément
l'injection que sa validation ferme. On répond alors par `*`, la seule forme qui
n'affirme rien.

**Le port 143 écoute**, avec `--listen-imap`. Le pilote ne sait du protocole que
trois choses : qu'une commande ne se découpe pas au premier `CRLF`, qu'une
réponse s'écrit telle quelle, et que la session lui dit quoi faire ensuite.

Là où les pilotes SMTP et POP3 lisent dans un tampon de taille fixe — une ligne y
tient ou n'y tient pas — **celui-ci fait grandir le sien**, parce que la longueur
d'une commande IMAP n'est connue qu'en la lisant. Ce qui l'empêche de croître
sans fin n'est pas une taille choisie dans le pilote, mais les bornes du
découpage : un littéral trop gros, trop de littéraux, une ligne trop longue sont
refusés **avant** que le moindre octet ne soit lu.

**Une commande indécodable ferme la connexion.** Quand la syntaxe est fautive, on
ne sait plus où la commande se termine ; reprendre la lecture laisserait le
client choisir ce qu'on lira comme une commande — exactement la faille que le
découpage existe pour fermer. Un tag illisible, lui, ne ferme rien : la commande
était lisible, c'est son tag qui ne l'était pas.

## Les boîtes IMAP : lire sans jamais tenir un message

`SELECT`, `EXAMINE`, `CLOSE`, `UNSELECT`, `LIST`, `STATUS`, `FETCH`, `STORE`,
`EXPUNGE`, `SEARCH`, `COPY`, `MOVE`, `APPEND`, `CREATE`, `DELETE`, `RENAME` et
leurs formes `UID` servent les boîtes du compte. Chacun a son `INBOX` — le nom que la RFC 9051 §5.1
réserve pour cela — et les dossiers que `CREATE` lui a faits.

**UN NOM DE BOÎTE DEVIENT UN RÉPERTOIRE**, et c'est la frontière la plus
délicate du serveur : voir « `CREATE` » plus bas pour les règles qui la tiennent,
et ce qu'elles ferment. Ce qu'on n'ouvre jamais, en revanche, c'est un répertoire
qu'on n'a pas fait : un `SELECT` sur une faute de frappe ne crée rien.

**UN MESSAGE NE PASSE JAMAIS PAR LA SESSION.** `FETCH` peut demander dix
mégaoctets ; les retenir pour les écrire ensuite donnerait au client le droit de
choisir combien de mémoire le serveur consomme. La session rend donc un
*intervalle* — « le message 3, de l'octet 0 à l'octet 4 812 » — et le pilote
l'écoule par tranches. **On a annoncé une longueur, et on la tient** : si le
magasin s'arrête plus tôt, le manque est comblé plutôt que de laisser un client
attendre des octets qui ne viendront pas.

**La conclusion étiquetée est le DERNIER morceau**, pas le premier. §7 veut que
les réponses non sollicitées d'une commande précèdent sa conclusion ; la rendre
d'avance obligerait le pilote à la retenir et à l'écrire après — un ordre
qu'aucun type ne lui rappellerait, et qu'il inverserait un jour. Il l'a
inversé, d'ailleurs, et c'est un essai contre le vrai binaire qui l'a montré.

**Un ensemble de séquences se lit de deux façons, et elles doivent s'accorder** :
`contains` répond « ce message est-il demandé ? », `ranges` énumère lesquels le
sont. Deux lectures qui se contrediraient rendraient un message à qui ne l'a pas
demandé. Un fuzz les confronte sur des ensembles arbitraires. Les surprises de la
§9 y sont : `*` vaut le dernier message, un intervalle n'est **pas** ordonné
(`25:*` sur une boîte de trois messages vaut `3:25`, et rend donc le troisième),
et sur une boîte vide `1:*` ne rend rien plutôt que le message zéro.

**IMAP NE VERROUILLE PAS, PARCE QU'IL N'ÉCRIT PAS.** POP3 prend le verrou
exclusif de la boîte — il efface, et la RFC 1939 §3 le lui demande. Une session
IMAP, elle, dure des heures : lui donner le même verrou interdirait toute relève
POP3 pendant ces heures, et — plus bêtement — s'interdirait à elle-même, car
`STATUS INBOX` sur une boîte déjà sélectionnée se heurtait à son propre verrou et
répondait qu'elle n'existe pas. Elle relève donc sans verrouiller, ce pour quoi
Maildir est fait. Ce qu'on accepte en échange est un message effacé en cours de
session, cas qu'il fallait tenir de toute façon.

**UNE SEULE VÉRITÉ SUR CE QUI S'ÉCRIT.** La boîte énumère les drapeaux qu'elle
sait faire survivre, et trois réponses en découlent : `PERMANENTFLAGS` les cite,
`SELECT` répond `[READ-ONLY]` quand il n'y en a aucun, et `STORE` refuse ce qui
n'y figure pas. Une seconde méthode « est-elle modifiable ? » aurait fini par ne
plus dire la même chose que la première.

## `STORE` : écrire dans un Maildir que personne ne verrouille

Dans un Maildir, **les drapeaux vivent dans le nom du fichier** : les écrire,
c'est renommer. Ce qui donne trois questions qu'aucun protocole ne tranche, et
que ce serveur tranche ainsi.

**ON N'ÉCRIT PAS CE QU'ON CROIT SAVOIR, ON ÉCRIT CE QU'ON VIENT DE LIRE.** Les
drapeaux sont relus dans le nom du fichier à l'instant du renommage, pas dans
l'instantané pris à l'ouverture. Deux `+FLAGS` concurrents se composent donc, au
lieu que le second efface ce que le premier venait de poser. Un `FLAGS` nu, lui,
écrase — mais c'est exactement ce que le client a demandé : `+`/`-` fusionnent,
`FLAGS` remplace, et la distinction n'est pas cosmétique.

**LE NOM QU'ON LIT DOIT ÊTRE CELUI QUI EXISTE.** Quand le renommage échoue, le
message a bougé sous nos pieds : on le retrouve par son UID — le seul
identifiant qui survive à un changement de drapeaux — et l'on recommence, trois
fois au plus. Le piège n'est pas là où on l'attend : c'est le raccourci « rien à
écrire » qui mordait, parce qu'il concluait à partir d'un nom disparu et
répondait `OK` sans avoir rien écrit. Il vérifie maintenant que le fichier est
là.

**`P` N'EST PAS DANS LE VOCABULAIRE D'IMAP, DONC IMAP NE PEUT PAS LE RETIRER.**
Maildir a six lettres, IMAP cinq drapeaux, et `P` (*passed*) n'a pas
d'équivalent. Un `FLAGS (\Seen)` demande « exactement `\Seen` » — exactement dans
le vocabulaire du client, qui ne sait pas dire `P`. Le lui faire effacer serait
lui prêter une intention qu'il ne pouvait pas former.

**Un drapeau inconnu — `$Important`, un mot-clé de client — est refusé**, pour
la même raison qu'on refuse tout ce qu'on ne sait pas faire survivre.

**Ce qui se perd, et ce qui ne se perd pas.** Deux sessions qui marquent le même
message ne s'effacent pas l'une l'autre : les écritures relisent le nom du
fichier au moment d'écrire, et les deux lettres se retrouvent sur le disque. En
revanche, **une session ne VOIT pas ce qu'une autre vient de poser** : son
instantané fixe les rangs et les noms pour toute la sélection, et le relire à
chaque `FETCH` coûterait un parcours de répertoire par commande. Elle le verra à
la prochaine sélection. C'est une limite, elle est dite, et elle ne fait perdre
aucune marque — seulement du retard à en rendre compte.

**`.SILENT` ne rend rien et fait le travail quand même**, et un message annoncé
puis disparu ne fait pas échouer la commande (§6.4.6) : le client l'apprend en
ne recevant rien pour lui.

## `EXPUNGE` : effacer pour de bon, sans jamais effacer de travers

`\Deleted` n'est plus refusé : quelque chose l'honore enfin. `EXPUNGE` efface les
messages qui le portent, `UID EXPUNGE` s'en tient à l'ensemble qu'on lui nomme
(§6.4.9), et `CLOSE` efface en refermant (§6.4.2) — là où `UNSELECT` referme sans
rien effacer, ce pour quoi il existe. Les confondre ferait effacer du courrier à
qui demandait le contraire.

**CHAQUE `* n EXPUNGE` RENUMÉROTE CE QUI SUIT** (§7.5.1). Effacer les messages 1
et 3 d'une boîte de trois ne s'annonce donc pas « 1 puis 3 » mais « 1 puis 2 » :
après le premier, l'ancien troisième est devenu le deuxième. Un serveur qui
annoncerait les rangs d'origine ferait effacer au client un message qu'il voulait
garder.

**ON N'EFFACE PAS SUR UNE CROYANCE PÉRIMÉE.** La session demande d'effacer ce que
son instantané dit marqué — un instantané pris à l'ouverture, il y a peut-être
des heures. Le magasin relit donc les lettres dans le nom du fichier à l'instant
d'effacer, et **refuse si la marque n'y est plus**. Le refus ne s'annonce pas :
annoncer un effacement qui n'a pas eu lieu ferait perdre au client le fil des
numéros. Un courrier perdu ne se retrouve pas ; un courrier qui survit une
session de trop se ferme au prochain `EXPUNGE`.

**`NotFound` NE VEUT PAS DIRE « DÉJÀ PARTI ».** Dans un Maildir, un message
introuvable sous son nom a le plus souvent changé de nom — quelqu'un a écrit ses
drapeaux. Le prendre pour une disparition faisait oublier de la boîte un message
bien vivant, et pire : « effacé » sur la foi de lettres lues dans un nom qui
n'existait plus. On le retrouve donc par son UID, et l'on recommence — trois fois
au plus. C'est l'essai contre le vrai binaire qui l'a montré, en retirant une
marque sous ses pieds.

**Une boucle qui n'avance pas remplit la mémoire.** L'effacement n'avance pas le
rang courant : ce qui suivait descend à sa place, et il faut l'examiner à son
tour. Le tour ne se termine donc que parce que la boîte rétrécit — ce que la
session ne peut pas vérifier. Elle ne compte pas dessus : **elle n'efface jamais
plus de messages que la boîte n'en portait**. Ce n'est pas de la prudence
abstraite : un itérateur qui ne consommait pas son entrée a déjà tué cette
machine, 6 Gio en quelques secondes.

## `SEARCH` : un arbre sans allocation, et un ensemble sans liste

**IMAP4rev2 a remplacé `* SEARCH` par `* ESEARCH`** (§7.3.4). L'ancienne réponse
`* SEARCH 2 4 5 6 7` a disparu ; la nouvelle rend `* ESEARCH (TAG "a001") ALL
2,4:7`, où les résultats sont un **ensemble** et non une liste. Ce serveur
n'annonce que `IMAP4rev2`, et rendre l'ancienne forme à un client qui a lu
l'annonce serait le tromper.

**On comprime en avançant, sans rien retenir.** Comprimer demande de savoir si le
résultat suivant prolonge le précédent, ce qui tient dans deux entiers : la plage
ouverte. Retenir tous les résultats pour les comprimer à la fin demanderait une
mémoire que le client choisirait.

**C'est la seule réponse du serveur qui ne tienne pas forcément dans un
morceau.** Une ligne `ESEARCH` peut être plus longue qu'un tampon : elle se
découpe, et le découpage ne change pas ce que le client lit. Chaque morceau
s'écrit d'un seul geste — composé dans un tampon de taille fixe par des routines
qui ne peuvent pas échouer, puis poussé une fois — parce que découvrir le manque
de place au milieu d'une plage laisserait un résultat à moitié écrit, que le
client lirait comme un résultat faux.

**`NOT`, `OR` et les parenthèses font de `SEARCH` un arbre**, et C1 interdit
d'allouer. Les nœuds vivent dans un tableau de taille fixe et se désignent par
leur indice — et **un nœud ne référence que des indices strictement
inférieurs**, parce qu'un enfant est rangé avant son parent. Ce n'est pas une
convention qu'on espère tenir : c'est la seule façon dont le tableau se remplit,
et elle rend le cycle impossible. L'évaluation descend donc toujours, et se
termine sans qu'on ait à compter les tours. L'imbrication est bornée à huit
niveaux : sans quoi `NOT NOT NOT …` ferait descendre l'analyseur aussi profond
que le client le demande, et la pile n'est pas extensible.

**Ce qui est cherché, et ce qui est refusé.** Tout ce qui se décide avec ce que
la boîte sait déjà : `ALL`, les cinq drapeaux et leurs formes `UN…`, `LARGER`,
`SMALLER`, `BEFORE`/`ON`/`SINCE`, `UID <ensemble>`, un ensemble de rangs, et les
combinaisons. **Rien qui demande de lire le message** — `BODY`, `TEXT`,
`SUBJECT`, `FROM`, `HEADER` et leurs semblables sont reconnus et **refusés**,
parce qu'un `SEARCH SUBJECT "facture"` qui répondrait « aucun résultat » serait
un mensonge exact. Ils viendront avec la machinerie qui lit un message au fil de
l'eau.

## `COPY` : tout ou rien, et dire où

`COPY` et `UID COPY` copient dans la boîte nommée. **`INBOX` est la seule qui
existe**, donc la seule destination possible ; toute autre reçoit
`NO [TRYCREATE]`, le code qui apprend au client qu'un `CREATE` suivi du même
`COPY` marcherait — le lui refuser sèchement le laisserait deviner.

**§6.4.7 : un `COPY` n'est pas partiellement réussi.** Si un message ne peut pas
être copié, ce qui l'a été avant lui est **défait**, et la commande répond `NO`.
Un client qui reçoit `NO` doit pouvoir recommencer sans se demander lesquels de
ses messages sont déjà passés — et sans faire de doublons. Défaire ne demande
rien à retenir : les UID attribués se suivent, donc ce qu'il faut retirer est une
plage.

**`COPYUID` dit au client OÙ ses messages ont atterri** — `[COPYUID <validité>
<source> <destination>]`, les deux ensembles se lisant dans le même ordre. Celui
de destination tient toujours en une plage, puisque les UID sont attribués en
croissant ; celui de source est ce que le client a désigné, trous compris, et sa
longueur est donc **choisie par le client**. On l'accumule dans un tampon borné,
et **s'il déborde, `COPYUID` est omis entièrement** : un ensemble tronqué
désignerait d'autres messages que ceux qu'on a copiés, ce qui est pire que de ne
rien dire.

**Copier, c'est déposer un message neuf**, avec la même danse que la remise SMTP :
écrire dans `tmp/`, synchroniser, renommer. Les drapeaux d'origine sont préservés
en **un seul** renommage — déposer puis renommer laisserait la copie visible sans
eux, et un client qui regarderait à cet instant la croirait non lue. La date
d'arrivée, elle, est celle de la copie : la reculer demanderait une dépendance
pour un `utimensat`, et §6.4.7 n'en fait qu'un souhait.

**Ce qu'on parcourt ne doit pas grandir sous nos pieds.** Copier dans la boîte
ouverte l'agrandit ; relire le nombre de messages à chaque tour ferait de
`COPY 1:* INBOX` une boucle que le client n'aurait qu'à demander. Le nombre est
donc arrêté d'avance.

## `MOVE` : copier, puis retirer — dans cet ordre, et en le disant dans cet ordre

`MOVE` est un `COPY` suivi d'un retrait, et §6.4.8 **impose l'ordre des
réponses** : d'abord `* OK [COPYUID …]`, non sollicité, qui dit où les messages
sont allés ; puis les `* n EXPUNGE`, qui disent qu'ils ne sont plus là ; enfin la
conclusion. Le premier voyage donc comme réponse du tour et les autres comme
morceaux d'émission — c'est exactement l'ordre où l'appelant les écrit, sans
qu'il ait rien à se rappeler.

**ON RETIRE PAR UID, MÊME QUAND LE CLIENT A DÉSIGNÉ DES RANGS.** Retirer
renumérote : un ensemble de rangs cesserait de désigner ce qu'il désignait dès le
premier retrait, et l'on retirerait des messages que personne n'a nommés. Les
sources sont donc traduites en UID pendant la copie — et **si cette traduction ne
tient pas** dans ce qu'on sait nommer, le déplacement est refusé et les copies
défaites : retirer au hasard serait perdre du courrier.

**Retirer n'est pas effacer.** `EXPUNGE` relit la marque `\Deleted` dans le nom
du fichier avant d'effacer — c'est la garde qui empêche de perdre du courrier sur
une croyance périmée. `MOVE` n'a aucune marque à relire : il retire un message
qu'il vient de copier, à l'instant, sur ordre exprès. Confondre les deux ferait ou
bien un `MOVE` qui ne déplace rien, ou bien un `EXPUNGE` qui efface ce qu'on ne
lui a pas demandé. Ce sont donc deux opérations distinctes du magasin.

**Si la ligne `COPYUID` ne tient pas dans le tampon de l'appelant, elle est
omise** — et le déplacement a lieu quand même. C'est un `SHOULD` de la RFC ;
échouer là laisserait les copies faites et les retraits à faire, ce qui est bien
pire que de ne pas dire où les messages sont allés.

## `APPEND` : la seule commande dont un argument est un message

Toutes les autres tiennent dans ce qu'une connexion peut retenir. Celle-ci porte
ce que le client veut — **la retenir en mémoire lui donnerait le droit de choisir
combien le serveur en consomme**. Elle se lit donc en deux temps : la grammaire
lit ce qui précède le littéral, et le message s'écoule vers le magasin au fil de
l'eau, exactement comme le `DATA` de SMTP.

**`APPEND` ne passe pas par le découpage ordinaire.** Le pilote reconnaît sa
première ligne AVANT de découper, parce que découper voudrait dire accumuler.
Ce qui n'est pas de cette forme — un `APPEND` sans littéral, ou dont le nom de
boîte EST un littéral, ce qui est légal — retombe sur le chemin ordinaire, qui
le refuse en le disant : écouler ce littéral-là écrirait un nom de boîte dans le
courrier.

**On refuse AVANT d'inviter.** Un littéral synchronisant attend une invitation ;
la donner puis refuser ferait attendre le serveur pour des octets que le client
n'enverra jamais — un délai d'attente entier, par commande refusée. Une boîte
inconnue, une session non authentifiée, un message plus gros que la borne : tout
cela se dit sans qu'un octet de message n'ait été lu, et c'est tout l'intérêt de
la forme synchronisante. Un littéral **non** synchronisant, lui, part sans
prévenir : ses octets arrivent quoi qu'on réponde, on les lit donc et on les
jette — ne pas les lire ferait lire un message comme des commandes.

**Deux bornes, et elles ne sont pas la même.** Celle d'un littéral ordinaire dit
ce qu'une connexion RETIENT (soixante-quatre kibioctets) ; celle d'un `APPEND`
dit ce qu'un MESSAGE pèse, et vaut la borne SMTP — un message qu'on refuserait
de recevoir par un chemin n'a pas de raison de passer par l'autre.

**Rien n'est visible tant que le dépôt n'est pas validé**, et un message tronqué
ne se dépose pas : si le pair raccroche au milieu, le dépôt est abandonné.
Valider ce qu'on a reçu déposerait du courrier que personne n'a envoyé.

**La date d'arrivée demandée est honorée.** §6.3.12 permet au client de donner la
date-heure du message ; elle est posée sur le fichier encore dans `tmp/`, avant
le renommage — c'est-à-dire avant que quiconque puisse le voir. Et `INTERNALDATE`
la relit à l'identique : lire ce qu'on écrit est la moindre des cohérences.

## `CREATE` : là où un nom de client devient un chemin

Jusqu'ici, ce dépôt pouvait écrire en toutes lettres qu'**aucun chemin n'était
construit à partir d'un nom de boîte** : `INBOX` se comparait à une constante.
`CREATE` met fin à cela, et c'est la frontière la plus délicate du serveur.

**On refuse, on ne transforme pas.** La RFC autorise beaucoup plus que ce serveur
n'accepte : de l'UTF-8, des points, des caractères qu'un système de fichiers lit
mal. Un nom qu'on ne saurait pas transcrire sans risque est **refusé**, jamais
adapté — rendre au client un nom qui n'est pas celui qu'il a demandé lui ferait
chercher longtemps. Les règles tiennent en un endroit : non vide et borné,
découpé sur `/` sans composant vide, profondeur bornée, **aucun point** (ce qui
ferme `..`), et de l'ASCII imprimable sans `\`, `%`, `*`, `"` ni `:`. Un espace
est admis : « Sent Messages » est un nom de dossier des plus ordinaires.

**La règle est vérifiée DEUX FOIS**, par la session puis par le magasin. Non par
défiance de la première, mais parce que c'est le magasin qui touche le système de
fichiers : une vérification faite ailleurs est une vérification qu'on ne voit pas
en lisant l'endroit qui en dépend, et elle survivra à un appelant qui
l'oublierait.

**Sur le disque, un seul niveau de répertoires.** `Archives/2026` devient
`.Archives.2026` dans la racine du compte, à la façon de Maildir++ : le chemin
n'a donc jamais plus d'un morceau venu du client. Une propriété de fuzz le
vérifie sur la transcription elle-même — pas de séparateur, pas de `..`, pas
d'octet de contrôle — sur des noms arbitraires.

**Créer `A/B/C` crée aussi `A` et `A/B`** (§6.3.4). En Maildir++ les parents sont
des répertoires frères, et les omettre ferait montrer par `LIST` une fille sans
sa mère.

**Les noms se citent dans les réponses.** Toujours, plutôt que seulement quand
c'est nécessaire : ne citer que les noms qui en ont besoin demanderait une
condition de plus, qu'il faudrait avoir juste à chaque endroit.

`INBOX` ne se crée pas (§6.3.4 : elle existe toujours), une boîte déjà là se dit
`[ALREADYEXISTS]`, et un magasin qui refuse le dit sans accuser le client.

## `DELETE` : ce qui s'en va, et ce qui doit rester

**§6.3.5 : une boîte qui a des filles ne disparaît pas.** Son courrier s'en va,
son **nom demeure**, et il se marque `\Noselect` dans `LIST`. Effacer le nom
romprait la hiérarchie : ses filles existeraient sans que personne puisse les
atteindre.

**Sur le disque, cela se dit sans marqueur.** Le répertoire reste, ses trois
sous-répertoires Maildir s'en vont : un nom qui n'a plus de `cur/` est
`\Noselect`, et il le reste tant qu'un `CREATE` ne le refait pas — ce que §6.3.4
autorise expressément, et qui marche. C'est aussi la garde qui empêche
`Maildir::open` de ressusciter une boîte effacée, puisqu'il recrée ce qui manque.

**L'index part avec le courrier**, et une boîte recréée sous le même nom reçoit
une `UIDVALIDITY` neuve. Le piège est la résolution de l'horloge : effacer puis
recréer dans la même seconde rendait la MÊME validité avec des UID repartis de
un, et un client qui a gardé ses UID aurait montré à son porteur des messages qui
ne sont pas ceux qu'il désigne. Un compteur fait avancer ce que l'horloge n'a pas
fait avancer, et **deux appels ne rendent jamais la même valeur**.

**`INBOX` ne s'efface pas** (§6.3.5) : c'est le seul endroit où le courrier
arrive. Et une boîte qu'on vient d'effacer ne reste pas ouverte : la session en
tient un instantané qui ne désigne plus rien, et le client se retrouve
authentifié sans sélection — il doit le savoir.

## `RENAME` : deux règles qu'on manque facilement

**§6.3.6 : les filles suivent.** Renommer `Vieux` en `Anciens` renomme aussi
`Vieux/2026` : les laisser derrière ferait des boîtes dont le chemin ne mène plus
nulle part. On rassemble donc d'abord tout ce qui bouge, on vérifie que **rien**
n'est déjà pris, puis on renomme — et si l'un échoue, on défait les précédents.
Un renommage à moitié réussi laisserait la mère sous un nom et ses filles sous
l'autre, ce qu'aucun client ne saurait démêler.

**§6.3.6 : renommer `INBOX` la vide, sans la faire disparaître.** Son courrier
s'en va vers le nouveau nom ; elle reste, vide. C'est le seul endroit où le
courrier arrive, et un compte qui la perdrait ne recevrait plus rien. Les
messages se déplacent par `rename` dans le même système de fichiers : ils ne
passent jamais par la mémoire, et n'existent à aucun instant en deux exemplaires.

**Et son index reste.** C'est le détail qui coûte cher si on le manque : l'index
porte le prochain UID à servir, et la validité d'`INBOX` **ne change pas** en la
renommant. Le retirer ferait repartir les UID de un après un redémarrage, sous la
même validité — c'est-à-dire réattribuer des numéros déjà donnés, ce que
§2.3.1.1 interdit. Un index qui compte des messages partis n'est pas un
problème : le parcours dit ce qui EST, l'index seulement ce qui A ÉTÉ.

Une boîte ne se renomme pas sous elle-même, rien ne se renomme en `INBOX`, et une
boîte qui vient de changer de nom — ou dont la mère a changé de nom — ne reste pas
ouverte : la session en tient un instantané qui désigne désormais autre chose.

### `ENVELOPE` : ce que le message dit de lui-même

Un client qui affiche une liste de messages ne veut pas les messages : il veut
dix champs par message — la date, le sujet, l'expéditeur, les destinataires.
`ENVELOPE` (§7.5.2) les lui donne sans qu'il ait à lire quoi que ce soit.

**On ne décode rien, et c'est la règle.** L'enveloppe porte le TEXTE DE
L'EN-TÊTE, tel quel : un `Subject:` en mots encodés (`=?utf-8?B?…?=`) se recopie
encodé, et c'est au client de le lire. Décoder ici lui rendrait autre chose que
ce que le message porte, et lui ôterait le moyen de le vérifier. En revanche, ce
qui appartient à la SYNTAXE de la RFC 5322 et non au texte s'en va : les
guillemets d'un nom cité et ses échappements, les commentaires — qui se
traversent sans se recopier —, et les routes source, que la RFC 5322 a retirées
et qu'`adl` rend donc toujours `NIL`.

**Une chaîne ne porte pas de fin de ligne.** Le pliage disparaît partout, y
compris à l'intérieur d'un nom cité — c'est le cas qu'on oublie, et c'est
exactement celui que le fuzzing a trouvé. Une chaîne IMAP ne peut porter ni `CR`
ni `LF` : le client lirait la fin de la réponse au milieu d'un nom, puis la suite
du dialogue comme du protocole. Ce n'est pas une laideur d'affichage, c'est une
désynchronisation. Le pli s'efface au lieu de devenir un blanc — celui qui suit
un `CRLF` appartient déjà à la chaîne —, et un nom qui n'est qu'un pli ne vaut
rien : `NIL`, et non `""`.

**L'enveloppe ne séjourne pas dans la session**, comme aucun message n'y
séjourne : elle se compose dans le tampon de l'appelant et s'écoule par morceaux.
Un défaut latent est tombé en l'écrivant : `FETCH 1 (BODY[] UID)` émettait
`BODY[] {100}` puis `UID 1`, PUIS les cent octets — les données d'un élément
arrivaient après l'élément suivant. La session compte désormais les éléments
déjà écrits, et reprend où elle s'était arrêtée au lieu de recommencer la ligne.

Là où la composition échoue — un en-tête illisible, une enveloppe plus grande que
son tampon —, le serveur rend `(NIL NIL NIL NIL NIL NIL NIL NIL NIL NIL)` plutôt
que rien : une enveloppe vide est une réponse, une enveloppe absente couperait la
réponse au milieu d'un élément.

### `BODYSTRUCTURE` : l'arbre du message, sans le message

Un client qui affiche une liste de pièces jointes ne veut pas les pièces
jointes : il veut leur nom, leur type et leur taille. `BODYSTRUCTURE` (§7.5.2)
les lui donne, pour chaque partie, y compris les parties emboîtées.

**Le message ne séjourne pas ; la description seule reste.** C'est la différence
avec l'enveloppe, et elle coûte cher : une enveloppe se lit dans l'en-tête, une
structure se lit dans TOUT le message, parce que ce sont les frontières de la RFC
2046 qui la dessinent et qu'elles sont semées d'un bout à l'autre. Retenir le
message pour les trouver reviendrait à réserver ce que l'expéditeur a choisi
d'écrire — exactement ce que C3 interdit. Le balayeur se fait donc **pousser** les
octets, par morceaux, et ne retient qu'un état borné : au plus soixante-quatre
parties, huit niveaux d'emboîtement, et une arène d'en-têtes de taille fixe. Un
message d'un gibioctet et un message de mille octets y coûtent la même mémoire.

**Le découpage ne change pas le résultat**, et c'est ce que le fuzz éprouve. Les
morceaux ont la taille du tampon de celui qui lit — une taille que le message ne
choisit pas et que rien ne garantit stable. Une frontière tombant à cheval sur
deux morceaux ne doit pas se voir. C'est la même propriété que pour la phase de
données de SMTP, et pour la même raison : deux lecteurs qui découpent
différemment doivent conclure pareil.

**Rien de ce qui déborde ne fait échouer.** Une structure absente couperait la
réponse au milieu d'un élément, ce qui est pire qu'une structure incomplète : au
delà des bornes, on décrit ce qu'on a pu voir, dans une forme que la grammaire
admet toujours. Un `multipart` qu'on n'a pas su ouvrir — pas de frontière, ou
plus de place pour l'emboîter — est décrit en `application/octet-stream`, ce que
MIME prescrit pour une entité qu'on ne sait pas interpréter (RFC 2049 §2) et ce
qu'un client ne lira pas de travers : un type `MULTIPART` suivi d'une taille
n'existe pas dans la grammaire.

Ce qui n'y est toujours pas : **servir une PARTIE désignée**. `BODY[1]`,
`BODY[1.MIME]` restent refusés — le serveur sait DIRE la structure d'un message,
il ne sait pas encore en rendre un morceau choisi, et un client qui veut une
pièce jointe télécharge le message entier. La réponse est `NO [UNAVAILABLE]` —
`NO` et non `BAD`, parce que la commande est correcte et permise et que c'est ce
serveur qui ne la sert pas. Le serveur dit au démarrage ce qu'il sert et ce qu'il
ne sert pas, plutôt que de laisser un port ouvert le faire croire.

## Émettre : le client SMTP sortant

Jusqu'ici, tout venait à ce serveur : des pairs frappaient, il répondait. Émettre
inverse la relation, et avec elle toutes les questions de confiance — **le
serveur qu'on joint est désigné par le destinataire**, c'est-à-dire par quiconque
publie un `MX`, et ce qu'il répond est une entrée hostile comme une autre.

Les trois étages y sont, et aucun ne partage une ligne avec le côté serveur :
lire une réponse n'est pas en écrire une, et les faire dériver d'un même code
ferait qu'un jour, en corrigeant l'un, on casserait l'autre.

**Trois refus qui se ressemblent et qui ne sont pas le même.** `4yz` : réessayer
plus tard a un sens, et jeter ici perd du courrier qui serait passé. `5yz` :
réessayer n'en a aucun, et insister revient à harceler un serveur qui a dit non.
Le `MX` nul (RFC 7505) : le domaine déclare à l'avance ne recevoir aucun
courrier. Un serveur injoignable n'est aucun des trois — c'est une panne, donc
temporaire.

**Le chiffrement sortant n'authentifie personne, et c'est écrit.** Le `MX` vient
d'un DNS non validé : un tiers capable de détourner cette résolution peut aussi
bien présenter un certificat valide pour le nom qu'il vient de fabriquer, et
vérifier ce certificat ne prouverait rien de plus que de ne pas le vérifier.
DANE (RFC 7672) et MTA-STS (RFC 8461) sont ce qu'il faudrait ; ni l'un ni l'autre
n'est ici. Ce qui est acquis est réel et limité : on passe d'un espion passif à
un attaquant actif. **Le repli, lui, n'est pas opportuniste** — un serveur qui
annonce `STARTTLS` puis refuse ne nous fera pas parler en clair.

**Ce qui n'écrit rien à moitié.** Une adresse de destination peut venir d'un tiers
— celle d'un rapport DMARC est publiée par le domaine qu'on rapporte. Un `CRLF`
glissé dedans écrirait des commandes à notre place sur notre propre connexion :
seul l'ASCII imprimable sans espace ni chevrons passe. Et un corps qui porte un
`LF` isolé n'est pas « réparé » : il ne part pas, parce que ce qu'on émettrait ne
serait plus ce qu'on a lu — et la signature DKIM qui le couvre ne vaudrait plus
rien.

Le client est éprouvé **contre notre propre serveur** : deux moitiés qui ne
partagent aucun code, mises face à face. C'est là que se vérifie que le
point-farcissage et sa défaite se répondent, et qu'un message contenant une ligne
au seul point arrive intact. Il n'a pas encore d'appelant dans le binaire — son
premier sera l'envoi des rapports — et il n'y a pas de file d'attente : `send`
remet, ou dit pourquoi il n'a pas pu.

**La quarantaine n'est pas encore un endroit.** `p=quarantine` demande de traiter
le message comme suspect ; ce serveur n'a pas de dossier pour cela. Il le remet,
et consigne la demande. Le refuser serait faire plus que ce que le domaine a
demandé ; le taire serait faire moins que ce qu'on sait.

`ams-dns` : le codec d'un message DNS — une question encodée, une réponse
décodée. **Un client stub, et rien de plus** : ce serveur pose des questions, il
n'en répond aucune. Prendre une bibliothèque de résolution toute faite aurait
apporté son propre modèle d'exécution, ses propres délais et ses propres caches,
c'est-à-dire exactement ce que l'étage 3 doit décider.

La compression des noms (RFC 1035 §4.1.4) y est le point sensible : un nom peut
se poursuivre par un **pointeur** vers un autre nom du message, et un message
hostile peut fabriquer un cycle. **La parade n'est pas un compteur de sauts,
c'est une impossibilité structurelle** : chaque pointeur doit viser strictement
plus bas que le précédent, la suite des cibles décroît dans les entiers
naturels, et une suite décroissante d'entiers naturels s'arrête. C'est aussi ce
que dit la RFC, qui veut qu'un pointeur désigne une occurrence antérieure.

**Ce que cette crate ne fait pas : DNSSEC.** C'est une lacune, pas un oubli — et
elle est écrite partout où elle compte : sans validation, un `pass` SPF ne vaut
que ce que vaut le chemin jusqu'au résolveur. Le résolveur doit donc être local,
ou joint par un lien de confiance ; le serveur le répète au démarrage.

`ams-auth` : les comptes — un nom, une empreinte, des adresses — et la
vérification **Argon2id** (m = 19456 Kio, t = 2,
p = 1 — la configuration OWASP). Un compte inconnu coûte le même temps qu'un
compte connu, parce qu'il est comparé à une empreinte de personne : sans cela,
l'écart de temps rendrait le magasin énumérable sans en connaître un seul mot de
passe. Une empreinte sous le plancher du produit est refusée **au chargement**,
en nommant le compte — une vérification emploie les paramètres inscrits dans
l'empreinte, si bien qu'un compte haché faiblement serait vérifié faiblement.

`ams-session` : **deux** sessions. La session POP3 d'abord — les trois états de
la RFC 1939, `USER`/`PASS` refusés hors chiffrement, les réponses multilignes et
le doublement du point. L'état UPDATE, celui qui efface, n'est atteint que par un
`QUIT` venu de TRANSACTION : une coupure réseau ne perd donc jamais de courrier.
La boîte **sort de la session** le temps d'une commande, ce qui rend l'état
structurel — une commande de relève reçoit la boîte en argument, donc elle ne
peut pas être appelée sans.

Et la session SMTP entière — bannière, `EHLO`, annonce des
extensions, séquencement `MAIL`/`RCPT`/`DATA`, `STARTTLS`, refus d'`AUTH` hors
chiffrement, **la phase de données et l'échange SASL** — défi, base64, format de
`PLAIN`, annulation par `*`. Elle n'authentifie personne pour autant : elle
demande à la politique, qui refuse par défaut.

`ams-loop-tokio` conduit aussi **la vérification SPF** : la session rend la main
sans répondre au `MAIL FROM:`, la boucle résout les questions posées par
`ams-spf`, et c'est la session qui compose le `250`, le `550 5.7.23` ou le
`451 4.4.3`. Le vocabulaire de sortie reste clos. Deux défenses gratuites
accompagnent chaque question : un identifiant tiré de `/dev/urandom` et un port
source neuf, soit trente-deux bits à deviner pour qui voudrait répondre à notre
place.

`ams-loop-tokio` : la boucle d'acceptation et le pilote d'une connexion, sur
tokio. Elle lit, elle écrit, elle ne décide de rien — pas même le `421` qui refuse
une source trop pressée, qui vient de la session. Ses tests jouent des
conversations en mémoire **et** de vraies connexions sur la boucle locale.

Elle conduit `STARTTLS` (RFC 3207) : la poignée de main, puis **le même pilote
rejoué au-dessus du flux chiffré**, la session remise à zéro. Ce qu'un pair envoie
derrière son `STARTTLS` n'est jamais exécuté — c'est la faille de 2011, et le
tampon n'est pas vidé en silence : le pair reçoit un `421` au lieu de son `220`.
Le fournisseur cryptographique, lui, ne vient jamais d'ici : l'appelant apporte
celui de `ams-tls`. De l'échange SASL, elle ne sait qu'une chose : après un
défi, la ligne suivante va à la session plutôt qu'à la grammaire des commandes.

`ams-guard` : la détection de flooding et le bannissement par source (C8), dans
une table **bornée** que l'appelant fournit — et dont une peine en cours n'est
jamais évincée. La clé est un **préfixe**, pas une adresse : bannir une IPv6 seule
ne sert à rien. Le garde est consulté avant la bannière, puis à chaque commande ;
**on ne dit pas un mot à un banni**.

`ams-tls` : le fournisseur cryptographique — pur Rust, **trois suites, toutes
TLS 1.3**, aucune ligne de C — et l'échange de clés hybride `X25519MLKEM768`
(C14), que `rustls-rustcrypto` ne fournit pas. C'est la seule crate du dépôt qui
porte de la **cryptographie composée** : les primitives viennent de `ml-kem` et
`x25519-dalek`, mais l'ordre des octets sur le fil est notre code. Il a été relevé
dans `draft-ietf-tls-ecdhe-mlkem` §3.1.3 — où le secret ML-KEM vient en premier,
à l'inverse de l'autre groupe du même brouillon — et **vérifié contre un
`openssl s_client` réel**, seule preuve possible que les deux camps calculent le
même secret. La boucle s'en sert pour `STARTTLS`, et le serveur pour de bon.

`ams-index` : les noms Maildir, les drapeaux, et la **reconstruction** — un
repliement sur les noms, sans table donc sans allocation. C'est là que vit la
raison d'être du `,U=` dans un nom de fichier.

Et ce que les noms **ne peuvent pas** porter : l'`UIDVALIDITY` de la boîte, et le
filigrane des UID. L'index persisté ne contient que ces deux nombres, et rien
d'autre — recopier ce que les noms disent déjà créerait une seconde source de
vérité, capable de diverger de la première sans que rien ne le signale. Le
perdre ne perd aucun message ni aucun UID : cela oblige seulement à changer
l'`UIDVALIDITY`, c'est-à-dire à demander aux clients de resynchroniser.

`ams-store` : la boîte Maildir. Une session de relève la **verrouille** par un
`flock` — pas par un fichier témoin, qui survivrait à un arrêt brutal et
obligerait à décider au bout de combien de temps un verrou devient « périmé ».
Personne ne décide bien cela ; le noyau, lui, relâche à la mort du processus. Arrivée par `rename()` atomique, **deux `fsync`**
— le fichier avant, le répertoire après —, adoption des messages déposés par
d'autres outils, et nettoyage de `tmp/` même quand une remise est abandonnée.
L'index s'écrit avec la même discipline, et son filigrane est **réservé par
tranches de 256** : un `fsync` toutes les 256 remises au lieu d'un par message,
au prix de trous dans la numérotation après un arrêt brutal. La RFC 9051 les
autorise ; un UID réattribué, lui, montrerait à un client un message pour un
autre.

`ams-config` : les **trois** schémas Cap'n Proto et leurs codecs — la
configuration, les comptes, l'index d'une boîte. Le code dérivé est **généré et
committé** : le build et la CI n'ont besoin d'aucun outil C++.

`ams-server` et `ams-admin` : les deux binaires de C12. Le premier assemble les
pièces et ne contient **aucune logique de protocole** — seulement le fil. Il lit
la section TLS de sa configuration, charge le certificat et la clé, et n'annonce
`STARTTLS` que s'il les a. Il **refuse de démarrer sur une clé privée lisible par
tout le monde** ; le partage par groupe, lui, reste permis. Le
second sait relire une boîte, ce qui est la reconstruction de C13 exécutée à la
demande.

Toutes les autres crates sont vides, et chacune le déclare dans sa documentation.

### Pourquoi les étages 1 et 2 ne font aucune entrée-sortie

Une machine à états se pilote pas à pas depuis un test : on lui donne des octets,
on lui donne une heure, on regarde ce qu'elle rend. **Une boucle asynchrone ne se
pilote pas — on l'attend.** C'est la seule disposition où le 100 % de couverture
reste atteignable au-dessus des codecs, et c'est aussi ce qui rend les décodeurs
fuzzables sans ouvrir un port.

L'étage 3 est hors de ce périmètre de couverture, non par indulgence, mais parce
qu'y atteindre 100 % exigerait de simuler les pannes du noyau — et l'on mesurerait
alors la fidélité de la simulation, pas la justesse du code.

### Aucune abstraction d'exécution

Il n'y a **pas** de trait qui abstrairait tokio et le moteur d'Air. Chaque moteur
porte sa propre boucle, qui pilote la **même** machine à états : rien à adapter,
rien à maintenir entre les deux, et la logique du serveur n'est écrite qu'une
fois.

## Portage vers Air

Ce projet appartient au même projet qu'[Air](https://github.com/air-desktop-project/air).
Il n'en dépend **pas** aujourd'hui.

Sur la cible `*-linux-air`, la boucle d'entrées-sorties sera adossée au moteur
asynchrone d'Air — `air-async` (exécuteur mono-thread) au-dessus de `air-uring`
(réacteur io_uring). Les deux existent réellement dans le dépôt `air`.

Cette boucle **n'est pas créée** : une crate vide portant ce nom laisserait croire
qu'un portage est entamé. Aucune date, aucun engagement de calendrier.

## Lancer

La configuration est un fichier **binaire** : elle n'est pas éditable à la main,
et `air-mail-admin` est le seul moyen d'en produire une. Le serveur, lui, n'a
aucune option de réglage — deux sources de configuration seraient une de trop.

```sh
cargo build --release

# 1. Produire la configuration.
./target/release/air-mail-admin config write air-mail.conf \
    --listen 127.0.0.1:2525 \
    --maildir ./maildir \
    --domain mail.example.com \
    --hosted example.com

# 2. La relire, pour vérifier ce qu'elle dit.
./target/release/air-mail-admin config show air-mail.conf

# 3. Servir.
./target/release/air-mail-server --config air-mail.conf

# Et regarder la boîte.
./target/release/air-mail-admin summary ./maildir
```

Le port par défaut **n'est pas 25** : le serveur refuse de s'exécuter en
superutilisateur (C10), et les ports privilégiés s'atteignent par une règle de
redirection du pare-feu.

Sans `--hosted`, il n'accepte de courrier pour personne — un serveur qui
accepterait tout serait un relais ouvert.

### Chiffrer

```sh
./target/release/air-mail-admin config write air-mail.conf \
    --domain mail.example.com --hosted example.com \
    --tls-cert /etc/ams/chaine.pem \
    --tls-key  /etc/ams/cle.pem
```

**Les deux options vont ensemble, ou aucune** : l'une sans l'autre ne veut dire
ni « chiffre » ni « ne chiffre pas », et elle est refusée devant le terminal
plutôt qu'au démarrage. Avec elles, le serveur annonce `STARTTLS` et monte en
TLS 1.3 (`X25519MLKEM768` préféré) ; sans elles, il sert en clair **et ne
l'annonce pas**.

Le serveur **refuse de démarrer si la clé est lisible par tout le monde** —
`chmod o-r` la répare. Le partage par groupe (`0640`, groupe `ssl-cert`) reste
permis : c'est la bonne pratique, pas la mauvaise.

Une mise en garde, mesurée et non supposée : **une paire dépareillée n'est pas
détectée au démarrage**. Le fournisseur pur Rust ne sait pas comparer la clé au
certificat, si bien qu'un renouvellement qui ne remplace qu'un des deux fichiers
donne un serveur qui démarre et dont toutes les poignées de main échouent.

### Des comptes, des boîtes

```sh
printf %s "$MDP" | ./target/release/air-mail-admin account add comptes.bin \
    --login jean --address jean@example.com --address j.dupont@example.com
./target/release/air-mail-admin account list comptes.bin
```

**Le nom du compte est le nom de sa boîte** — `<maildir>/jean/{cur,new,tmp}`. Un
seul champ plutôt que deux : un identifiant et un répertoire qu'on peut faire
diverger finissent par diverger. C'est une frontière de sécurité, et le nom est
donc contrôlé (ni `.`, ni `..`, sans `/`, sans point en tête) à l'écriture comme
à la lecture.

**Seules les adresses déclarées sont acceptées.** `--hosted` ne sert plus à
accepter : c'est la liste de ce que le serveur annonce servir, et elle est
confrontée aux adresses des comptes **au démarrage**. Une adresse dans un domaine
non annoncé est presque toujours une faute de frappe, et le serveur refuse de
démarrer en le disant.

Un compte **sans adresse** est licite : il se connecte, il envoie, il ne reçoit
rien. Et `postmaster` est un compte comme un autre — le serveur avertit au
démarrage si personne ne le reçoit, parce que la RFC 5321 §4.5.1 l'exige.

### Authentifier

```sh
# Le mot de passe se lit sur l'ENTRÉE STANDARD, jamais sur la ligne de commande :
# ce que `ps` affiche, tout le monde le lit.
printf %s "$MDP" | ./target/release/air-mail-admin account add comptes.bin --login jean
./target/release/air-mail-admin account list comptes.bin      # les noms, jamais les empreintes

./target/release/air-mail-admin config write air-mail.conf \
    --domain mail.example.com --hosted example.com \
    --tls-cert /etc/ams/chaine.pem --tls-key /etc/ams/cle.pem \
    --accounts comptes.bin
```

Le magasin sert **deux choses** qu'il faut distinguer : le *routage* — quelles
adresses existent, et vers quelle boîte — qui ne demande aucun chiffrement ; et
l'*authentification*, qui n'est annoncée que sous TLS. Un serveur de courrier
entrant en clair a donc des comptes sans avoir d'`AUTH`.

Le magasin est un **autre fichier**, écrit en `0600` : les comptes et la
configuration ne changent pas au même rythme, ne méritent pas les mêmes
permissions, et une fuite de l'un n'est pas une fuite de l'autre. Le serveur
refuse de démarrer s'il est lisible par tout le monde — ce ne sont que des
empreintes, mais c'est un dictionnaire de noms à essayer.

`--accounts` sans `--tls-cert` est refusé : `AUTH` n'est **jamais** annoncé hors
chiffrement, et ce refus n'est pas réglable.

## Construire

La toolchain est épinglée dans `rust-toolchain.toml` (**Rust 1.98.0**, stable).
`rustup` la sélectionne tout seul dans ce répertoire.

```sh
cargo build --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
```

Le pin est une **version exacte**, pas le canal `stable` : un canal roulant
désigne une version différente toutes les six semaines, et deux mesures prises à
deux mois d'écart ne sont alors plus comparables.

## Vérification

La CI (`.github/workflows/ci.yml`) tourne sur chaque PR et sur `main`, en quatre
jobs indépendants : la vérification du code (les quatre commandes ci-dessus, sous
`-D warnings` et `--locked`), le gate **DCO**, le gate de **couverture**, et un
**smoke-fuzz**.

### Fuzzing (C3)

`fuzz/` est une crate `cargo-fuzz` **hors du workspace** : elle exige un nightly,
que le pin exact du workspace n'admet pas — deux LLVM produisent des profils de
couverture mutuellement illisibles. Dix cibles, quarante-six propriétés, dont un
**aller-retour** sur l'encodeur de réponses, un **vocabulaire de sortie clos** sur
la session, et l'**indépendance au découpage** sur la phase de données — celle qui
vise directement la contrebande SMTP. **Six défauts réels** trouvés et
corrigés, dont deux dans le garde. Voir
[`fuzz/README.md`](fuzz/README.md).

La CI en lance un smoke borné à vingt secondes par cible : un détecteur de
régression, **pas une campagne**.

### Couverture (C2)

`scripts/check-couverture.sh` exige **100 %** sur les treize crates des étages 1
et 2. Le seuil porte sur les **régions** et les **lignes** — pas sur les branches,
que `llvm-cov` n'instrumente pas sur Rust stable et dont le compteur reste à
`0 / 0`. Les régions font le travail attendu : chaque bras d'un conditionnel en
est une.

Le gate mesure aujourd'hui **6 891 régions** et **4 044 lignes**, toutes
couvertes. **Une seule dérogation, et elle est annoncée à chaque exécution** : le
code *généré* du schéma Cap'n Proto en est exclu — il porte un accesseur par champ
et par sens, dont la plupart ne seront jamais appelés, et les couvrir n'éprouverait
aucune de nos décisions. L'exclusion nomme **un fichier**, pas une crate. `ams-loop-tokio` en est **hors** : elle lit, écrit et attend, et y
atteindre 100 % exigerait de simuler les pannes du noyau — on mesurerait alors la
fidélité de la simulation. Il naissait à zéro dette et n'en a pas pris.

```sh
./scripts/check-couverture.sh
./scripts/check-couverture.sh --seuil 95   # pour un diagnostic local
```

### DCO

`scripts/check-dco.sh` examine les commits que la branche **ajoute** (`base..HEAD`,
jamais tout l'historique) et fait échouer sur :

- un commit sans `Signed-off-by:` — le DCO n'est pas certifié (`git commit -s`) ;
- une attribution de paternité à un outil (`Co-Authored-By: Claude …`,
  `Claude-Session:`, « Generated with … », une URL de session). Un outil ne
  co-signe pas, pas plus qu'un compilateur ; seule la signature de l'auteur humain
  fait foi.

Il **signale sans faire échouer** un `Signed-off-by` qui ne nomme pas l'auteur
(légitime pour un patch relayé) et un commit sans signature cryptographique.

Ce qu'il ne peut **pas** faire : dire si une signature est *valide*. `git`
distingue « non signé » de « signé mais invérifiable ici », et un runner de CI n'a
le trousseau de personne — il constate qu'une signature existe, jamais qu'elle est
bonne. La vérification effective relève de la protection de branche GitHub
(`required_signatures`), qui n'est **pas** activée sur ce dépôt à ce jour.

Le script tourne aussi en local :

```sh
./scripts/check-dco.sh            # base : origin/main
./scripts/check-dco.sh main       # ou une base explicite
```

## Dépendances

**Deux dépendances externes** : `tokio` pour la boucle d'entrées-sorties (C5), et
`capnp` pour la configuration binaire (C11) — cette dernière **pure Rust, sans
aucune dépendance transitive**, et compatible `no_std`.
Le graphe de build réel, sur Linux et avec les seules features qui servent, compte
**douze crates transitives, dont sept seulement à l'exécution** — `bytes`,
`errno`, `libc`, `mio`, `pin-project-lite`, `signal-hook-registry`, `socket2`.
Les cinq autres (`tokio-macros` et son outillage proc-macro) compilent pour l'hôte
et n'entrent dans aucun binaire. Le
registre tablait sur vingt-cinq ; `default-features = false` fait toute la
différence, et l'estimation y a été corrigée.

`libc` est déclarée en direct bien que tokio la tire déjà : `refuse_root` (C10)
appelle `geteuid` elle-même, et une dépendance qu'on utilise se déclare.

Les crates des étages 1 et 2 n'en ont **aucune** : elles sont `#![no_std]` sans
`alloc`.

## Licence

[MPL-2.0](LICENSE).
