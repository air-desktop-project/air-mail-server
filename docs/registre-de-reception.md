# Le registre de réception — et la confiance d'un message

*Conception, 2026-09-29. Décisions de Thierry DELHAISE : verdict hors du
message (index + API), orange pour les listes, et les quatre points de la
section 7. **Le lot 1 est livré en 0.2.44** — voir la section 10.*

## 1. Ce que c'est, et ce que ce n'est pas

Le registre garde, pour chaque session SMTP et chaque message, **ce que le
serveur savait à cet instant** : qui se connectait, comment le DNS répondait,
ce que TLS a négocié, ce que SPF, DKIM et DMARC ont dit, et le verdict qu'on
en a tiré. Il a deux vocations :

1. **Expliquer après coup** pourquoi tel message a été jugé vert, orange ou
   rouge — et le réévaluer sous des règles plus récentes ;
2. **Juger la réputation d'un MTA émetteur** : une IP, un domaine, un
   opérateur, sur des mois.

**Ce n'est pas un journal.** Un journal se tourne et se jette ; le registre se
**conserve**. Il est structuré, scellé, chaîné, et se relit par un outil.

## 2. Deux contraintes qui décident de la forme

- **Aucun C** (`check-sans-c`) : pas de SQLite. Le format est le nôtre — des
  enregistrements Cap'n Proto, comme la configuration et les appareils.
- **Les fichiers sont la seule source de vérité**, comme pour `ams-index`.
  Les index de recherche (par IP, domaine, Message-ID) et les tables de
  réputation sont **dérivés** et se reconstruisent. Rien ne se modifie : une
  information venue plus tard (RDAP, sonde de retour) **s'ajoute** comme un
  enregistrement d'enrichissement qui renvoie au premier.

## 3. Les enregistrements

Tous portent : le type, l'identifiant de session, l'horodatage UTC à la
milliseconde, la version du serveur.

### 3.1 Session — une connexion, même sans message

| Rubrique | Contenu |
|---|---|
| Identité | identifiant de session ; écoute (25, 465, 587) et adresse locale ; IP et port du pair |
| Temps | connexion, fin de poignée TLS, fin de session |
| DNS inverse, à l'instant | noms PTR ; vérification aller-retour (le nom PTR résout-il vers l'IP ?) ; DNSSEC validé ou non ; TTL ; résolveur ; erreur (NXDOMAIN, SERVFAIL, délai) |
| HELO / EHLO | le nom annoncé tel quel ; syntaxe (nom, littéral d'adresse) ; résout-il, et vers l'IP du pair ? |
| Comportement | parole avant la bannière ; extensions employées (PIPELINING, SIZE, 8BITMIME, SMTPUTF8, CHUNKING) ; nombre de commandes, inconnues, erreurs, RSET, transactions ; tentatives d'AUTH (soumission) |
| TLS | version ; suite ; groupe d'échange ; SNI ; ALPN ; reprise ; certificat client s'il en présente un (empreinte SHA-256, sujet, émetteur, validité) ; empreinte du ClientHello (suites, groupes, algorithmes de signature proposés — ce que `rustls` expose) |
| Protections | seuils d'`ams-guard` atteints ; connexions simultanées de cette IP |
| Issue | fermée proprement, coupée, refusée ; derniers codes de réponse ; raison |
| Pays | pays RIR de l'IP, et la date du fichier de délégation consulté |

### 3.2 Transaction — un message

| Rubrique | Contenu |
|---|---|
| Liens | session ; notre identifiant de message ; **par destinataire, le nom du fichier Maildir** — le lien avec la boîte et l'index |
| Enveloppe | MAIL FROM ; chaque RCPT TO, accepté ou refusé, avec son code ; taille annoncée et réelle ; BODY / SMTPUTF8 |
| En-têtes | Message-ID ; écart `Date:` / réception ; From, Sender, Reply-To ; nombre de destinataires visibles ; List-Id ; List-Unsubscribe ; présence d'ARC ; **condensat** de l'objet (jamais l'objet) |
| SPF | résultat pour MAIL FROM et pour le HELO ; **l'enregistrement à l'instant** ; mécanisme décisif ; nombre de requêtes |
| DKIM (par signature) | d=, s=, algorithme, taille de clef, résultat, en-têtes signés, `l=` ; **la clef publiée à l'instant** |
| DMARC | **l'enregistrement à l'instant** ; alignements SPF et DKIM ; résultat ; disposition appliquée |
| Trajet déclaré | les `Received` analysés saut par saut — **marqués non fiables** : ce sont des indices |
| Logiciel supposé | déduit de l'EHLO, de l'empreinte TLS, des `Received` qu'il a ajoutés, de la forme du Message-ID — avec la règle qui l'a déduit |
| Verdict | couleur ; raisons (codes stables) ; **version du jeu de règles** ; version du serveur |

Garder les **entrées** et la **version des règles** rend chaque verdict
explicable, et réévaluable.

### 3.3 Session sortante — nos remises

Quand nous remettons chez un autre serveur, c'est **lui** qui présente sa
bannière (`220 … ESMTP Postfix`), sa réponse EHLO, **son certificat**, sa
version de TLS. Tout cela s'enregistre : c'est la source fiable du logiciel et
du certificat d'un MTA — gratuite, puisque la connexion a lieu de toute façon.
Plus : MX choisi, DANE / MTA-STS appliqués, codes reçus.

### 3.4 Enrichissement — ce qui arrive après

- **Sonde de retour** (section 7.2) : bannière, EHLO, certificat et TLS du
  port 25 de l'émetteur ;
- **RDAP** : titulaire et date de création du domaine, titulaire de la plage ;
- **Corrections de l'utilisateur** : « faire confiance », « signaler ».

Chacun renvoie à la session ou au message qu'il enrichit.

## 4. L'écriture

- Un **fil d'écriture** et une file bornée, comme le journal d'audit.
- **Le message n'est accepté qu'une fois son enregistrement écrit et
  synchronisé** (section 7.1) : la réponse finale à DATA attend l'écriture,
  regroupée — plusieurs enregistrements par `fsync`.
- Les données viennent de l'extérieur : chaque champ texte est **borné** et
  tronqué au-delà (C3), et la troncature se note.

## 5. Rotation, archivage, intégrité

- **Un fichier par jour UTC** : `registre/AAAA-MM-JJ.amsr`.
- **Scellement à minuit** : un enregistrement final (nombre, condensat
  SHA-256 du fichier) ; le fichier passe en lecture seule.
- **Chaînage** : chaque fichier commence par le condensat du précédent — une
  archive retouchée ou retirée se voit.
- **Signature** Ed25519 du scellement, en option (`ed25519-dalek`, déjà au
  graphe).
- **Paliers** : le mois courant sous `/var/lib/air-mail/registre/` ; les mois
  précédents sous `registre/archives/AAAA/MM/`, compressés (`flate2`, backend
  Rust, déjà au graphe), puis copiés hors de la machine.
- **Aucune suppression, aucune transformation** : tout reste en clair
  (section 7.3).
- Volume estimé : 2 à 4 Kio par message.

## 6. L'exploitation

`air-mail-admin registre …` :

- `cherche` par IP, domaine, adresse, Message-ID, période → JSON ;
- `explique <message>` : le verdict, ses raisons, et ce qui les fondait ;
- `reputation <ip|domaine>` : premier et dernier passage, volume, taux de
  SPF / DKIM / DMARC, répartition des verdicts, logiciels vus ;
- `verifie` : la chaîne et les signatures ;
- `reindexe` : reconstruit les index dérivés.

L'API `/v1` rend aux clients le verdict et ses raisons avec chaque message ;
un toucher sur la pastille montre le trajet.

## 7. Décisions

1. **Registre indisponible → `451`** (refus temporaire). Un message sans trace
   ni verdict n'entre pas ; l'expéditeur réessaie.
2. **Sonde de retour : oui, différée et bornée** — après la réception, jamais
   pendant ; une fois par IP tous les 30 jours au plus ; EHLO puis QUIT, rien
   d'autre ; un débit global plafonné. Réglable, et désactivable.
3. **Tout se garde en clair**, sans limite de durée — adresses et IP
   comprises. Ce sont des données personnelles au sens de la LPD et du RGPD :
   le registre se lit sous le seul compte de service (répertoire `0700`,
   fichiers `0600`), et ses copies hors machine demandent le même soin.
4. **L'objet ne se stocke pas** — seulement son condensat, qui suffit à relier
   les messages d'une même campagne.

## 8. Le verdict

- 🔴 **Rouge** : DMARC `fail` hors liste ; domaine sosie du destinataire ou de
  ses correspondants ; non authentifié ET remis depuis un pays de la liste « à
  risque » ; Reply-To vers un autre domaine ET authentification faible.
- 🟠 **Orange** : DMARC `fail` **sur une liste** (`List-Id`, renvoi) ;
  authentifié mais premier contact ; domaine de moins de 90 jours ; Reply-To ≠
  From ; destinataires non nommés ; envoi de masse sans `List-Unsubscribe` ;
  pays jamais vu pour ce correspondant.
- 🟢 **Vert** — « authentifié et connu », **jamais « sûr »** : DMARC `pass`
  aligné ET (correspondant connu, ou domaine établi sans signal contraire).
- ⚪ **Gris** : non évalué — tout message antérieur au registre.

Les choix de l'utilisateur priment sur les règles.

## 9. Découpage

1. **Registre** : format, écriture, scellement, chaînage, `451`, sessions
   entrantes et transactions avec tout ce que le serveur sait déjà ;
   `registre cherche|verifie`.
2. **Verdict** : règles, pays RIR (fichiers de délégation relus chaque jour),
   exposition par l'API ; `registre explique`.
3. **Sessions sortantes**, empreinte TLS du ClientHello, logiciel supposé.
4. **Premier contact**, domaines sosies, sonde de retour, RDAP différé,
   corrections de l'utilisateur, `registre reputation`.
5. **Archivage** : compression, signature.

## 10. Ce que la 0.2.44 livre (lot 1)

- Le format (`ams-config`, `schema/ams-registre.capnp`, `registre.rs`) :
  trames, entête, sceau, vérification, JSON, analyse des en-têtes — couvert à
  100 %, et fuzzé (`fuzz_ams_registre`). Le fuzz a trouvé, dès sa première
  minute, une liste lue sans borne qui ne se réécrivait pas à l'identique.
- L'écriture (`ams-server`, `registre.rs`) : `sync_data` après chaque trame,
  scellement au premier passage après minuit (une tâche le vérifie chaque
  minute), reprise d'une trame coupée, `451` quand un constat ne s'écrit pas.
- La boucle (`ams-loop-tokio`) : résolution inverse lancée dès l'acceptation
  et attendue avant d'écrire, confirmation aller-retour, nom du `HELO` résolu,
  constat de chaque message — refusé compris — et de chaque session, sauf un
  pair banni.
- L'outil : `air-mail-admin registre verifie|cherche`.

**Pas encore** : l'horodatage de la fin de la poignée TLS, l'empreinte du
ClientHello et le logiciel supposé (lot 3), les sessions sortantes (lot 3),
le pays RIR et le verdict (lot 2). Les champs existent ou s'ajouteront au
schéma sans rien casser.
