# Votre messagerie change de serveur

Bonjour,

Le serveur de courrier de `narro.ch` est remplacé **le samedi 12 septembre au
matin**. Vos adresses, vos messages et vos dossiers ne changent pas. Ce document
dit ce que vous avez à faire — et ce n'est pas grand-chose.

---

## En une minute

1. **Votre adresse ne change pas.** Ni vos alias.
2. **Vos anciens messages sont conservés**, avec leurs dossiers, et le fait que
   vous les ayez lus, marqués ou auxquels vous avez répondu.
3. **Vous recevrez un nouveau mot de passe** la veille, vendredi 11. Il faudra
   le saisir dans votre logiciel de messagerie et sur votre téléphone.
4. **Votre logiciel va retélécharger tous vos messages une fois.** C'est normal.
   Sur une grosse boîte, cela peut prendre un long moment.

---

## Le jour de la bascule : samedi 12 septembre, à partir de 9 h

Comptez une coupure d'environ une demi-heure entre 9 h 30 et 10 h. Votre
logiciel affichera pendant ce temps une erreur de connexion, et vous ne pourrez
ni recevoir ni envoyer.

**Aucun message ne sera perdu.** Le courrier qui vous est envoyé pendant cette
période est conservé par le serveur de l'expéditeur, qui réessaie
automatiquement — c'est ainsi que fonctionne le courrier électronique. Il vous
arrivera avec quelques minutes ou quelques heures de retard.

Un message que vous tenteriez d'envoyer pendant la coupure, lui, restera dans
votre logiciel : renvoyez-le simplement une fois la messagerie revenue.

**Vous recevrez votre nouveau mot de passe la veille**, vendredi 11, par un
autre canal que le courriel.

---

## Ce que vous devez faire

### 1. Saisir le nouveau mot de passe

Il vous sera transmis séparément, par un autre canal que le courriel.

Dans votre logiciel, à l'endroit où il vous demande votre mot de passe. Il vous
le redemandera de lui-même après la bascule.

**Sur chaque appareil** : ordinateur, téléphone, tablette. Une seule oubliée, et
elle continuera d'essayer avec l'ancien.

### 1bis. Le remplacer par le vôtre

Celui qu'on vous a transmis est un mot de passe **de passage**. Il a servi à vous
faire entrer ; il n'a pas à rester.

Vous pouvez le changer vous-même, sans passer par personne. Sur un terminal :

    # 1. On échange son mot de passe actuel contre un jeton de session.
    curl -X POST https://mail.narro.ch:8443/v1/tokens \
         -H 'Content-Type: application/json' \
         -d '{"login":"VOTRE-COMPTE","password":"CELUI-QU-ON-VOUS-A-DONNÉ"}'

    # La réponse contient un `token`. On le recopie ci-dessous.
    curl -X PUT https://mail.narro.ch:8443/v1/me/password \
         -H "Authorization: Bearer LE-TOKEN-RECOPIÉ" \
         -H 'Content-Type: application/json' \
         -d '{"current_password":"CELUI-QU-ON-VOUS-A-DONNÉ","password":"LE-VÔTRE"}'

Une réponse vide veut dire que c'est fait. **Ressaisissez alors le nouveau sur
chacun de vos appareils**, comme à l'étape précédente.

Si le terminal ne vous dit rien, demandez simplement qu'on le change pour vous.

Deux choses, pour être exact sur ce que cela veut dire :

- **personne ne peut LIRE votre mot de passe**, pas même l'administrateur. Le
  serveur n'en garde qu'une empreinte, dont on ne revient pas ;
- **l'administrateur peut en POSER un nouveau** sans connaître l'ancien — c'est
  ce qu'est une réinitialisation, et c'est ce qui vous dépanne si vous perdez le
  vôtre. Il vous le transmettra alors comme le premier, par un autre canal que le
  courriel, et vous le remplacerez de nouveau.

### 2. Vérifier vos réglages

Ils ne changent pas, mais vérifiez qu'ils sont bien ceux-ci :

| | Valeur |
|---|---|
| Serveur de réception (IMAP) | `mail.narro.ch` |
| Port IMAP | **993**, chiffrement **SSL/TLS** |
| Serveur d'envoi (SMTP) | `mail.narro.ch` |
| Port d'envoi | **587** avec **STARTTLS**, ou **465** avec **SSL/TLS** |
| Nom d'utilisateur | le même qu'avant |
| Méthode d'authentification | **Mot de passe normal** |

Ce dernier point est le seul qui puisse coincer. Si votre logiciel propose une
liste (« Mot de passe normal », « Mot de passe chiffré », « NTLM »…), choisissez
**« Mot de passe normal »** — parfois écrit « PLAIN » ou « Clair ». Si vous aviez
choisi autre chose, il faudra le changer.

### 3. Laisser votre logiciel travailler

Au premier démarrage, il considérera que vos dossiers sont neufs et retéléchargera
tout. **Ne l'interrompez pas**, et laissez-le branché. Ce n'est nécessaire
qu'une fois.

---

## Questions que vous vous poserez

**Vais-je perdre des messages ?**
Non. Ils sont copiés avant la bascule, et recomptés un par un — dossier par
dossier — juste avant. Si le compte ne tombe pas juste, la bascule n'a pas lieu.

**Et ce que j'ai dans « Envoyés », « Brouillons », « Corbeille » ?**
Conservé aussi, ainsi que tous les dossiers que vous avez créés.

**Mon téléphone va-t-il tout retélécharger aussi ?**
Oui. Faites-le de préférence en Wi-Fi.

**Vais-je pouvoir continuer d'envoyer de grosses pièces jointes ?**
Oui : la limite reste la même qu'aujourd'hui, 50 Mo. Rappelez-vous seulement que
beaucoup de destinataires en acceptent moins.

**Mes règles de tri automatique ?**
Celles de votre logiciel continuent de fonctionner : elles sont chez vous. Si
des règles avaient été posées **sur le serveur**, elles ne seront pas reprises —
vous seriez prévenu individuellement.

**Et si ça se passe mal ?**
Le serveur précédent est conservé intact et peut être remis en service en
quelques minutes. Dans ce cas, votre ANCIEN mot de passe redevient le bon, et
vous seriez prévenu.

---

## Si quelque chose ne marche pas

Avant de nous écrire — ce qui sera difficile si votre messagerie ne marche
pas — vérifiez dans cet ordre :

1. Le nouveau mot de passe, saisi **sans espace** avant ou après.
2. Le port **993** pour la réception, avec **SSL/TLS**.
3. La méthode d'authentification : **« Mot de passe normal »**.
4. Sur téléphone : supprimer le compte et le recréer suffit souvent, et **ne
   perd rien** — les messages sont sur le serveur.

Si cela ne suffit pas, joignez-nous **par téléphone ou par une autre adresse**,
en disant quel logiciel vous employez et le message d'erreur exact.
