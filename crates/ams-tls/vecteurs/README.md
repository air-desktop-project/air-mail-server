# Vecteurs : trois certificats, fabriqués une fois

Ces trois fichiers DER servent aux essais de `relay.rs`, et **ne sortent jamais
du dépôt** : aucune clé privée n'est ici, et aucun de ces certificats n'est
présenté par quoi que ce soit.

Ils sont **fabriqués une fois et versionnés**, plutôt qu'engendrés par
`openssl` au moment de l'essai. Trois raisons :

1. **`ams-tls` est soumise au 100 % de couverture (C2).** Un essai qui se saute
   quand `openssl` manque laisserait la mesure sous le seuil sur une machine et
   au-dessus sur une autre — c'est-à-dire un gate qui ne dit plus rien.
2. **Un vérificateur DANE se juge sur des octets précis.** Un certificat
   réengendré à chaque exécution change d'empreinte, et l'on ne pourrait plus
   écrire l'empreinte attendue dans l'essai.
3. Ils sont **petits** — quelques centaines d'octets — et leur validité court
   jusqu'en 2126 : aucun essai ne tombera un matin parce qu'une date a passé.

| Fichier | Ce que c'est |
| --- | --- |
| `ca.der` | Une autorité auto-signée, `CA:TRUE`, `CN=ams-dane-ca`. |
| `leaf.der` | `CN=mx.example.test`, SAN `DNS:mx.example.test`, signé par `ca.der`. |
| `solo.der` | Auto-signé, `CN=solo.example.test` — pour `DANE-EE(3)`, qui n'a besoin d'aucune chaîne. |

Tous en ECDSA P-256/SHA-256, l'algorithme que le fournisseur du produit vérifie.

Refabriquer (les empreintes des essais changeront) :

```sh
openssl ecparam -name prime256v1 -genkey -noout -out ca.key
openssl req -new -x509 -key ca.key -sha256 -days 36500 -subj "/CN=ams-dane-ca" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" -out ca.pem
openssl ecparam -name prime256v1 -genkey -noout -out leaf.key
openssl req -new -key leaf.key -subj "/CN=mx.example.test" -out leaf.csr
printf 'subjectAltName=DNS:mx.example.test\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\n' > leaf.ext
openssl x509 -req -in leaf.csr -CA ca.pem -CAkey ca.key -CAcreateserial -days 36500 \
    -sha256 -extfile leaf.ext -out leaf.pem
openssl ecparam -name prime256v1 -genkey -noout -out solo.key
openssl req -new -x509 -key solo.key -sha256 -days 36500 -subj "/CN=solo.example.test" \
    -addext "subjectAltName=DNS:solo.example.test" -out solo.pem
for n in ca leaf solo; do openssl x509 -in $n.pem -outform DER -out $n.der; done
```
