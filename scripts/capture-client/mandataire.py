#!/usr/bin/env python3
"""Un mandataire qui note tout ce qui passe, dans les deux sens.

EN CLAIR du côté de Thunderbird, EN TLS du côté du serveur. C'est ce qui évite
d'avoir à faire accepter un certificat auto-signé à un client qui a de bonnes
raisons de le refuser — et cela ne change rien à ce qu'on mesure : le serveur
voit une vraie session TLS, et les commandes sont bien celles de Thunderbird.

Le but n'est pas d'éprouver le mandataire, mais d'obtenir les octets EXACTS
qu'un vrai client envoie, pour en faire un essai rejouable — comme `interop.rs`
le fait déjà pour Postfix.
"""
import datetime
import socket
import ssl
import sys
import threading

ecoute_port, serveur_port, ou = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3]
journal = open(ou, "w", buffering=1, encoding="utf-8", errors="replace")
verrou = threading.Lock()


def noter(sens, octets):
    with verrou:
        journal.write(f"{sens} {octets!r}\n")


def pomper(source, cible, sens):
    try:
        while True:
            octets = source.recv(65536)
            if not octets:
                break
            noter(sens, octets)
            cible.sendall(octets)
    except OSError:
        pass
    finally:
        for prise in (source, cible):
            try:
                prise.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass


amont = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
amont.check_hostname = False
amont.verify_mode = ssl.CERT_NONE

ecoute = socket.socket()
ecoute.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
ecoute.bind(("127.0.0.1", ecoute_port))
ecoute.listen(8)
print(f"mandataire : {ecoute_port} (clair) → {serveur_port} (TLS)", flush=True)

while True:
    client, _ = ecoute.accept()
    try:
        serveur = amont.wrap_socket(
            socket.create_connection(("127.0.0.1", serveur_port)),
            server_hostname="localhost",
        )
    except OSError as faute:
        noter("!!", f"amont injoignable : {faute}".encode())
        client.close()
        continue
    noter("--", f"connexion {datetime.datetime.now():%H:%M:%S}".encode())
    threading.Thread(target=pomper, args=(client, serveur, "C>"), daemon=True).start()
    threading.Thread(target=pomper, args=(serveur, client, "S>"), daemon=True).start()
