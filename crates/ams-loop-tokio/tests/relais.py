"""Un faux relais de sortie : TLS implicite, AUTH PLAIN exigé."""
import base64, socket, ssl, sys, threading

port, cert, cle, mode = int(sys.argv[1]), sys.argv[2], sys.argv[3], sys.argv[4]
ATTENDU = base64.b64encode(b"\0jean\0secret").decode()
recu = []

def servir(flux):
    f = flux.makefile("rwb")
    def dire(t): flux.sendall(t.encode() + b"\r\n")
    dire("220 relais.essai.test ESMTP")
    authentifie = False
    while True:
        ligne = f.readline()
        if not ligne: return
        cmd = ligne.decode("latin1").strip()
        haut = cmd.upper()
        if haut.startswith("EHLO"):
            dire("250-relais.essai.test")
            if mode == "sans-auth": dire("250 SIZE 52428800")
            else: dire("250-SIZE 52428800"); dire("250 AUTH PLAIN LOGIN")
        elif haut.startswith("AUTH PLAIN"):
            jeton = cmd.split(None, 2)[2] if len(cmd.split(None, 2)) > 2 else ""
            if mode == "refuse": dire("535 5.7.8 Authentication credentials invalid")
            elif jeton == ATTENDU: authentifie = True; dire("235 2.7.0 Authentication successful")
            else: dire("535 5.7.8 mauvais jeton : " + jeton[:20])
        elif haut.startswith("MAIL FROM"):
            dire("250 2.1.0 Ok" if authentifie else "530 5.7.0 Authentication required")
        elif haut.startswith("RCPT TO"):
            dire("250 2.1.5 Ok" if authentifie else "530 5.7.0 Authentication required")
        elif haut.startswith("DATA"):
            dire("354 End data with <CR><LF>.<CR><LF>")
            corps = b""
            while True:
                l = f.readline()
                if not l or l == b".\r\n": break
                corps += l
            recu.append(corps); dire("250 2.0.0 Ok: queued")
        elif haut.startswith("QUIT"): dire("221 Bye"); return
        else: dire("250 Ok")

ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.load_cert_chain(cert, cle)
srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", port)); srv.listen(5)
print(f"relais sur 127.0.0.1:{srv.getsockname()[1]}", flush=True)
while True:
    brut, _ = srv.accept()
    try:
        with ctx.wrap_socket(brut, server_side=True) as flux: servir(flux)
    except Exception as e: print("  session :", type(e).__name__, e, flush=True)
    if recu: print(f"  REÇU {len(recu[-1])} octets", flush=True)
