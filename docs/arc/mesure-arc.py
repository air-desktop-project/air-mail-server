#!/usr/bin/env python3
"""Compte, dans le registre de reception, ce qui decide d'ARC :
   - combien de messages portent des en-tetes ARC ;
   - combien echouent en DMARC, et sous quelle politique.
Lu sur l'entree standard : une ligne JSON par enregistrement."""
import json, sys
tr = {"total": 0, "arc": 0, "dmarc_fail": 0, "arc_et_fail": 0}
pol, doms = {}, {}
for ligne in sys.stdin:
    ligne = ligne.strip()
    if not ligne.startswith("{"):
        continue
    try:
        e = json.loads(ligne)
    except Exception:
        continue
    if e.get("type") != "transaction":
        continue
    tr["total"] += 1
    a = bool(e.get("entetes", {}).get("arc"))
    d = e.get("dmarc") or {}
    echec = d.get("resultat") not in ("pass", None, "")
    if a: tr["arc"] += 1
    if echec:
        tr["dmarc_fail"] += 1
        pol[d.get("politique", "?")] = pol.get(d.get("politique", "?"), 0) + 1
        doms[d.get("domaine", "?")] = doms.get(d.get("domaine", "?"), 0) + 1
    if a and echec: tr["arc_et_fail"] += 1
print(f"  messages consignes          : {tr['total']}")
print(f"  portant des en-tetes ARC    : {tr['arc']}")
print(f"  en echec DMARC              : {tr['dmarc_fail']}")
print(f"  ARC *et* echec DMARC        : {tr['arc_et_fail']}   <- ce qu'ARC sauverait")
if pol:  print(f"  politiques vues             : {pol}")
if doms: print(f"  domaines en echec           : {dict(list(doms.items())[:6])}")
