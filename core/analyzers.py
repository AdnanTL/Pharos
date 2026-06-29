"""
PHAROS — Analyzers
WHOIS, VirusTotal, géolocalisation IP, chaînes de redirections
"""

import asyncio
import httpx
import socket
import re
from datetime import datetime, timezone


async def analyze_domain(domain: str, vt_key: str = "") -> dict:
    result = {
        "domain":       domain,
        "age_days":     None,
        "created":      None,
        "registrar":    None,
        "dns_resolves": False,
        "vt_malicious": 0,
        "vt_total":     0,
        "flags":        [],
    }

    # Vérifie si le domaine résout via DNS
    try:
        socket.getaddrinfo(domain, None)
        result["dns_resolves"] = True
    except Exception:
        result["flags"].append("Le domaine ne résout pas via DNS")

    # WHOIS pour l'âge du domaine
    try:
        import whois as pywhois
        w        = pywhois.whois(domain)
        creation = w.creation_date
        if isinstance(creation, list):
            creation = creation[0]
        if creation:
            if creation.tzinfo is None:
                creation = creation.replace(tzinfo=timezone.utc)
            age = (datetime.now(timezone.utc) - creation).days
            result["age_days"] = age
            result["created"]  = str(creation)[:10]
            if age < 30:
                result["flags"].append(f"Domaine créé il y a seulement {age} jours !")
            elif age < 90:
                result["flags"].append(f"Domaine récent ({age} jours)")
        result["registrar"] = str(w.registrar or "")[:60]
    except Exception:
        result["flags"].append("WHOIS indisponible")

    # VirusTotal (optionnel — nécessite une clé API)
    if vt_key:
        try:
            async with httpx.AsyncClient(timeout=15) as client:
                resp = await client.get(
                    f"https://www.virustotal.com/api/v3/domains/{domain}",
                    headers={"x-apikey": vt_key},
                )
                if resp.status_code == 200:
                    stats = resp.json().get("data", {}).get("attributes", {}).get(
                        "last_analysis_stats", {})
                    result["vt_malicious"] = stats.get("malicious", 0)
                    result["vt_total"]     = sum(stats.values())
                    if result["vt_malicious"] > 0:
                        result["flags"].append(
                            f"VirusTotal : {result['vt_malicious']}/{result['vt_total']} moteurs le signalent malveillant"
                        )
        except Exception:
            pass

    return result


async def analyze_ip(ip: str, abuseipdb_key: str = "") -> dict:
    result = {
        "ip":              ip,
        "country":         None,
        "city":            None,
        "org":             None,
        "region":          None,
        "lat":             None,
        "lon":             None,
        "hostname":        None,
        "isp":             None,
        "asn":             None,
        "connection_type": None,
        "abuse_score":     0,
        "is_tor":          False,
        "flags":           [],
    }

    # Géolocalisation IP enrichie
    # On récupère les infos les plus utiles affichées par des outils type HostIP :
    # pays, région, ville, coordonnées, FAI/organisation, ASN, reverse DNS.
    try:
        async with httpx.AsyncClient(timeout=10, headers={"User-Agent": "PHAROS/1.0"}) as client:
            resp = await client.get(f"https://monip.lws.fr/api/{ip}")

            if resp.status_code == 200:
                data = resp.json()

                result["country"] = data.get("country") or data.get("country_name")
                result["region"]  = data.get("region") or data.get("region_name")
                result["city"]    = data.get("city")
                result["lat"]     = data.get("latitude") or data.get("lat")
                result["lon"]     = data.get("longitude") or data.get("lon")
                result["hostname"] = data.get("hostname") or data.get("reverse")
                result["isp"]      = data.get("isp")
                result["asn"]      = data.get("asn")
                result["org"]      = (
                    data.get("org")
                    or data.get("organization")
                    or data.get("isp")
                )

                isp_org_blob = " ".join(
                    str(x or "") for x in [
                        result.get("isp"),
                        result.get("org"),
                        result.get("hostname"),
                        result.get("asn"),
                    ]
                ).lower()

                hosting_keywords = [
                    "hetzner", "ovh", "amazon", "aws", "google", "microsoft",
                    "azure", "cloudflare", "digitalocean", "linode", "vultr",
                    "your-server", "datacenter", "server", "hosting"
                ]
                proxy_keywords = [
                    "proxy", "vpn", "tor", "anonymous", "anonymizer"
                ]

                if any(k in isp_org_blob for k in hosting_keywords):
                    result["connection_type"] = "Hébergeur / VPN"
                    result["flags"].append("L'IP appartient à un hébergeur / datacenter connu")
                else:
                    result["connection_type"] = "Résidentiel / inconnu"

                if any(k in isp_org_blob for k in proxy_keywords):
                    result["flags"].append("L'IP semble liée à un proxy / VPN / anonymiseur")

                if result["hostname"] and any(k in result["hostname"].lower() for k in ["static", "clients", "server"]):
                    result["flags"].append("Le reverse DNS suggère une IP d'hébergeur ou de serveur")

    except Exception:
        pass

    # AbuseIPDB (optionnel — nécessite une clé)
    if abuseipdb_key:
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.get(
                    "https://api.abuseipdb.com/api/v2/check",
                    headers={"Key": abuseipdb_key, "Accept": "application/json"},
                    params={"ipAddress": ip, "maxAgeInDays": 90},
                )
                if resp.status_code == 200:
                    data = resp.json().get("data", {})
                    result["abuse_score"] = data.get("abuseConfidenceScore", 0)
                    result["is_tor"]      = data.get("isTor", False)
                    if result["abuse_score"] > 50:
                        result["flags"].append(
                            f"Score d'abus élevé : {result['abuse_score']}/100"
                        )
                    if result["is_tor"]:
                        result["flags"].append("Nœud de sortie Tor !")
                        if result["connection_type"] is None:
                            result["connection_type"] = "Tor"

        except Exception:
            pass

    return result


async def follow_redirects(url: str, max_hops: int = 10) -> list:
    """Suit la chaîne de redirections d'une URL et retourne chaque saut."""
    chain   = []
    current = url
    visited = set()

    async with httpx.AsyncClient(
        timeout=10,
        follow_redirects=False,
        headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0"},
    ) as client:
        for _ in range(max_hops):
            if current in visited:
                chain.append({"url": current, "status": 0, "note": "Boucle détectée"})
                break
            visited.add(current)
            try:
                resp = await client.get(current)
                chain.append({"url": current, "status": resp.status_code, "note": ""})

                if resp.status_code in (301, 302, 303, 307, 308):
                    next_url = resp.headers.get("Location", "")
                    if not next_url:
                        break
                    if next_url.startswith("/"):
                        from urllib.parse import urljoin
                        next_url = urljoin(current, next_url)
                    current = next_url
                else:
                    break
            except Exception as e:
                chain.append({"url": current, "status": 0, "note": str(e)[:80]})
                break

    return chain
