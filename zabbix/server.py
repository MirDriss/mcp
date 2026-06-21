#!/usr/bin/env python3
"""
Serveur MCP pour Zabbix
========================
Expose des outils MCP permettant à Claude Code d'interroger :
  - l'API JSON-RPC de Zabbix : hôtes, problèmes, métriques, triggers, tendances

Configuration via variables d'environnement (.env) :
  ZABBIX_URL          ex: https://172.16.0.X/zabbix/api_jsonrpc.php
  ZABBIX_API_TOKEN    token API Zabbix (généré dans Administration → API tokens)
"""

import os
from datetime import datetime, timedelta, timezone
from typing import Optional

import httpx
from mcp.server.fastmcp import FastMCP


from pathlib import Path
from dotenv import load_dotenv

load_dotenv(Path(__file__).parent.parent / ".env")
# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

ZABBIX_URL = os.environ.get("ZABBIX_URL", "")
ZABBIX_TOKEN = os.environ.get("ZABBIX_API_TOKEN", "")

SEVERITY_MAP = {
    "0": "Not classified",
    "1": "Information",
    "2": "Warning",
    "3": "Average",
    "4": "High",
    "5": "Disaster",
}

mcp = FastMCP("zabbix")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

async def _zabbix_call(method: str, params: dict):
    """Appelle l'API Zabbix JSON-RPC, authentifiée via token API (Bearer)."""
    if not (ZABBIX_URL and ZABBIX_TOKEN):
        raise RuntimeError(
            "Variables ZABBIX_URL / ZABBIX_API_TOKEN manquantes."
        )
    body = {
        "jsonrpc": "2.0",
        "method": method,
        "params": params,
        "id": 1,
    }
    async with httpx.AsyncClient(verify=False, timeout=30) as client:
        resp = await client.post(
            ZABBIX_URL,
            headers={
                "Content-Type": "application/json-rpc",
                "Authorization": f"Bearer {ZABBIX_TOKEN}",
            },
            json=body,
        )
        resp.raise_for_status()
        data = resp.json()

    if "error" in data:
        err = data["error"]
        raise RuntimeError(
            f"Erreur API Zabbix ({err.get('message')}): {err.get('data')}"
        )
    return data["result"]


async def _find_host(host: str) -> dict | None:
    """Trouve un hôte par son nom technique ou son nom visible."""
    hosts = await _zabbix_call("host.get", {
        "output": ["hostid", "host", "name"],
        "filter": {"host": [host]},
    })
    if not hosts:
        hosts = await _zabbix_call("host.get", {
            "output": ["hostid", "host", "name"],
            "search": {"name": host},
        })
    return hosts[0] if hosts else None


def _parse_duration(duration: str) -> timedelta | None:
    """Parse une durée type '30m', '1h', '7d'."""
    unit = duration[-1]
    try:
        amount = int(duration[:-1])
    except ValueError:
        return None
    if unit == "m":
        return timedelta(minutes=amount)
    if unit == "h":
        return timedelta(hours=amount)
    if unit == "d":
        return timedelta(days=amount)
    return None


# ---------------------------------------------------------------------------
# Outils MCP — Hôtes
# ---------------------------------------------------------------------------

@mcp.tool()
async def list_hosts() -> str:
    """Liste tous les hôtes surveillés par Zabbix avec leur statut et
    leur disponibilité. Point de départ pour identifier les machines
    à investiguer."""
    hosts = await _zabbix_call("host.get", {
        "output": ["hostid", "host", "name", "status"],
        "selectInterfaces": ["available"],
    })
    if not hosts:
        return "Aucun hôte trouvé"

    lines = []
    for h in hosts:
        status = "activé" if h["status"] == "0" else "désactivé"
        avail_states = {i["available"] for i in h.get("interfaces", [])}
        if "2" in avail_states:
            avail = "indisponible"
        elif "1" in avail_states:
            avail = "disponible"
        else:
            avail = "inconnu"
        lines.append(
            f"- {h['name']} (hostid: {h['hostid']}, "
            f"status: {status}, availability: {avail})"
        )
    return "\n".join(lines)


@mcp.tool()
async def get_host_groups() -> str:
    """Liste tous les groupes d'hôtes Zabbix et les machines qu'ils contiennent.
    Utile pour comprendre l'organisation de l'infrastructure surveillée."""
    groups = await _zabbix_call("hostgroup.get", {
        "output": ["groupid", "name"],
        "selectHosts": ["host"],
    })
    if not groups:
        return "Aucun groupe d'hôtes trouvé"

    lines = []
    for g in groups:
        hosts = ", ".join(h["host"] for h in g.get("hosts", [])) or "aucun hôte"
        lines.append(f"- {g['name']} (groupid: {g['groupid']}): {hosts}")
    return "\n".join(lines)


@mcp.tool()
async def get_host_inventory(host: str) -> str:
    """Détails d'inventaire d'un hôte : OS, matériel, rôle, etc.
    Nécessite que le mode inventaire soit activé dans Zabbix pour cet hôte.

    Args:
        host: nom technique ou nom visible de l'hôte, ex: "k3s-master"
    """
    hosts = await _zabbix_call("host.get", {
        "output": ["hostid", "host", "name"],
        "filter": {"host": [host]},
        "selectInventory": "extend",
    })
    if not hosts:
        hosts = await _zabbix_call("host.get", {
            "output": ["hostid", "host", "name"],
            "search": {"name": host},
            "selectInventory": "extend",
        })
    if not hosts:
        return f"Hôte '{host}' introuvable"

    h = hosts[0]
    inventory = h.get("inventory")
    if not inventory:
        return f"Mode d'inventaire désactivé pour {h['name']}"

    fields = {k: v for k, v in inventory.items() if v}
    if not fields:
        return f"Inventaire vide pour {h['name']}"

    lines = [f"Inventaire de {h['name']}:"]
    for k, v in fields.items():
        lines.append(f"  {k}: {v}")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Outils MCP — Problèmes et triggers
# ---------------------------------------------------------------------------

@mcp.tool()
async def get_problems() -> str:
    """Liste les problèmes Zabbix actifs avec leur sévérité et l'hôte concerné.
    Idéal pour une vue d'ensemble rapide des incidents en cours."""
    problems = await _zabbix_call("problem.get", {
        "output": ["eventid", "name", "severity", "clock", "objectid"],
        "recent": False,
        "sortfield": ["eventid"],
        "sortorder": "DESC",
    })
    if not problems:
        return "Aucun problème actif"

    triggerids = list({p["objectid"] for p in problems if p.get("objectid")})
    host_by_trigger = {}
    if triggerids:
        triggers = await _zabbix_call("trigger.get", {
            "output": ["triggerid"],
            "triggerids": triggerids,
            "selectHosts": ["host"],
        })
        for t in triggers:
            if t.get("hosts"):
                host_by_trigger[t["triggerid"]] = t["hosts"][0]["host"]

    lines = []
    for p in problems:
        host = host_by_trigger.get(p.get("objectid"), "?")
        severity = SEVERITY_MAP.get(p["severity"], p["severity"])
        started = datetime.fromtimestamp(
            int(p["clock"]), tz=timezone.utc
        ).isoformat()
        lines.append(
            f"- [{severity}] {p['name']} sur {host} (depuis {started})"
        )
    return "\n".join(lines)


@mcp.tool()
async def get_triggers(host: str) -> str:
    """Liste les triggers (seuils d'alerte) configurés pour un hôte,
    avec leur état actuel. Utile pour savoir ce qui est surveillé et
    ce qui est en cours de déclenchement.

    Args:
        host: nom technique ou nom visible de l'hôte, ex: "k3s-worker1"
    """
    h = await _find_host(host)
    if h is None:
        return f"Hôte '{host}' introuvable"

    triggers = await _zabbix_call("trigger.get", {
        "output": ["triggerid", "description", "priority", "status", "value", "expression"],
        "hostids": h["hostid"],
        "expandExpression": True,
    })
    if not triggers:
        return f"Aucun trigger configuré pour {h['name']}"

    lines = [f"Triggers de {h['name']} (hostid: {h['hostid']}):"]
    for t in triggers:
        severity = SEVERITY_MAP.get(t["priority"], t["priority"])
        state = "activé" if t["status"] == "0" else "désactivé"
        firing = "EN COURS" if t["value"] == "1" else "ok"
        lines.append(f"- [{severity}] {t['description']} ({state}, état: {firing})")
        lines.append(f"    expression: {t['expression']}")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Outils MCP — Métriques
# ---------------------------------------------------------------------------

@mcp.tool()
async def get_host_items(host: str) -> str:
    """Dernières valeurs de toutes les métriques surveillées pour un hôte :
    CPU, RAM, disque, réseau, etc. Utile pour avoir un snapshot instantané
    de l'état d'une machine.

    Args:
        host: nom technique ou nom visible de l'hôte, ex: "k3s-master"
    """
    h = await _find_host(host)
    if h is None:
        return f"Hôte '{host}' introuvable"

    items = await _zabbix_call("item.get", {
        "output": ["itemid", "name", "key_", "lastvalue", "lastclock", "units"],
        "hostids": h["hostid"],
        "monitored": True,
    })
    if not items:
        return f"Aucun item surveillé pour {h['name']}"

    lines = [f"Items de {h['name']} (hostid: {h['hostid']}):"]
    for it in items:
        lines.append(
            f"- {it['name']} (itemid: {it['itemid']}, key: {it['key_']}): "
            f"{it['lastvalue']} {it.get('units', '')}"
        )
    return "\n".join(lines)


@mcp.tool()
async def get_item_history(itemid: str, duration: str) -> str:
    """Historique brut des valeurs d'une métrique sur une période récente.
    Utile pour voir l'évolution d'un indicateur dans le temps.

    Args:
        itemid: identifiant de la métrique (obtenu via get_host_items)
        duration: période — "30m", "1h", "6h", "1d", etc.
    """
    delta = _parse_duration(duration)
    if delta is None:
        return f"Durée invalide: {duration} (utilise un format comme '30m', '1h', '1d')"

    items = await _zabbix_call("item.get", {
        "output": ["itemid", "name", "value_type", "units"],
        "itemids": itemid,
    })
    if not items:
        return f"Item {itemid} introuvable"
    item = items[0]

    now = datetime.now(timezone.utc)
    start = now - delta

    history = await _zabbix_call("history.get", {
        "output": "extend",
        "history": int(item["value_type"]),
        "itemids": itemid,
        "time_from": int(start.timestamp()),
        "time_till": int(now.timestamp()),
        "sortfield": "clock",
        "sortorder": "ASC",
    })
    if not history:
        return "Aucune donnée historique sur cette période"

    lines = [f"Historique de {item['name']} (itemid: {itemid}):"]
    for point in history:
        ts = datetime.fromtimestamp(
            int(point["clock"]), tz=timezone.utc
        ).isoformat()
        lines.append(f"  {ts}: {point['value']} {item.get('units', '')}")
    return "\n".join(lines)


@mcp.tool()
async def get_trends(itemid: str, duration: str) -> str:
    """Tendances horaires long-terme d'une métrique (min/avg/max) pour
    la capacité et la prévision. Idéal pour détecter une dérive progressive
    (ex: disque qui se remplit, RAM qui augmente).

    Args:
        itemid: identifiant de la métrique (obtenu via get_host_items)
        duration: période longue — "7d", "30d", etc.
    """
    delta = _parse_duration(duration)
    if delta is None:
        return f"Durée invalide: {duration} (utilise un format comme '7d', '30d')"

    items = await _zabbix_call("item.get", {
        "output": ["itemid", "name", "units"],
        "itemids": itemid,
    })
    if not items:
        return f"Item {itemid} introuvable"
    item = items[0]

    now = datetime.now(timezone.utc)
    start = now - delta

    trends = await _zabbix_call("trend.get", {
        "output": "extend",
        "itemids": itemid,
        "time_from": int(start.timestamp()),
        "time_till": int(now.timestamp()),
        "sortfield": "clock",
        "sortorder": "ASC",
    })
    if not trends:
        return (
            "Aucune donnée de tendance sur cette période "
            "(item non numérique ou historique insuffisant)"
        )

    lines = [f"Tendances de {item['name']} (itemid: {itemid}):"]
    for tr in trends:
        ts = datetime.fromtimestamp(int(tr["clock"]), tz=timezone.utc).isoformat()
        lines.append(
            f"  {ts}: min={tr['value_min']} avg={tr['value_avg']} "
            f"max={tr['value_max']} {item.get('units', '')}"
        )
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Entrée
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    mcp.run(transport="stdio")