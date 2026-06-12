#!/usr/bin/env python3
"""
Serveur MCP pour Grafana
=========================
Expose des outils MCP permettant à Claude Code d'interroger :
  - l'API Grafana : dashboards, datasources, alertes
  - la datasource Prometheus (via le proxy Grafana) : métriques temps réel et historiques

Configuration via variables d'environnement (.env) :
  GRAFANA_URL          ex: http://grafana.infraaitoolkit.lan:3000
  GRAFANA_API_TOKEN    token API Grafana (Administration → Service accounts)
  GRAFANA_VERIFY_SSL   "true" / "false" (défaut: false, certifs auto-signés)
"""

import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

import httpx
from dotenv import load_dotenv
from mcp.server.fastmcp import FastMCP

load_dotenv(Path(__file__).parent.parent / ".env")

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

GRAFANA_URL = os.environ.get("GRAFANA_URL", "").rstrip("/")
GRAFANA_TOKEN = os.environ.get("GRAFANA_API_TOKEN", "")
VERIFY_SSL = os.environ.get("GRAFANA_VERIFY_SSL", "false").lower() == "true"

mcp = FastMCP("grafana")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

async def _get(client: httpx.AsyncClient, path: str, params: Optional[dict] = None) -> dict:
    """GET authentifié sur l'API Grafana."""
    if not (GRAFANA_URL and GRAFANA_TOKEN):
        raise RuntimeError(
            "Variables GRAFANA_URL / GRAFANA_API_TOKEN manquantes."
        )
    resp = await client.get(
        f"{GRAFANA_URL}{path}",
        params=params or {},
        headers={"Authorization": f"Bearer {GRAFANA_TOKEN}"},
    )
    resp.raise_for_status()
    return resp.json()


async def _post(client: httpx.AsyncClient, path: str, body: dict) -> dict:
    """POST authentifié sur l'API Grafana."""
    if not (GRAFANA_URL and GRAFANA_TOKEN):
        raise RuntimeError(
            "Variables GRAFANA_URL / GRAFANA_API_TOKEN manquantes."
        )
    resp = await client.post(
        f"{GRAFANA_URL}{path}",
        headers={"Authorization": f"Bearer {GRAFANA_TOKEN}"},
        json=body,
    )
    resp.raise_for_status()
    return resp.json()


async def _get_prometheus_uid(client: httpx.AsyncClient) -> Optional[str]:
    """Trouve l'uid de la datasource Prometheus, ou None si absente."""
    datasources = await _get(client, "/api/datasources")
    prometheus_ds = next((ds for ds in datasources if ds["type"] == "prometheus"), None)
    return prometheus_ds["uid"] if prometheus_ds else None


def _parse_duration(duration: str) -> Optional[timedelta]:
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
# Outils MCP — Dashboards et datasources
# ---------------------------------------------------------------------------

@mcp.tool()
async def list_dashboards() -> str:
    """Liste tous les dashboards Grafana disponibles. Point de départ pour
    explorer ce qui est surveillé visuellement sur l'infrastructure."""
    async with httpx.AsyncClient(verify=VERIFY_SSL, timeout=30) as client:
        data = await _get(client, "/api/search", {"type": "dash-db"})
    if not data:
        return "Aucun dashboard trouvé"
    return "\n".join(f"- {d['title']} (uid: {d['uid']})" for d in data)


@mcp.tool()
async def list_datasources() -> str:
    """Liste toutes les datasources Grafana configurées (Prometheus, etc.)
    avec leur uid. Utile pour savoir quelles métriques sont disponibles."""
    async with httpx.AsyncClient(verify=VERIFY_SSL, timeout=30) as client:
        data = await _get(client, "/api/datasources")
    if not data:
        return "Aucune datasource trouvée"
    return "\n".join(
        f"- {ds['name']} (type: {ds['type']}, uid: {ds['uid']})" for ds in data
    )


@mcp.tool()
async def get_dashboard(uid: str) -> str:
    """Détails d'un dashboard Grafana : titre, panels et leurs requêtes
    PromQL. Utile pour comprendre ce qu'un dashboard surveille exactement.

    Args:
        uid: identifiant du dashboard (obtenu via list_dashboards)
    """
    async with httpx.AsyncClient(verify=VERIFY_SSL, timeout=30) as client:
        data = await _get(client, f"/api/dashboards/uid/{uid}")

    dashboard = data["dashboard"]
    lines = [f"Dashboard: {dashboard['title']} (uid: {uid})"]

    for panel in dashboard.get("panels", []):
        lines.append(f"\nPanel: {panel.get('title', 'Sans titre')} (type: {panel.get('type')})")
        for target in panel.get("targets", []):
            expr = target.get("expr")  # requête PromQL
            if expr:
                lines.append(f"  - query: {expr}")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Outils MCP — Alertes
# ---------------------------------------------------------------------------

@mcp.tool()
async def get_alerts() -> str:
    """Liste les alertes Grafana actives avec leur sévérité et leur statut.
    Idéal pour une vue d'ensemble rapide des incidents en cours côté
    métriques (complémentaire aux alertes Wazuh et aux problèmes Zabbix)."""
    async with httpx.AsyncClient(verify=VERIFY_SSL, timeout=30) as client:
        data = await _get(client, "/api/alertmanager/grafana/api/v2/alerts")

    if not data:
        return "Aucune alerte active"

    lines = []
    for alert in data:
        labels = alert.get("labels", {})
        annotations = alert.get("annotations", {})
        name = labels.get("alertname", "Sans nom")
        severity = labels.get("severity", "unknown")
        state = alert.get("status", {}).get("state", "unknown")
        summary = annotations.get("summary", annotations.get("description", ""))
        starts_at = alert.get("startsAt", "")
        lines.append(f"- [{severity}] {name} ({state}) - {summary} (depuis {starts_at})")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Outils MCP — Métriques Prometheus
# ---------------------------------------------------------------------------

@mcp.tool()
async def query_prometheus(query: str) -> str:
    """Exécute une requête PromQL instantanée sur la datasource Prometheus
    de Grafana et retourne les valeurs courantes. Utile pour un snapshot
    immédiat (ex: CPU, RAM, charge réseau actuelle).

    Args:
        query: expression PromQL, ex: "node_load1", "rate(node_network_receive_bytes_total[5m])"
    """
    async with httpx.AsyncClient(verify=VERIFY_SSL, timeout=30) as client:
        ds_uid = await _get_prometheus_uid(client)
        if ds_uid is None:
            return "Aucune datasource Prometheus trouvée"

        now = datetime.now(timezone.utc)
        body = {
            "queries": [
                {"datasource": {"uid": ds_uid}, "expr": query, "refId": "A", "instant": True}
            ],
            "from": str(int((now - timedelta(minutes=5)).timestamp() * 1000)),
            "to": str(int(now.timestamp() * 1000)),
        }
        data = await _post(client, "/api/ds/query", body)

    frames = data["results"]["A"]["frames"]
    lines = []
    for frame in frames:
        fields = frame["schema"]["fields"]
        values = frame["data"]["values"]
        if len(fields) < 2 or len(values) < 2:
            continue
        labels = fields[1].get("labels", {})
        timestamps, vals = values[0], values[1]
        if not vals:
            continue
        last_ts, last_val = timestamps[-1], vals[-1]
        lines.append(f"- {labels}: {last_val} (at {last_ts})")

    if not lines:
        return "Aucune donnée retournée"
    return "\n".join(lines)


@mcp.tool()
async def query_range_prometheus(query: str, duration: str) -> str:
    """Exécute une requête PromQL sur une période donnée et retourne les
    points de données dans le temps. Utile pour voir l'évolution d'une
    métrique (ex: pic de CPU pendant une attaque, dérive mémoire).

    Args:
        query: expression PromQL, ex: "node_load1", "rate(node_cpu_seconds_total[5m])"
        duration: période — "30m", "1h", "1d", etc.
    """
    delta = _parse_duration(duration)
    if delta is None:
        return f"Durée invalide: {duration} (utilise un format comme '30m', '1h', '1d')"

    now = datetime.now(timezone.utc)
    start = now - delta

    async with httpx.AsyncClient(verify=VERIFY_SSL, timeout=30) as client:
        ds_uid = await _get_prometheus_uid(client)
        if ds_uid is None:
            return "Aucune datasource Prometheus trouvée"

        body = {
            "queries": [
                {
                    "datasource": {"uid": ds_uid},
                    "expr": query,
                    "refId": "A",
                    "range": True,
                    "intervalMs": 60000,
                    "maxDataPoints": 100,
                }
            ],
            "from": str(int(start.timestamp() * 1000)),
            "to": str(int(now.timestamp() * 1000)),
        }
        data = await _post(client, "/api/ds/query", body)

    frames = data["results"]["A"]["frames"]
    if not frames:
        return "Aucune donnée retournée"

    lines = []
    for frame in frames:
        fields = frame["schema"]["fields"]
        values = frame["data"]["values"]
        if len(fields) < 2 or len(values) < 2:
            continue
        labels = fields[1].get("labels", {})
        timestamps, vals = values[0], values[1]
        lines.append(f"Série {labels}:")
        for ts, val in zip(timestamps, vals):
            lines.append(f"  {ts}: {val}")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Entrée
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    mcp.run(transport="stdio")