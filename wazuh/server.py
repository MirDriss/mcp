#!/usr/bin/env python3
"""
Serveur MCP pour Wazuh
======================
Expose des outils MCP permettant à Claude Code d'interroger :
  - l'API du manager Wazuh (port 55000) : agents, SCA, infos manager
  - l'indexer Wazuh / OpenSearch (port 9200) : alertes, vulnérabilités (4.8+)

Configuration via variables d'environnement (voir .env.example) :
  WAZUH_API_URL          ex: https://10.0.0.10:55000
  WAZUH_API_USER         utilisateur API (ex: wazuh-mcp)
  WAZUH_API_PASSWORD     mot de passe API
  WAZUH_INDEXER_URL      ex: https://10.0.0.10:9200   (optionnel)
  WAZUH_INDEXER_USER     ex: admin                     (optionnel)
  WAZUH_INDEXER_PASSWORD                               (optionnel)
  WAZUH_VERIFY_SSL       "true" / "false" (défaut: false, certifs auto-signés)
"""

import json
import os
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

import httpx
from mcp.server.fastmcp import FastMCP

from pathlib import Path
from dotenv import load_dotenv

load_dotenv(Path(__file__).parent.parent / ".env")

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

API_URL = os.environ.get("WAZUH_API_URL", "").rstrip("/")
API_USER = os.environ.get("WAZUH_API_USER", "")
API_PASSWORD = os.environ.get("WAZUH_API_PASSWORD", "")

INDEXER_URL = os.environ.get("WAZUH_INDEXER_URL", "").rstrip("/")
INDEXER_USER = os.environ.get("WAZUH_INDEXER_USER", "")
INDEXER_PASSWORD = os.environ.get("WAZUH_INDEXER_PASSWORD", "")

VERIFY_SSL = os.environ.get("WAZUH_VERIFY_SSL", "false").lower() == "true"

mcp = FastMCP("wazuh")

# Cache du token JWT (validité ~900 s côté Wazuh)
_token_cache: dict[str, Any] = {"token": None, "expires_at": 0.0}


# ---------------------------------------------------------------------------
# Helpers - API manager
# ---------------------------------------------------------------------------

async def _get_token(client: httpx.AsyncClient) -> str:
    """Récupère (et met en cache) un token JWT auprès de l'API Wazuh."""
    now = time.time()
    if _token_cache["token"] and now < _token_cache["expires_at"]:
        return _token_cache["token"]

    if not (API_URL and API_USER and API_PASSWORD):
        raise RuntimeError(
            "Variables WAZUH_API_URL / WAZUH_API_USER / WAZUH_API_PASSWORD manquantes."
        )

    resp = await client.post(
        f"{API_URL}/security/user/authenticate",
        auth=(API_USER, API_PASSWORD),
    )
    resp.raise_for_status()
    token = resp.json()["data"]["token"]
    _token_cache["token"] = token
    _token_cache["expires_at"] = now + 780
    return token


async def _api_get(path: str, params: Optional[dict] = None) -> dict:
    """GET authentifié sur l'API du manager Wazuh."""
    async with httpx.AsyncClient(verify=VERIFY_SSL, timeout=30) as client:
        token = await _get_token(client)
        resp = await client.get(
            f"{API_URL}{path}",
            params=params or {},
            headers={"Authorization": f"Bearer {token}"},
        )
        if resp.status_code == 401:
            _token_cache["token"] = None
            token = await _get_token(client)
            resp = await client.get(
                f"{API_URL}{path}",
                params=params or {},
                headers={"Authorization": f"Bearer {token}"},
            )
        resp.raise_for_status()
        return resp.json()


# ---------------------------------------------------------------------------
# Helpers - Indexer (OpenSearch)
# ---------------------------------------------------------------------------

async def _indexer_search(index: str, body: dict) -> dict:
    """POST _search sur l'indexer Wazuh."""
    if not (INDEXER_URL and INDEXER_USER and INDEXER_PASSWORD):
        raise RuntimeError(
            "Indexer non configuré : définis WAZUH_INDEXER_URL, "
            "WAZUH_INDEXER_USER et WAZUH_INDEXER_PASSWORD."
        )
    async with httpx.AsyncClient(verify=VERIFY_SSL, timeout=30) as client:
        resp = await client.post(
            f"{INDEXER_URL}/{index}/_search",
            json=body,
            auth=(INDEXER_USER, INDEXER_PASSWORD),
        )
        resp.raise_for_status()
        return resp.json()


def _fmt(data: Any) -> str:
    """Sérialise proprement pour le retour MCP."""
    return json.dumps(data, indent=2, ensure_ascii=False, default=str)


def _time_range_filter(hours_back: int) -> dict:
    since = (datetime.now(timezone.utc) - timedelta(hours=hours_back)).isoformat()
    return {"range": {"timestamp": {"gte": since}}}


# ---------------------------------------------------------------------------
# Outils MCP — Manager / agents
# ---------------------------------------------------------------------------

@mcp.tool()
async def get_manager_info() -> str:
    """Retourne les informations du manager Wazuh : version, type d'installation,
    chemins, date de compilation. Utile pour vérifier la connectivité de l'API."""
    data = await _api_get("/manager/info")
    return _fmt(data.get("data", data))


@mcp.tool()
async def get_agents(
    status: Optional[str] = None,
    search: Optional[str] = None,
    limit: int = 50,
    offset: int = 0,
) -> str:
    """Liste les agents Wazuh enregistrés.

    Args:
        status: filtre par état — "active", "disconnected", "never_connected", "pending"
        search: recherche libre (nom, IP, OS...)
        limit: nombre max de résultats (défaut 50, max 500)
        offset: pagination
    """
    params: dict[str, Any] = {
        "limit": min(limit, 500),
        "offset": offset,
        "select": "id,name,ip,status,os.name,os.version,version,lastKeepAlive,group",
    }
    if status:
        params["status"] = status
    if search:
        params["search"] = search
    data = await _api_get("/agents", params)
    return _fmt(data.get("data", data))


@mcp.tool()
async def get_agents_summary() -> str:
    """Résumé global de l'état des agents : nombre d'agents actifs,
    déconnectés, en attente, jamais connectés."""
    data = await _api_get("/agents/summary/status")
    return _fmt(data.get("data", data))


@mcp.tool()
async def get_agent_details(agent_id: str) -> str:
    """Détails complets d'un agent (OS, version, groupes, dernière activité).

    Args:
        agent_id: identifiant numérique de l'agent, ex: "001"
    """
    data = await _api_get("/agents", {"agents_list": agent_id})
    return _fmt(data.get("data", data))


@mcp.tool()
async def get_sca_results(agent_id: str, limit: int = 25) -> str:
    """Résultats SCA (Security Configuration Assessment) d'un agent :
    politiques évaluées, score de conformité, nombre de checks pass/fail.

    Args:
        agent_id: identifiant de l'agent, ex: "001"
        limit: nombre max de politiques retournées
    """
    data = await _api_get(f"/sca/{agent_id}", {"limit": limit})
    return _fmt(data.get("data", data))


@mcp.tool()
async def get_sca_checks(
    agent_id: str,
    policy_id: str,
    result: Optional[str] = None,
    limit: int = 50,
) -> str:
    """Détail des checks SCA d'une politique pour un agent.

    Args:
        agent_id: identifiant de l'agent, ex: "001"
        policy_id: id de la politique SCA (obtenu via get_sca_results), ex: "cis_ubuntu22-04"
        result: filtre — "passed", "failed" ou "not applicable"
        limit: nombre max de checks retournés
    """
    params: dict[str, Any] = {"limit": limit}
    if result:
        params["result"] = result
    data = await _api_get(f"/sca/{agent_id}/checks/{policy_id}", params)
    return _fmt(data.get("data", data))


# ---------------------------------------------------------------------------
# Outils MCP — Alertes (indexer)
# ---------------------------------------------------------------------------

@mcp.tool()
async def search_alerts(
    query: Optional[str] = None,
    min_level: int = 0,
    agent_name: Optional[str] = None,
    rule_group: Optional[str] = None,
    hours_back: int = 24,
    limit: int = 20,
) -> str:
    """Recherche dans les alertes Wazuh (index wazuh-alerts-*).

    Args:
        query: requête libre type query_string, ex: "ssh AND failed"
        min_level: niveau de règle minimum (0-15). 12+ = critique
        agent_name: filtrer sur un agent précis
        rule_group: filtrer sur un groupe de règles, ex: "authentication_failed"
        hours_back: fenêtre temporelle en heures (défaut 24)
        limit: nombre max d'alertes retournées (défaut 20)
    """
    must: list[dict] = [_time_range_filter(hours_back)]
    if query:
        must.append({"query_string": {"query": query}})
    if min_level > 0:
        must.append({"range": {"rule.level": {"gte": min_level}}})
    if agent_name:
        must.append({"term": {"agent.name": agent_name}})
    if rule_group:
        must.append({"term": {"rule.groups": rule_group}})

    body = {
        "size": min(limit, 100),
        "sort": [{"timestamp": {"order": "desc"}}],
        "query": {"bool": {"must": must}},
        "_source": [
            "timestamp", "agent.name", "agent.ip", "rule.id", "rule.level",
            "rule.description", "rule.groups", "rule.mitre", "full_log",
            "data.srcip", "data.srcuser", "location",
        ],
    }
    data = await _indexer_search("wazuh-alerts-*", body)
    hits = data.get("hits", {})
    out = {
        "total": hits.get("total", {}).get("value", 0),
        "alerts": [h["_source"] for h in hits.get("hits", [])],
    }
    return _fmt(out)


@mcp.tool()
async def get_alert_stats(hours_back: int = 24, min_level: int = 0) -> str:
    """Statistiques agrégées des alertes : top règles déclenchées, top agents,
    répartition par niveau de sévérité. Idéal pour une vue d'ensemble rapide.

    Args:
        hours_back: fenêtre temporelle en heures (défaut 24)
        min_level: ne compter que les alertes de niveau >= min_level
    """
    must: list[dict] = [_time_range_filter(hours_back)]
    if min_level > 0:
        must.append({"range": {"rule.level": {"gte": min_level}}})

    body = {
        "size": 0,
        "query": {"bool": {"must": must}},
        "aggs": {
            "top_rules": {
                "terms": {"field": "rule.description", "size": 10}
            },
            "top_agents": {
                "terms": {"field": "agent.name", "size": 10}
            },
            "by_level": {
                "terms": {"field": "rule.level", "size": 16}
            },
        },
    }
    data = await _indexer_search("wazuh-alerts-*", body)
    aggs = data.get("aggregations", {})
    out = {
        "total_alerts": data.get("hits", {}).get("total", {}).get("value", 0),
        "top_rules": [
            {"rule": b["key"], "count": b["doc_count"]}
            for b in aggs.get("top_rules", {}).get("buckets", [])
        ],
        "top_agents": [
            {"agent": b["key"], "count": b["doc_count"]}
            for b in aggs.get("top_agents", {}).get("buckets", [])
        ],
        "by_level": sorted(
            (
                {"level": b["key"], "count": b["doc_count"]}
                for b in aggs.get("by_level", {}).get("buckets", [])
            ),
            key=lambda x: x["level"],
            reverse=True,
        ),
    }
    return _fmt(out)


# ---------------------------------------------------------------------------
# Outils MCP — Vulnérabilités
# ---------------------------------------------------------------------------

@mcp.tool()
async def get_vulnerabilities(
    agent_name: Optional[str] = None,
    severity: Optional[str] = None,
    cve: Optional[str] = None,
    limit: int = 25,
) -> str:
    """Liste les vulnérabilités détectées (Wazuh 4.8+ : index
    wazuh-states-vulnerabilities-* de l'indexer ; fallback automatique sur
    l'API du manager pour les versions < 4.8).

    Args:
        agent_name: filtrer sur un agent précis
        severity: "Critical", "High", "Medium" ou "Low"
        cve: rechercher un CVE précis, ex: "CVE-2024-3094"
        limit: nombre max de résultats
    """
    try:
        must: list[dict] = []
        if agent_name:
            must.append({"term": {"agent.name": agent_name}})
        if severity:
            must.append({"term": {"vulnerability.severity": severity}})
        if cve:
            must.append({"term": {"vulnerability.id": cve}})

        body = {
            "size": min(limit, 100),
            "query": {"bool": {"must": must}} if must else {"match_all": {}},
            "_source": [
                "agent.name", "vulnerability.id", "vulnerability.severity",
                "vulnerability.score", "vulnerability.description",
                "package.name", "package.version", "vulnerability.detected_at",
            ],
            "sort": [{"vulnerability.score.base": {"order": "desc", "unmapped_type": "float"}}],
        }
        data = await _indexer_search("wazuh-states-vulnerabilities-*", body)
        hits = data.get("hits", {})
        out = {
            "source": "indexer (wazuh-states-vulnerabilities-*)",
            "total": hits.get("total", {}).get("value", 0),
            "vulnerabilities": [h["_source"] for h in hits.get("hits", [])],
        }
        return _fmt(out)
    except Exception as indexer_err:
        if not agent_name:
            return _fmt({
                "error": "Indexer indisponible et l'API manager (< 4.8) exige un "
                         "agent_id. Réessaie en précisant agent_name avec l'ID de "
                         "l'agent (ex: '001').",
                "indexer_error": str(indexer_err),
            })
        try:
            params: dict[str, Any] = {"limit": limit}
            if severity:
                params["severity"] = severity
            if cve:
                params["cve"] = cve
            data = await _api_get(f"/vulnerability/{agent_name}", params)
            return _fmt({
                "source": "API manager (/vulnerability)",
                "data": data.get("data", data),
            })
        except Exception as api_err:
            return _fmt({
                "error": "Échec via l'indexer ET via l'API manager.",
                "indexer_error": str(indexer_err),
                "api_error": str(api_err),
            })


@mcp.tool()
async def get_vulnerability_summary() -> str:
    """Résumé des vulnérabilités par sévérité et par agent (Wazuh 4.8+,
    nécessite l'indexer)."""
    body = {
        "size": 0,
        "aggs": {
            "by_severity": {
                "terms": {"field": "vulnerability.severity", "size": 10}
            },
            "by_agent": {
                "terms": {"field": "agent.name", "size": 15}
            },
        },
    }
    data = await _indexer_search("wazuh-states-vulnerabilities-*", body)
    aggs = data.get("aggregations", {})
    out = {
        "total": data.get("hits", {}).get("total", {}).get("value", 0),
        "by_severity": [
            {"severity": b["key"], "count": b["doc_count"]}
            for b in aggs.get("by_severity", {}).get("buckets", [])
        ],
        "top_agents": [
            {"agent": b["key"], "count": b["doc_count"]}
            for b in aggs.get("by_agent", {}).get("buckets", [])
        ],
    }
    return _fmt(out)


# ---------------------------------------------------------------------------
# Entrée
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    mcp.run(transport="stdio")