#!/usr/bin/env python3
"""
Serveur MCP pour ELK (Elasticsearch)
=====================================
Index disponibles :
  - kubernetes-logs-*     : logs de tous les pods k3s
  - journald-services-*   : logs systemd des services des VMs
  - linux-system-*        : logs système Linux (syslog, auth, kernel)
  - k3s-pods-*            : logs spécifiques k3s

Configuration via variables d'environnement (.env) :
  ELK_URL           ex: https://172.16.0.107:9200
  ELK_USER          ex: elastic
  ELK_PASSWORD      mot de passe Elasticsearch
  ELK_VERIFY_SSL    "true" / "false" (défaut: false)
"""

import json
import os
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

ELK_URL = os.environ.get("ELK_URL", "").rstrip("/")
ELK_USER = os.environ.get("ELK_USER", "")
ELK_PASSWORD = os.environ.get("ELK_PASSWORD", "")
VERIFY_SSL = os.environ.get("ELK_VERIFY_SSL", "false").lower() == "true"

mcp = FastMCP("elk")


# ---------------------------------------------------------------------------
# Helper central
# ---------------------------------------------------------------------------

async def _search(index: str, body: dict) -> dict:
    """POST _search sur Elasticsearch."""
    if not (ELK_URL and ELK_USER and ELK_PASSWORD):
        raise RuntimeError(
            "Variables ELK_URL / ELK_USER / ELK_PASSWORD manquantes."
        )
    async with httpx.AsyncClient(verify=VERIFY_SSL, timeout=30) as client:
        resp = await client.post(
            f"{ELK_URL}/{index}/_search",
            json=body,
            auth=(ELK_USER, ELK_PASSWORD),
        )
        resp.raise_for_status()
        return resp.json()


def _fmt(data: Any) -> str:
    return json.dumps(data, indent=2, ensure_ascii=False, default=str)


def _time_filter(hours_back: int, field: str = "@timestamp") -> dict:
    since = (datetime.now(timezone.utc) - timedelta(hours=hours_back)).isoformat()
    return {"range": {field: {"gte": since}}}


# ---------------------------------------------------------------------------
# Outils MCP — Vue d'ensemble
# ---------------------------------------------------------------------------

@mcp.tool()
async def get_elk_overview() -> str:
    """Vue d'ensemble de l'ELK : liste des index avec leur nombre de documents
    et leur taille. Utile pour savoir ce qui est disponible et comment les données
    sont réparties."""
    async with httpx.AsyncClient(verify=VERIFY_SSL, timeout=30) as client:
        resp = await client.get(
            f"{ELK_URL}/_cat/indices?v&s=index&h=index,health,docs.count,store.size",
            auth=(ELK_USER, ELK_PASSWORD),
        )
        resp.raise_for_status()
        lines = resp.text.strip().split("\n")
        # On filtre les index internes (.internal, .*)
        filtered = [l for l in lines if not l.strip().startswith(".")]
        return "\n".join(filtered)


# ---------------------------------------------------------------------------
# Outils MCP — Logs Kubernetes
# ---------------------------------------------------------------------------

@mcp.tool()
async def search_kubernetes_logs(
    query: Optional[str] = None,
    namespace: Optional[str] = None,
    pod: Optional[str] = None,
    container: Optional[str] = None,
    level: Optional[str] = None,
    hours_back: int = 24,
    limit: int = 20,
) -> str:
    """Recherche dans les logs des pods Kubernetes (index kubernetes-logs-*).

    Args:
        query: recherche texte libre, ex: "error", "OOMKilled", "CrashLoopBackOff"
        namespace: filtrer par namespace Kubernetes, ex: "default", "monitoring"
        pod: filtrer par nom de pod (partiel accepté), ex: "mattermost"
        container: filtrer par nom de conteneur
        level: niveau de log — "error", "warn", "info", "debug"
        hours_back: fenêtre temporelle en heures (défaut 24)
        limit: nombre max de logs retournés (défaut 20)
    """
    must: list[dict] = [_time_filter(hours_back)]

    if query:
        must.append({"query_string": {"query": query, "default_field": "message"}})
    if namespace:
        must.append({"term": {"kubernetes.namespace": namespace}})
    if pod:
        must.append({"wildcard": {"kubernetes.pod.name": f"*{pod}*"}})
    if container:
        must.append({"term": {"kubernetes.container.name": container}})
    if level:
        must.append({"term": {"log.level": level.lower()}})

    body = {
        "size": min(limit, 100),
        "sort": [{"@timestamp": {"order": "desc"}}],
        "query": {"bool": {"must": must}},
        "_source": [
            "@timestamp", "message", "kubernetes.namespace",
            "kubernetes.pod.name", "kubernetes.container.name",
            "log.level", "stream",
        ],
    }
    data = await _search("kubernetes-logs-*", body)
    hits = data.get("hits", {})
    out = {
        "total": hits.get("total", {}).get("value", 0),
        "logs": [h["_source"] for h in hits.get("hits", [])],
    }
    return _fmt(out)


@mcp.tool()
async def get_kubernetes_stats(hours_back: int = 24) -> str:
    """Statistiques agrégées des logs Kubernetes : top namespaces, top pods,
    top conteneurs, répartition par niveau de log. Idéal pour identifier
    rapidement les pods qui génèrent le plus de logs ou d'erreurs.

    Args:
        hours_back: fenêtre temporelle en heures (défaut 24)
    """
    body = {
        "size": 0,
        "query": {"bool": {"must": [_time_filter(hours_back)]}},
        "aggs": {
            "top_namespaces": {
                "terms": {"field": "kubernetes.namespace", "size": 10}
            },
            "top_pods": {
                "terms": {"field": "kubernetes.pod.name", "size": 10}
            },
            "by_level": {
                "terms": {"field": "log.level", "size": 10}
            },
            "errors_over_time": {
                "date_histogram": {
                    "field": "@timestamp",
                    "calendar_interval": "1h",
                },
                "aggs": {
                    "errors": {
                        "filter": {"term": {"log.level": "error"}}
                    }
                }
            }
        },
    }
    data = await _search("kubernetes-logs-*", body)
    aggs = data.get("aggregations", {})
    out = {
        "total_logs": data.get("hits", {}).get("total", {}).get("value", 0),
        "top_namespaces": [
            {"namespace": b["key"], "count": b["doc_count"]}
            for b in aggs.get("top_namespaces", {}).get("buckets", [])
        ],
        "top_pods": [
            {"pod": b["key"], "count": b["doc_count"]}
            for b in aggs.get("top_pods", {}).get("buckets", [])
        ],
        "by_level": [
            {"level": b["key"], "count": b["doc_count"]}
            for b in aggs.get("by_level", {}).get("buckets", [])
        ],
    }
    return _fmt(out)


@mcp.tool()
async def get_kubernetes_errors(
    namespace: Optional[str] = None,
    hours_back: int = 24,
    limit: int = 30,
) -> str:
    """Retourne uniquement les logs d'erreur des pods Kubernetes, triés du
    plus récent au plus ancien. Raccourci pratique pour investiguer rapidement
    les problèmes sans avoir à spécifier le niveau.

    Args:
        namespace: filtrer sur un namespace précis
        hours_back: fenêtre temporelle en heures (défaut 24)
        limit: nombre max de logs retournés
    """
    must: list[dict] = [
        _time_filter(hours_back),
        {"bool": {"should": [
            {"term": {"log.level": "error"}},
            {"term": {"log.level": "ERROR"}},
            {"query_string": {"query": "error OR exception OR fatal OR panic", "default_field": "message"}},
        ], "minimum_should_match": 1}},
    ]
    if namespace:
        must.append({"term": {"kubernetes.namespace": namespace}})

    body = {
        "size": min(limit, 100),
        "sort": [{"@timestamp": {"order": "desc"}}],
        "query": {"bool": {"must": must}},
        "_source": [
            "@timestamp", "message", "kubernetes.namespace",
            "kubernetes.pod.name", "kubernetes.container.name", "log.level",
        ],
    }
    data = await _search("kubernetes-logs-*", body)
    hits = data.get("hits", {})
    out = {
        "total": hits.get("total", {}).get("value", 0),
        "errors": [h["_source"] for h in hits.get("hits", [])],
    }
    return _fmt(out)


@mcp.tool()
async def get_pod_logs(
    pod: str,
    hours_back: int = 6,
    limit: int = 50,
) -> str:
    """Récupère tous les logs d'un pod spécifique, toutes sévérités confondues,
    triés chronologiquement. Pratique pour débugger un pod précis.

    Args:
        pod: nom du pod (partiel accepté), ex: "mattermost", "nginx"
        hours_back: fenêtre temporelle en heures (défaut 6)
        limit: nombre max de logs retournés
    """
    body = {
        "size": min(limit, 200),
        "sort": [{"@timestamp": {"order": "asc"}}],
        "query": {"bool": {"must": [
            _time_filter(hours_back),
            {"wildcard": {"kubernetes.pod.name": f"*{pod}*"}},
        ]}},
        "_source": [
            "@timestamp", "message", "kubernetes.namespace",
            "kubernetes.pod.name", "kubernetes.container.name", "log.level",
        ],
    }
    data = await _search("kubernetes-logs-*", body)
    hits = data.get("hits", {})
    out = {
        "total": hits.get("total", {}).get("value", 0),
        "logs": [h["_source"] for h in hits.get("hits", [])],
    }
    return _fmt(out)


# ---------------------------------------------------------------------------
# Outils MCP — Logs système Linux
# ---------------------------------------------------------------------------

@mcp.tool()
async def search_system_logs(
    query: Optional[str] = None,
    host: Optional[str] = None,
    service: Optional[str] = None,
    hours_back: int = 24,
    limit: int = 20,
) -> str:
    """Recherche dans les logs système Linux : syslog, auth, kernel
    (index linux-system-* et journald-services-*).

    Args:
        query: recherche texte libre, ex: "ssh", "sudo", "kernel panic"
        host: filtrer par machine, ex: "k3s-master", "wazuh"
        service: filtrer par service systemd, ex: "sshd", "kubelet", "docker"
        hours_back: fenêtre temporelle en heures (défaut 24)
        limit: nombre max de logs retournés
    """
    must: list[dict] = [_time_filter(hours_back)]
    if query:
        must.append({"query_string": {"query": query, "default_field": "message"}})
    if host:
        must.append({"wildcard": {"host.name": f"*{host}*"}})
    if service:
        must.append({"wildcard": {"systemd.unit": f"*{service}*"}})

    body = {
        "size": min(limit, 100),
        "sort": [{"@timestamp": {"order": "desc"}}],
        "query": {"bool": {"must": must}},
        "_source": [
            "@timestamp", "message", "host.name",
            "systemd.unit", "syslog.identifier", "log.level",
            "process.name", "user.name",
        ],
    }
    # Recherche sur les deux index système
    data = await _search("linux-system-*,journald-services-*", body)
    hits = data.get("hits", {})
    out = {
        "total": hits.get("total", {}).get("value", 0),
        "logs": [h["_source"] for h in hits.get("hits", [])],
    }
    return _fmt(out)


@mcp.tool()
async def get_auth_logs(
    host: Optional[str] = None,
    hours_back: int = 24,
    limit: int = 30,
) -> str:
    """Logs d'authentification Linux : connexions SSH, sudo, échecs de login.
    Utile pour détecter des accès suspects ou des tentatives de brute force.

    Args:
        host: filtrer sur une machine précise
        hours_back: fenêtre temporelle en heures (défaut 24)
        limit: nombre max de logs retournés
    """
    must: list[dict] = [
        _time_filter(hours_back),
        {"bool": {"should": [
            {"wildcard": {"systemd.unit": "*ssh*"}},
            {"wildcard": {"syslog.identifier": "*ssh*"}},
            {"wildcard": {"syslog.identifier": "*sudo*"}},
            {"query_string": {
                "query": "authentication OR \"Failed password\" OR \"Accepted password\" OR sudo OR \"Invalid user\"",
                "default_field": "message"
            }},
        ], "minimum_should_match": 1}},
    ]
    if host:
        must.append({"wildcard": {"host.name": f"*{host}*"}})

    body = {
        "size": min(limit, 100),
        "sort": [{"@timestamp": {"order": "desc"}}],
        "query": {"bool": {"must": must}},
        "_source": [
            "@timestamp", "message", "host.name",
            "systemd.unit", "syslog.identifier", "user.name", "source.ip",
        ],
    }
    data = await _search("linux-system-*,journald-services-*", body)
    hits = data.get("hits", {})
    out = {
        "total": hits.get("total", {}).get("value", 0),
        "logs": [h["_source"] for h in hits.get("hits", [])],
    }
    return _fmt(out)


@mcp.tool()
async def get_system_stats(hours_back: int = 24) -> str:
    """Statistiques des logs système : top machines, top services,
    répartition par niveau de sévérité sur linux-system-* et journald-services-*.

    Args:
        hours_back: fenêtre temporelle en heures (défaut 24)
    """
    body = {
        "size": 0,
        "query": {"bool": {"must": [_time_filter(hours_back)]}},
        "aggs": {
            "top_hosts": {
                "terms": {"field": "host.name", "size": 10}
            },
            "top_services": {
                "terms": {"field": "systemd.unit", "size": 10}
            },
            "by_level": {
                "terms": {"field": "log.level", "size": 10}
            },
        },
    }
    data = await _search("linux-system-*,journald-services-*", body)
    aggs = data.get("aggregations", {})
    out = {
        "total_logs": data.get("hits", {}).get("total", {}).get("value", 0),
        "top_hosts": [
            {"host": b["key"], "count": b["doc_count"]}
            for b in aggs.get("top_hosts", {}).get("buckets", [])
        ],
        "top_services": [
            {"service": b["key"], "count": b["doc_count"]}
            for b in aggs.get("top_services", {}).get("buckets", [])
        ],
        "by_level": [
            {"level": b["key"], "count": b["doc_count"]}
            for b in aggs.get("by_level", {}).get("buckets", [])
        ],
    }
    return _fmt(out)


# ---------------------------------------------------------------------------
# Outils MCP — Logs k3s
# ---------------------------------------------------------------------------

@mcp.tool()
async def search_k3s_logs(
    query: Optional[str] = None,
    hours_back: int = 24,
    limit: int = 20,
) -> str:
    """Recherche dans les logs spécifiques k3s (index k3s-pods-*) :
    logs du control plane, scheduler, controller-manager, etcd.

    Args:
        query: recherche texte libre, ex: "evicted", "node not ready", "timeout"
        hours_back: fenêtre temporelle en heures (défaut 24)
        limit: nombre max de logs retournés
    """
    must: list[dict] = [_time_filter(hours_back)]
    if query:
        must.append({"query_string": {"query": query, "default_field": "message"}})

    body = {
        "size": min(limit, 100),
        "sort": [{"@timestamp": {"order": "desc"}}],
        "query": {"bool": {"must": must}},
        "_source": ["@timestamp", "message", "host.name", "log.level", "stream"],
    }
    data = await _search("k3s-pods-*", body)
    hits = data.get("hits", {})
    out = {
        "total": hits.get("total", {}).get("value", 0),
        "logs": [h["_source"] for h in hits.get("hits", [])],
    }
    return _fmt(out)


# ---------------------------------------------------------------------------
# Outil MCP — Recherche globale
# ---------------------------------------------------------------------------

@mcp.tool()
async def search_all_logs(
    query: str,
    hours_back: int = 24,
    limit: int = 30,
) -> str:
    """Recherche dans TOUS les index ELK simultanément : kubernetes-logs-*,
    linux-system-*, journald-services-*, k3s-pods-*. Utile pour une
    investigation transversale quand on ne sait pas dans quel index chercher.

    Args:
        query: recherche texte libre obligatoire, ex: "connection refused", "OOM"
        hours_back: fenêtre temporelle en heures (défaut 24)
        limit: nombre max de logs retournés au total
    """
    body = {
        "size": min(limit, 100),
        "sort": [{"@timestamp": {"order": "desc"}}],
        "query": {"bool": {"must": [
            _time_filter(hours_back),
            {"query_string": {"query": query, "default_field": "message"}},
        ]}},
        "_source": [
            "@timestamp", "message", "host.name", "log.level",
            "kubernetes.namespace", "kubernetes.pod.name",
            "systemd.unit", "syslog.identifier",
        ],
    }
    index = "kubernetes-logs-*,linux-system-*,journald-services-*,k3s-pods-*"
    data = await _search(index, body)
    hits = data.get("hits", {})
    out = {
        "total": hits.get("total", {}).get("value", 0),
        "logs": [h["_source"] for h in hits.get("hits", [])],
    }
    return _fmt(out)


# ---------------------------------------------------------------------------
# Entrée
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    mcp.run(transport="stdio")