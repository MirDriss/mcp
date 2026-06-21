#!/usr/bin/env python3
"""
Serveur MCP pour Kubernetes
============================
Expose des outils MCP permettant à Claude Code d'interroger un cluster
Kubernetes (k3s) : nodes, namespaces, pods, déploiements, events.

Particulièrement utile pour identifier un pod à partir de son IP (ex: une
IP suspecte 10.42.x.x repérée dans les logs ELK ou les alertes Wazuh) et
investiguer son état.

Configuration via variables d'environnement (.env) :
  KUBECONFIG_PATH   (optionnel) chemin vers le fichier kubeconfig.
                    Par défaut : kubernetes/kubeconfig.yaml (à côté de ce
                    script) — place simplement ton fichier ici, rien à
                    configurer.
  KUBE_CONTEXT      (optionnel) nom du contexte à utiliser si plusieurs
"""

import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from dotenv import load_dotenv
from kubernetes import client, config

load_dotenv(Path(__file__).parent.parent / ".env")

try:
    from mcp.server.fastmcp import FastMCP
except ImportError:  # pragma: no cover
    raise

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# Par défaut, on cherche kubeconfig.yaml dans le même dossier que ce script
# (kubernetes/kubeconfig.yaml). Chacun place son fichier là, sans rien
# configurer dans le .env. KUBECONFIG_PATH permet de surcharger ce chemin
# si besoin (ex: kubeconfig partagé ailleurs sur la machine).
_DEFAULT_KUBECONFIG = Path(__file__).parent / "kubeconfig.yaml"
KUBECONFIG_PATH = os.environ.get("KUBECONFIG_PATH") or str(_DEFAULT_KUBECONFIG)
KUBE_CONTEXT = os.environ.get("KUBE_CONTEXT") or None

mcp = FastMCP("kubernetes")

_clients_cache: dict[str, object] = {}


def _load_clients():
    """Charge (une seule fois) les clients Kubernetes CoreV1 et AppsV1."""
    if "core" in _clients_cache:
        return _clients_cache["core"], _clients_cache["apps"]

    if not KUBECONFIG_PATH:
        raise RuntimeError("Variable KUBECONFIG_PATH manquante dans .env")
    if not Path(KUBECONFIG_PATH).exists():
        raise RuntimeError(
            f"Fichier kubeconfig introuvable : {KUBECONFIG_PATH}\n"
            f"Place ton kubeconfig dans kubernetes/kubeconfig.yaml, "
            f"ou définis KUBECONFIG_PATH dans .env pour pointer ailleurs."
        )

    config.load_kube_config(config_file=KUBECONFIG_PATH, context=KUBE_CONTEXT)
    core = client.CoreV1Api()
    apps = client.AppsV1Api()
    _clients_cache["core"] = core
    _clients_cache["apps"] = apps
    return core, apps


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _age(creation_timestamp) -> str:
    """Calcule un âge lisible depuis un timestamp de création Kubernetes."""
    if creation_timestamp is None:
        return "?"
    delta = datetime.now(timezone.utc) - creation_timestamp
    days = delta.days
    hours, rem = divmod(delta.seconds, 3600)
    minutes = rem // 60
    if days > 0:
        return f"{days}j{hours}h"
    if hours > 0:
        return f"{hours}h{minutes}m"
    return f"{minutes}m"


def _container_statuses(pod) -> str:
    """Résume les statuts des conteneurs d'un pod (ready, restarts, raison)."""
    statuses = pod.status.container_statuses or []
    parts = []
    for cs in statuses:
        state = "running"
        reason = ""
        if cs.state.waiting:
            state = "waiting"
            reason = cs.state.waiting.reason or ""
        elif cs.state.terminated:
            state = "terminated"
            reason = cs.state.terminated.reason or ""
        ready = "ready" if cs.ready else "not ready"
        suffix = f" ({reason})" if reason else ""
        parts.append(f"{cs.name}: {state}{suffix}, {ready}, restarts={cs.restart_count}")
    return "; ".join(parts) if parts else "aucun conteneur"


# ---------------------------------------------------------------------------
# Outils MCP — Cluster / Nodes
# ---------------------------------------------------------------------------

@mcp.tool()
async def list_nodes() -> str:
    """Liste les nodes du cluster avec leur statut, rôle, version kubelet
    et utilisation des ressources de base. Point de départ pour vérifier
    la santé globale du cluster."""
    core, _ = _load_clients()
    nodes = core.list_node().items
    if not nodes:
        return "Aucun node trouvé"

    lines = []
    for n in nodes:
        conditions = {c.type: c.status for c in (n.status.conditions or [])}
        ready = "Ready" if conditions.get("Ready") == "True" else "NotReady"
        roles = [
            label.split("/")[1]
            for label in (n.metadata.labels or {})
            if label.startswith("node-role.kubernetes.io/")
        ]
        role_str = ", ".join(roles) if roles else "worker"
        version = n.status.node_info.kubelet_version if n.status.node_info else "?"
        age = _age(n.metadata.creation_timestamp)
        lines.append(
            f"- {n.metadata.name} ({role_str}) : {ready}, "
            f"kubelet {version}, age {age}"
        )
    return "\n".join(lines)


@mcp.tool()
async def get_node_details(node_name: str) -> str:
    """Détails d'un node : capacité (CPU/RAM), conditions de santé,
    labels, et liste des pods qui y tournent.

    Args:
        node_name: nom du node, ex: "k3sworker1"
    """
    core, _ = _load_clients()
    try:
        node = core.read_node(node_name)
    except client.ApiException as e:
        return f"Node '{node_name}' introuvable : {e.reason}"

    lines = [f"Node: {node.metadata.name}"]
    lines.append(f"  Labels: {dict(node.metadata.labels or {})}")
    lines.append(f"  Capacité: {dict(node.status.capacity or {})}")
    lines.append(f"  Allouable: {dict(node.status.allocatable or {})}")
    lines.append("  Conditions:")
    for c in node.status.conditions or []:
        lines.append(f"    - {c.type}: {c.status} ({c.reason})")

    pods = core.list_pod_for_all_namespaces(
        field_selector=f"spec.nodeName={node_name}"
    ).items
    lines.append(f"\n  Pods sur ce node ({len(pods)}):")
    for p in pods:
        lines.append(f"    - {p.metadata.namespace}/{p.metadata.name} ({p.status.phase})")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Outils MCP — Namespaces et pods
# ---------------------------------------------------------------------------

@mcp.tool()
async def list_namespaces() -> str:
    """Liste tous les namespaces du cluster avec leur statut et leur âge."""
    core, _ = _load_clients()
    namespaces = core.list_namespace().items
    lines = []
    for ns in namespaces:
        age = _age(ns.metadata.creation_timestamp)
        lines.append(f"- {ns.metadata.name} ({ns.status.phase}, age {age})")
    return "\n".join(lines)


@mcp.tool()
async def list_pods(
    namespace: Optional[str] = None,
    status: Optional[str] = None,
) -> str:
    """Liste les pods du cluster, avec leur statut, node, IP et nombre de
    redémarrages. Filtrable par namespace et/ou par statut.

    Args:
        namespace: filtrer sur un namespace précis, ex: "default", "log-lab"
        status: filtrer par phase — "Running", "Pending", "Failed", "Succeeded"
    """
    core, _ = _load_clients()
    if namespace:
        pods = core.list_namespaced_pod(namespace).items
    else:
        pods = core.list_pod_for_all_namespaces().items

    if status:
        pods = [p for p in pods if p.status.phase == status]

    if not pods:
        return "Aucun pod trouvé"

    lines = []
    for p in pods:
        restarts = sum(
            cs.restart_count for cs in (p.status.container_statuses or [])
        )
        age = _age(p.metadata.creation_timestamp)
        lines.append(
            f"- {p.metadata.namespace}/{p.metadata.name} : {p.status.phase}, "
            f"node={p.spec.node_name}, ip={p.status.pod_ip}, "
            f"restarts={restarts}, age={age}"
        )
    return "\n".join(lines)


@mcp.tool()
async def get_pod_details(namespace: str, pod_name: str) -> str:
    """Détails complets d'un pod : statut, conteneurs, raisons d'échec,
    node, IP. Équivalent du résumé de `kubectl describe pod`.

    Args:
        namespace: namespace du pod, ex: "default"
        pod_name: nom du pod (exact)
    """
    core, _ = _load_clients()
    try:
        pod = core.read_namespaced_pod(pod_name, namespace)
    except client.ApiException as e:
        return f"Pod '{namespace}/{pod_name}' introuvable : {e.reason}"

    lines = [
        f"Pod: {namespace}/{pod.metadata.name}",
        f"  Statut: {pod.status.phase}",
        f"  Node: {pod.spec.node_name}",
        f"  IP: {pod.status.pod_ip}",
        f"  Age: {_age(pod.metadata.creation_timestamp)}",
        f"  Conteneurs: {_container_statuses(pod)}",
    ]
    if pod.metadata.labels:
        lines.append(f"  Labels: {dict(pod.metadata.labels)}")
    if pod.metadata.owner_references:
        owners = ", ".join(
            f"{o.kind}/{o.name}" for o in pod.metadata.owner_references
        )
        lines.append(f"  Owner: {owners}")
    return "\n".join(lines)


@mcp.tool()
async def get_pod_logs(
    namespace: str,
    pod_name: str,
    container: Optional[str] = None,
    tail_lines: int = 50,
    previous: bool = False,
) -> str:
    """Récupère les logs d'un pod en direct depuis Kubernetes (complémentaire
    aux logs indexés dans ELK, utile pour les pods très récents ou
    redémarrés avant indexation).

    Args:
        namespace: namespace du pod
        pod_name: nom du pod (exact)
        container: nom du conteneur si le pod en a plusieurs
        tail_lines: nombre de lignes à récupérer depuis la fin (défaut 50)
        previous: True pour récupérer les logs du conteneur précédent
                  (utile après un crash/redémarrage)
    """
    core, _ = _load_clients()
    try:
        logs = core.read_namespaced_pod_log(
            name=pod_name,
            namespace=namespace,
            container=container,
            tail_lines=tail_lines,
            previous=previous,
        )
    except client.ApiException as e:
        return f"Impossible de récupérer les logs : {e.reason}"
    return logs or "(aucun log)"


@mcp.tool()
async def find_pod_by_ip(ip: str) -> str:
    """Retrouve le pod correspondant à une adresse IP interne du cluster
    (ex: 10.42.x.x). Très utile pour identifier un pod suspect repéré dans
    les logs ELK ou les alertes Wazuh à partir de son IP source/destination.

    Args:
        ip: adresse IP du pod, ex: "10.42.0.15"
    """
    core, _ = _load_clients()
    pods = core.list_pod_for_all_namespaces(
        field_selector=f"status.podIP={ip}"
    ).items

    if not pods:
        return (
            f"Aucun pod trouvé avec l'IP {ip}. "
            f"Si l'IP correspond à un node, vérifie avec list_nodes."
        )

    lines = []
    for p in pods:
        lines.append(
            f"- {p.metadata.namespace}/{p.metadata.name} "
            f"(statut: {p.status.phase}, node: {p.spec.node_name}, "
            f"image: {p.spec.containers[0].image if p.spec.containers else '?'})"
        )
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Outils MCP — Déploiements et events
# ---------------------------------------------------------------------------

@mcp.tool()
async def list_deployments(namespace: Optional[str] = None) -> str:
    """Liste les déploiements et leur statut de rollout (replicas désirés
    vs disponibles). Utile pour repérer un déploiement qui ne converge pas.

    Args:
        namespace: filtrer sur un namespace précis
    """
    _, apps = _load_clients()
    if namespace:
        deployments = apps.list_namespaced_deployment(namespace).items
    else:
        deployments = apps.list_deployment_for_all_namespaces().items

    if not deployments:
        return "Aucun déploiement trouvé"

    lines = []
    for d in deployments:
        desired = d.spec.replicas or 0
        available = d.status.available_replicas or 0
        ready = d.status.ready_replicas or 0
        lines.append(
            f"- {d.metadata.namespace}/{d.metadata.name} : "
            f"{available}/{desired} disponibles, {ready} prêts"
        )
    return "\n".join(lines)


@mcp.tool()
async def get_events(
    namespace: Optional[str] = None,
    limit: int = 30,
) -> str:
    """Liste les events Kubernetes récents (OOMKilled, CrashLoopBackOff,
    FailedScheduling, Pulling, etc.), triés du plus récent au plus ancien.
    Idéal pour comprendre pourquoi un pod a un comportement anormal.

    Args:
        namespace: filtrer sur un namespace précis
        limit: nombre max d'events retournés (défaut 30)
    """
    core, _ = _load_clients()
    if namespace:
        events = core.list_namespaced_event(namespace).items
    else:
        events = core.list_event_for_all_namespaces().items

    if not events:
        return "Aucun event trouvé"

    events = sorted(
        events,
        key=lambda e: e.last_timestamp or e.event_time or datetime.min.replace(tzinfo=timezone.utc),
        reverse=True,
    )[:limit]

    lines = []
    for e in events:
        ts = e.last_timestamp or e.event_time
        ts_str = ts.isoformat() if ts else "?"
        obj = e.involved_object
        lines.append(
            f"- [{e.type}] {e.reason} : {obj.kind}/{obj.name} "
            f"({e.metadata.namespace}) — {e.message} (à {ts_str})"
        )
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Entrée
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    mcp.run(transport="stdio")