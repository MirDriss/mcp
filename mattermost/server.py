#!/usr/bin/env python3
"""
Serveur MCP pour Mattermost
============================
Expose des outils MCP permettant à Claude Code de :
  - consulter les équipes, canaux et threads Mattermost (ex: canal ops/astreinte)
  - poster des résumés d'alertes ou des rapports d'incident
  - répondre dans des fils de discussion existants

Configuration via variables d'environnement (.env) :
  MATTERMOST_URL          ex: https://mattermost.infraaitoolkit.lan
  MATTERMOST_TOKEN        token d'accès personnel (Compte → Sécurité → Jetons d'accès personnel)
  MATTERMOST_VERIFY_SSL   "true" / "false" (défaut: false, certifs auto-signés)

Le compte associé au token doit être membre des équipes/canaux à consulter
ou dans lesquels poster.
"""

import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import httpx
from dotenv import load_dotenv
from mcp.server.fastmcp import FastMCP

load_dotenv(Path(__file__).parent.parent / ".env")

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

MATTERMOST_URL = os.environ.get("MATTERMOST_URL", "").rstrip("/")
MATTERMOST_TOKEN = os.environ.get("MATTERMOST_TOKEN", "")
VERIFY_SSL = os.environ.get("MATTERMOST_VERIFY_SSL", "false").lower() == "true"

CHANNEL_TYPES = {"O": "public", "P": "privé", "D": "message direct", "G": "groupe"}

mcp = FastMCP("mattermost")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

async def _get(client: httpx.AsyncClient, path: str, params: Optional[dict] = None) -> dict:
    """GET authentifié sur l'API Mattermost."""
    if not (MATTERMOST_URL and MATTERMOST_TOKEN):
        raise RuntimeError(
            "Variables MATTERMOST_URL / MATTERMOST_TOKEN manquantes."
        )
    resp = await client.get(
        f"{MATTERMOST_URL}/api/v4{path}",
        params=params or {},
        headers={"Authorization": f"Bearer {MATTERMOST_TOKEN}"},
    )
    resp.raise_for_status()
    return resp.json()


async def _post(client: httpx.AsyncClient, path: str, body: dict) -> dict:
    """POST authentifié sur l'API Mattermost."""
    if not (MATTERMOST_URL and MATTERMOST_TOKEN):
        raise RuntimeError(
            "Variables MATTERMOST_URL / MATTERMOST_TOKEN manquantes."
        )
    resp = await client.post(
        f"{MATTERMOST_URL}/api/v4{path}",
        headers={"Authorization": f"Bearer {MATTERMOST_TOKEN}"},
        json=body,
    )
    resp.raise_for_status()
    return resp.json()


async def _get_team_id(client: httpx.AsyncClient, team: str) -> Optional[str]:
    """Résout le nom d'une équipe (champ "name") vers son id."""
    try:
        data = await _get(client, f"/teams/name/{team}")
    except httpx.HTTPStatusError:
        return None
    return data["id"]


async def _get_channel_id(client: httpx.AsyncClient, team_id: str, channel: str) -> Optional[str]:
    """Résout le nom d'un canal (champ "name") vers son id, dans une équipe."""
    try:
        data = await _get(client, f"/teams/{team_id}/channels/name/{channel}")
    except httpx.HTTPStatusError:
        return None
    return data["id"]


async def _get_usernames(client: httpx.AsyncClient, user_ids: list[str]) -> dict[str, str]:
    """Résout une liste d'ids utilisateurs vers leurs usernames."""
    unique_ids = list(set(user_ids))
    if not unique_ids:
        return {}
    resp = await client.post(
        f"{MATTERMOST_URL}/api/v4/users/ids",
        headers={"Authorization": f"Bearer {MATTERMOST_TOKEN}"},
        json=unique_ids,
    )
    resp.raise_for_status()
    return {u["id"]: u["username"] for u in resp.json()}


def _format_ts(create_at: int) -> str:
    """Convertit un timestamp Mattermost (ms epoch) en ISO 8601 UTC."""
    return datetime.fromtimestamp(create_at / 1000, tz=timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Outils MCP — Équipes et canaux
# ---------------------------------------------------------------------------

@mcp.tool()
async def list_teams() -> str:
    """Liste les équipes Mattermost dont le compte associé au token est
    membre. Point de départ pour connaître le nom d'équipe à utiliser dans
    les autres outils."""
    async with httpx.AsyncClient(verify=VERIFY_SSL, timeout=30) as client:
        data = await _get(client, "/users/me/teams")
    if not data:
        return "Aucune équipe trouvée (le compte associé au token n'est membre d'aucune équipe)"
    return "\n".join(f"- {t['display_name']} (name: {t['name']})" for t in data)


@mcp.tool()
async def list_channels(team: str) -> str:
    """Liste les canaux d'une équipe dont le compte associé au token est
    membre (publics et privés). Utile pour trouver le nom exact d'un canal
    d'astreinte ou ops avant de le lire ou d'y poster.

    Args:
        team: nom de l'équipe, champ "name" (obtenu via list_teams)
    """
    async with httpx.AsyncClient(verify=VERIFY_SSL, timeout=30) as client:
        team_id = await _get_team_id(client, team)
        if team_id is None:
            return f"Équipe '{team}' introuvable"
        data = await _get(client, f"/users/me/teams/{team_id}/channels")

    lines = []
    for c in data:
        if c.get("delete_at"):
            continue
        ctype = CHANNEL_TYPES.get(c["type"], c["type"])
        lines.append(f"- {c['display_name']} (name: {c['name']}, type: {ctype})")
    if not lines:
        return f"Aucun canal actif trouvé pour l'équipe '{team}'"
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Outils MCP — Lecture des messages
# ---------------------------------------------------------------------------

@mcp.tool()
async def get_channel_messages(team: str, channel: str, limit: int = 20) -> str:
    """Récupère les derniers messages d'un canal, du plus ancien au plus
    récent. Utile pour avoir le contexte d'un canal d'astreinte avant de
    poster un résumé ou de répondre dans un thread.

    Args:
        team: nom de l'équipe, champ "name" (obtenu via list_teams)
        channel: nom du canal, champ "name" (obtenu via list_channels)
        limit: nombre de messages à récupérer (défaut: 20, max: 100)
    """
    limit = max(1, min(limit, 100))
    async with httpx.AsyncClient(verify=VERIFY_SSL, timeout=30) as client:
        team_id = await _get_team_id(client, team)
        if team_id is None:
            return f"Équipe '{team}' introuvable"
        channel_id = await _get_channel_id(client, team_id, channel)
        if channel_id is None:
            return f"Canal '{channel}' introuvable dans l'équipe '{team}'"

        data = await _get(client, f"/channels/{channel_id}/posts", {"per_page": limit})
        posts = data["posts"]
        order = data["order"]
        usernames = await _get_usernames(client, [posts[pid]["user_id"] for pid in order])

    if not order:
        return f"Aucun message dans le canal '{channel}'"

    lines = [f"Derniers messages de #{channel} ({team}) :"]
    for pid in reversed(order):  # ordre chronologique
        post = posts[pid]
        if not post["message"]:
            continue
        author = usernames.get(post["user_id"], post["user_id"])
        thread_info = f" [réponse au thread {post['root_id']}]" if post.get("root_id") else ""
        lines.append(
            f"- [{_format_ts(post['create_at'])}] {author}: {post['message']}"
            f"{thread_info} (id: {pid})"
        )
    return "\n".join(lines)


@mcp.tool()
async def get_thread(post_id: str) -> str:
    """Récupère un fil de discussion complet (message racine + réponses)
    dans l'ordre chronologique. Utile pour comprendre le contexte d'une
    discussion d'astreinte avant d'y répondre.

    Args:
        post_id: id du message racine ou de toute réponse du thread
            (obtenu via get_channel_messages ou search_messages)
    """
    async with httpx.AsyncClient(verify=VERIFY_SSL, timeout=30) as client:
        data = await _get(client, f"/posts/{post_id}/thread")
        posts = data["posts"]
        ordered = sorted(posts.values(), key=lambda p: p["create_at"])
        usernames = await _get_usernames(client, [p["user_id"] for p in ordered])

    if not ordered:
        return f"Thread {post_id} introuvable"

    lines = [f"Thread {post_id} :"]
    for post in ordered:
        author = usernames.get(post["user_id"], post["user_id"])
        marker = "racine" if not post.get("root_id") else "réponse"
        lines.append(f"- [{_format_ts(post['create_at'])}] {author} ({marker}): {post['message']}")
    return "\n".join(lines)


@mcp.tool()
async def search_messages(team: str, query: str) -> str:
    """Recherche des messages contenant les termes donnés dans une équipe.
    Utile pour retrouver une discussion passée sur un incident, un hôte ou
    une alerte précise.

    Args:
        team: nom de l'équipe, champ "name" (obtenu via list_teams)
        query: termes à rechercher, ex: "k3s-worker1 disque"
    """
    async with httpx.AsyncClient(verify=VERIFY_SSL, timeout=30) as client:
        team_id = await _get_team_id(client, team)
        if team_id is None:
            return f"Équipe '{team}' introuvable"

        data = await _post(client, f"/teams/{team_id}/posts/search", {
            "terms": query,
            "is_or_search": False,
        })
        posts = data["posts"]
        order = data["order"]
        usernames = await _get_usernames(client, [posts[pid]["user_id"] for pid in order])

    if not order:
        return f"Aucun message trouvé pour '{query}' dans l'équipe '{team}'"

    lines = [f"Résultats pour '{query}' dans '{team}' :"]
    for pid in order:
        post = posts[pid]
        author = usernames.get(post["user_id"], post["user_id"])
        lines.append(
            f"- [{_format_ts(post['create_at'])}] {author} (canal: {post['channel_id']}): "
            f"{post['message']} (id: {pid})"
        )
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Outils MCP — Écriture
# ---------------------------------------------------------------------------

@mcp.tool()
async def post_message(team: str, channel: str, message: str) -> str:
    """Poste un message dans un canal Mattermost. Utile pour publier un
    résumé d'alerte (Wazuh, Zabbix, Grafana) ou un rapport d'incident sur
    le canal ops/astreinte.

    Args:
        team: nom de l'équipe, champ "name" (obtenu via list_teams)
        channel: nom du canal, champ "name" (obtenu via list_channels)
        message: contenu du message (markdown Mattermost supporté)
    """
    async with httpx.AsyncClient(verify=VERIFY_SSL, timeout=30) as client:
        team_id = await _get_team_id(client, team)
        if team_id is None:
            return f"Équipe '{team}' introuvable"
        channel_id = await _get_channel_id(client, team_id, channel)
        if channel_id is None:
            return f"Canal '{channel}' introuvable dans l'équipe '{team}'"

        post = await _post(client, "/posts", {"channel_id": channel_id, "message": message})

    return f"Message posté dans #{channel} ({team}) (id: {post['id']})"


@mcp.tool()
async def reply_to_thread(post_id: str, message: str) -> str:
    """Répond dans un fil de discussion existant. Utile pour ajouter du
    contexte (ex: résultat d'investigation) à une discussion d'incident en
    cours sans créer un nouveau message racine.

    Args:
        post_id: id du message racine ou de toute réponse du thread
            (obtenu via get_channel_messages, search_messages ou get_thread)
        message: contenu de la réponse (markdown Mattermost supporté)
    """
    async with httpx.AsyncClient(verify=VERIFY_SSL, timeout=30) as client:
        root = await _get(client, f"/posts/{post_id}")
        channel_id = root["channel_id"]
        root_id = root["root_id"] or root["id"]

        post = await _post(client, "/posts", {
            "channel_id": channel_id,
            "message": message,
            "root_id": root_id,
        })

    return f"Réponse postée dans le thread {root_id} (id: {post['id']})"


# ---------------------------------------------------------------------------
# Entrée
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    mcp.run(transport="stdio")