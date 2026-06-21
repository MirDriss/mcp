from mcp.server.fastmcp import FastMCP
import os, paramiko
from dotenv import load_dotenv

load_dotenv()

PFSENSE_HOST = os.environ["PFSENSE_HOST"]
PFSENSE_USER = os.environ["PFSENSE_USER"]
PFSENSE_SSH_KEY = os.path.expanduser(os.environ["PFSENSE_SSH_KEY"])

mcp = FastMCP("pfsense")


def ssh_run(command: str) -> str:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(PFSENSE_HOST, username=PFSENSE_USER, key_filename=PFSENSE_SSH_KEY, timeout=10)
    _, stdout, stderr = client.exec_command(command)
    output = stdout.read().decode().strip()
    error = stderr.read().decode().strip()
    client.close()
    return output if output else error


@mcp.tool()
def get_system_status() -> str:
    """Get pfSense system status: CPU usage, memory, uptime and kernel info"""
    uptime = ssh_run("uptime")
    memory = ssh_run("vmstat -H | tail -1 | awk '{print \"Active: \" $5 \"K  Free: \" $6 \"K  Swap: \" $10 \"K\"}'")
    version = ssh_run("cat /etc/version")
    return f"Version: {version}\nUptime: {uptime}\nMemory: {memory}"


@mcp.tool()
def get_interfaces() -> str:
    """Get pfSense network interfaces status: IP addresses, state (up/down) and traffic"""
    output = ssh_run("ifconfig | grep -E '^[a-z]|inet |status'")
    return output


@mcp.tool()
def get_firewall_stats() -> str:
    """Get pfSense firewall statistics: active states, blocked packets, rules count"""
    info = ssh_run("pfctl -s info")
    rules_count = ssh_run("pfctl -s rules 2>/dev/null | wc -l")
    return f"{info}\n\nNombre de règles actives: {rules_count.strip()}"


@mcp.tool()
def get_vpn_clients() -> str:
    """List currently connected OpenVPN clients: name, IP, connection time and bytes transferred"""
    socks = ssh_run("find /var/etc/openvpn -name 'sock' 2>/dev/null").splitlines()
    if not socks:
        return "Socket de management OpenVPN introuvable"

    results = []
    for sock in socks:
        raw = ssh_run(
            f"php -r \""
            f"\\$fp = stream_socket_client('unix://{sock}', \\$e, \\$s, 5);"
            f"if (!\\$fp) {{ die('socket error: '.\\$s); }}"
            f"fwrite(\\$fp, \\\"status\\\\n\\\");"
            f"\\$out = '';"
            f"while (!feof(\\$fp)) {{"
            f"  \\$line = fgets(\\$fp, 1024);"
            f"  \\$out .= \\$line;"
            f"  if (trim(\\$line) === 'END') break;"
            f"}}"
            f"fwrite(\\$fp, \\\"quit\\\\n\\\");"
            f"fclose(\\$fp);"
            f"echo \\$out;"
            f"\""
        )
        results.append(f"=== {sock} ===\n{raw}")
    output = "\n".join(results)

    if "CLIENT LIST" not in output:
        return "Aucun client VPN connecté"

    lines = output.splitlines()
    clients = []
    in_clients = False
    for line in lines:
        if line.startswith("Common Name"):
            in_clients = True
            continue
        if line.startswith("ROUTING TABLE"):
            break
        if in_clients and line.strip():
            parts = line.split(",")
            if len(parts) >= 5:
                name, real_ip, bytes_rx, bytes_tx, since = parts[0], parts[1], parts[2], parts[3], ",".join(parts[4:])
                clients.append(f"- {name} | IP: {real_ip} | Reçu: {bytes_rx}B | Envoyé: {bytes_tx}B | Connecté depuis: {since}")

    return "\n".join(clients) if clients else "Aucun client VPN connecté"


@mcp.tool()
def get_firewall_logs(lines: int = 20) -> str:
    """Get last firewall log entries showing blocked/passed packets (source IP, dest IP, port, action)"""
    output = ssh_run(f"tail -{lines} /var/log/filter.log 2>/dev/null || grep filterlog /var/log/system.log 2>/dev/null | tail -{lines}")
    return output if output else "Aucun log firewall disponible"


@mcp.tool()
def get_dhcp_leases() -> str:
    """List active DHCP leases: hostname, IP address, MAC address and lease expiry"""
    raw = ssh_run("cat /var/dhcpd/var/db/dhcpd.leases 2>/dev/null")
    if not raw:
        return "Aucun bail DHCP actif trouvé"

    leases = {}
    current_ip = None
    for line in raw.splitlines():
        line = line.strip()
        if line.startswith("lease "):
            current_ip = line.split()[1]
            leases.setdefault(current_ip, {})
        elif current_ip:
            if "binding state active" in line:
                leases[current_ip]["active"] = True
            elif "hardware ethernet" in line:
                leases[current_ip]["mac"] = line.split()[-1].rstrip(";")
            elif "client-hostname" in line:
                leases[current_ip]["hostname"] = line.split()[-1].strip('";')
            elif line.startswith("ends "):
                leases[current_ip]["expires"] = " ".join(line.split()[2:]).rstrip(";")

    active = {ip: d for ip, d in leases.items() if d.get("active")}
    if not active:
        return "Aucun bail DHCP actif trouvé"

    result = []
    for ip, d in active.items():
        hostname = d.get("hostname", "inconnu")
        mac = d.get("mac", "inconnu")
        expires = d.get("expires", "inconnu")
        result.append(f"- {ip} | {hostname} | MAC: {mac} | Expire: {expires}")
    return "\n".join(result)


@mcp.tool()
def get_routing_table() -> str:
    """Get pfSense routing table: all active routes with destination, gateway and interface"""
    output = ssh_run("netstat -rn")
    return output


if __name__ == "__main__":
    mcp.run(transport="stdio")
