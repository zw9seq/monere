import netifaces
from scapy.all import ARP, Ether, srp
import platform
import subprocess
from datetime import datetime
import asyncio
from asyncio.subprocess import PIPE
from ipaddress import ip_network
from typing import List, Dict
import xml.etree.ElementTree as ET

from .storage import load_devices, save_devices, update_device, list_networks, _load_all

# ================================================================
# UTILIDADES DE RED
# ================================================================

def get_default_interface_network(return_iface=False):
    """
    Devuelve la interfaz de red principal y su información (gateway, ip, netmask).
    Si return_iface=True, solo devuelve el nombre de la interfaz.
    """
    try:
        gws = netifaces.gateways()
        default = gws.get('default', {})
        iface = None

        # Intentar con IPv4 o IPv6
        if netifaces.AF_INET in default:
            iface = default[netifaces.AF_INET][1]
        elif netifaces.AF_INET6 in default:
            iface = default[netifaces.AF_INET6][1]

        if not iface:
            raise RuntimeError("No se encontró interfaz de salida por defecto")

        addrs = netifaces.ifaddresses(iface)
        ipv4_info = addrs.get(netifaces.AF_INET, [{}])[0]
        network_info = {
            "iface": iface,
            "ip": ipv4_info.get("addr"),
            "netmask": ipv4_info.get("netmask"),
            "gateway": gws.get('default', {}).get(netifaces.AF_INET, [None])[0],
        }

        return iface if return_iface else (iface, network_info)

    except Exception as e:
        print(f"[!] Error obteniendo interfaz por defecto: {e}")
        if return_iface:
            return None
        return None, {}

# ================================================================
# ESCANEO ARP
# ================================================================
def scan_network_for(network_id: str, timeout=2):
    """Escanea la red vía ARP y actualiza el storage con los dispositivos encontrados."""
    data = _load_all()
    net = data["networks"].get(network_id)
    if not net:
        raise KeyError("network not found")
    cidr = net["cidr"]

    packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=cidr)
    result = srp(packet, timeout=timeout, verbose=0)[0]

    found_macs = []
    for _, received in result:
        mac = received.hwsrc.lower()
        ip = received.psrc
        update_device(network_id, mac, ip=ip, status="online")
        found_macs.append(mac)

    # marcar offline los no detectados
    devices = load_devices(network_id)
    for mac in list(devices.keys()):
        if mac not in found_macs:
            update_device(network_id, mac, status="offline")

    return load_devices(network_id)

# ================================================================
# PING SIMPLE
# ================================================================
def ping_host(ip: str) -> bool:
    """Realiza un ping a la IP y devuelve True si responde."""
    param = "-n" if platform.system().lower() == "windows" else "-c"
    try:
        result = subprocess.run(
            ["ping", param, "1", ip],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        return result.returncode == 0
    except Exception:
        return False

# ================================================================
# PING SWEEP ASÍNCRONO
# ================================================================
async def _ping_one(ip: str, timeout_sec: int = 1) -> bool:
    """Ping individual asincrónico para ping sweep."""
    param = "-n" if platform.system().lower() == "windows" else "-c"
    timeout_flag = "-W" if platform.system().lower() != "windows" else "-w"
    args = ["ping", param, "1", timeout_flag, str(timeout_sec), ip]
    try:
        proc = await asyncio.create_subprocess_exec(*args, stdout=PIPE, stderr=PIPE)
        await proc.communicate()
        return proc.returncode == 0
    except Exception:
        return False

def _get_mac_from_arp_table(ip: str) -> str | None:
    """Intenta resolver la MAC de una IP desde la tabla ARP local."""
    try:
        with open("/proc/net/arp", "r") as f:
            lines = f.readlines()[1:]
        for line in lines:
            parts = line.split()
            if len(parts) >= 4:
                ip_entry = parts[0]
                mac = parts[3]
                if ip_entry == ip and mac != "00:00:00:00:00:00":
                    return mac.lower()
    except FileNotFoundError:
        pass
    return None

async def ping_sweep(network_id: str,
                     target: str,
                     timeout: int = 1,
                     concurrency: int = 100,
                     progress_cb = None):
    """
    Realiza un ping sweep sobre la red 'target' (ej. '192.168.1.0/24').
    Actualiza storage con los hosts que respondan.
    """
    net = ip_network(target)
    ips = [str(ip) for ip in net.hosts()]
    total = len(ips)

    semaphore = asyncio.Semaphore(concurrency)
    processed = 0
    found = []

    async def worker(ip_addr):
        nonlocal processed, found
        async with semaphore:
            ok = await _ping_one(ip_addr, timeout_sec=timeout)
            processed += 1
            if ok:
                await asyncio.sleep(0.05)  # esperar que kernel actualice ARP
                mac = _get_mac_from_arp_table(ip_addr)
                if mac:
                    update_device(network_id, mac, ip=ip_addr, status="online")
                else:
                    pseudo_mac = f"ip:{ip_addr}"
                    devices = load_devices(network_id)
                    devices[pseudo_mac] = {
                        "ip": ip_addr,
                        "status": "online",
                        "last_seen": datetime.now().isoformat(timespec="seconds"),
                    }
                    save_devices(network_id, devices)
                found.append(ip_addr)

            if callable(progress_cb):
                try:
                    progress_cb(processed, total, len(found))
                except Exception:
                    pass

    tasks = [asyncio.create_task(worker(ip)) for ip in ips]
    await asyncio.gather(*tasks)
    return found

# ================================================================
# ESCANEO DE PUERTOS (NMAP)
# ================================================================
def _run_nmap_command(cmd: List[str], timeout: int = 300) -> str:
    """Ejecuta nmap y devuelve stdout (XML)."""
    proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=timeout)
    return proc.stdout

def discover_ports_with_nmap(ip: str, timeout: int = 300) -> List[int]:
    """
    Paso 1: descubre puertos abiertos rápido (equivalente a nmap -p- --min-rate=1000 -Pn -T4).
    Devuelve lista de puertos abiertos.
    """
    cmd = ["nmap", "-p-", "--min-rate", "1000", "-Pn", "-T4", "-oX", "-", ip]
    xml = _run_nmap_command(cmd, timeout=timeout)
    root = ET.fromstring(xml)
    ports = []
    for host in root.findall("host"):
        for ports_node in host.findall("ports"):
            for port in ports_node.findall("port"):
                state_node = port.find("state")
                if state_node is None:
                    continue
                state = state_node.attrib.get("state", "")
                if state == "open":
                    try:
                        ports.append(int(port.attrib["portid"]))
                    except Exception:
                        pass
    return sorted(set(ports))

def service_scan_with_nmap(ip: str, ports: List[int], timeout: int = 300) -> Dict[int, Dict]:
    """
    Paso 2: escaneo detallado con -sC -sV de los puertos listados.
    Devuelve dict {port: {"state":..., "service": {"name":..., "product":..., "version":...}}}.
    """
    ports_arg = ",".join(str(p) for p in ports) if ports else "1-1024"
    cmd = ["nmap", "-p", ports_arg, "-Pn", "-sC", "-sV", "-oX", "-", ip]
    xml = _run_nmap_command(cmd, timeout=timeout)
    root = ET.fromstring(xml)
    res = {}
    for host in root.findall("host"):
        for ports_node in host.findall("ports"):
            for port in ports_node.findall("port"):
                try:
                    portid = int(port.attrib.get("portid"))
                except Exception:
                    continue
                state_node = port.find("state")
                state = state_node.attrib.get("state", "") if state_node is not None else ""
                svc_node = port.find("service")
                svc = {}
                if svc_node is not None:
                    svc["name"] = svc_node.attrib.get("name")
                    svc["product"] = svc_node.attrib.get("product")
                    svc["version"] = svc_node.attrib.get("version")
                    svc["extrainfo"] = svc_node.attrib.get("extrainfo")
                res[portid] = {"state": state, "service": svc}
    return res