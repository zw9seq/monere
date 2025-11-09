import os
import json
import threading
from datetime import datetime
from typing import Dict, Any

DATA_DIR = "data"
NETWORKS_FILE = os.path.join(DATA_DIR, "networks.json")
ONLINE_THRESHOLD = 3600  # segundos (1 hora)
_lock = threading.Lock()

# ---------------------------
# Helpers genéricos
# ---------------------------
def _ensure_data_dir():
    os.makedirs(DATA_DIR, exist_ok=True)

def _now_iso() -> str:
    return datetime.now().isoformat(timespec="seconds")

# ---------------------------
# Gestión del fichero "networks.json"
# ---------------------------
def _load_all() -> Dict[str, Any]:
    """
    Carga la estructura principal que contiene 'networks'.
    Devuelve {'networks': {...}, ...} mínimo.
    """
    _ensure_data_dir()
    if not os.path.exists(NETWORKS_FILE):
        return {"networks": {}}
    try:
        with open(NETWORKS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, FileNotFoundError):
        return {"networks": {}}

def _save_all(data: Dict[str, Any]):
    _ensure_data_dir()
    with _lock:
        with open(NETWORKS_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

def list_networks() -> Dict[str, Any]:
    data = _load_all()
    return data.get("networks", {})

def create_network(network_id: str, name: str, cidr: str) -> Dict[str, Any]:
    data = _load_all()
    networks = data.setdefault("networks", {})
    if network_id in networks:
        return networks[network_id]
    networks[network_id] = {
        "id": network_id,
        "name": name,
        "cidr": cidr,
        "created_at": _now_iso(),
        "device_count": 0,
        "last_scan": None
    }
    _save_all(data)
    # ensure devices file exists
    save_devices(network_id, {})
    return networks[network_id]

def get_network_cidr(network_id: str) -> str | None:
    data = _load_all()
    net = data.get("networks", {}).get(network_id)
    return net.get("cidr") if net else None

# ---------------------------
# Gestión de redes
# ---------------------------

def update_network(network_id: str, name: str | None = None, cidr: str | None = None):
    data = _load_all()
    nets = data.setdefault("networks", {})
    net = nets.get(network_id)
    if not net:
        raise ValueError(f"Network {network_id} not found")

    if name:
        net["name"] = name
    if cidr:
        net["cidr"] = cidr
    net["updated_at"] = _now_iso()
    _save_all(data)
    return net


def delete_network(network_id: str):
    """
    Elimina la red del archivo networks.json y su archivo de dispositivos asociado.
    """
    data = _load_all()
    nets = data.get("networks", {})

    if network_id in nets:
        nets.pop(network_id)
        _save_all(data)

    # Buscar y eliminar ficheros relacionados con esta red
    deleted_any = False
    for filename in os.listdir(DATA_DIR):
        if filename.startswith("devices_") and network_id in filename:
            try:
                os.remove(os.path.join(DATA_DIR, filename))
                deleted_any = True
            except Exception as e:
                print(f"[ADVERTENCIA] No se pudo eliminar {filename}: {e}")

    # Seguridad adicional: eliminar el archivo exacto
    path = _devices_file(network_id)
    if os.path.exists(path):
        try:
            os.remove(path)
            deleted_any = True
        except Exception as e:
            print(f"[ADVERTENCIA] No se pudo eliminar {path}: {e}")

    if not deleted_any:
        print(f"[INFO] No se encontró archivo de dispositivos para la red {network_id}")

# ---------------------------
# Gestión de dispositivos por red
# ---------------------------
def _devices_file(network_id: str) -> str:
    _ensure_data_dir()
    # ruta: data/devices_<network_id>.json
    safe_id = str(network_id)
    return os.path.join(DATA_DIR, f"devices_{safe_id}.json")

def load_devices(network_id: str) -> Dict[str, Any]:
    """
    Carga y devuelve el dict de dispositivos para la red dada.
    Si no existe el fichero, devuelve {} sin error.
    """
    path = _devices_file(network_id)
    if not os.path.exists(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, FileNotFoundError):
        return {}

def save_devices(network_id: str, devices: Dict[str, Any]):
    """
    Guarda el dict de dispositivos para la red dada.
    """
    path = _devices_file(network_id)
    _ensure_data_dir()
    with _lock:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(devices, f, indent=2, ensure_ascii=False)

def update_device(network_id: str,
                  mac: str,
                  ip: str | None = None,
                  status: str | None = None,
                  name: str | None = None) -> Dict[str, Any]:
    """
    Actualiza (o crea) un dispositivo identificado por `mac` dentro de la red `network_id`.
    - normaliza la MAC (lowercase)
    - actualiza ip/name/status si se pasan
    - si status == 'online' o si se actualiza la ip, se pone last_seen = ahora
    Devuelve el dict del dispositivo actualizado.
    """
    if mac is None:
        raise ValueError("mac is required")

    mac_key = str(mac)
    devices = load_devices(network_id)
    dev = devices.get(mac_key, {})

    if ip is not None:
        dev["ip"] = ip

    if name is not None:
        dev["name"] = name

    # Actualiza status si se pasa como argumento
    if status is not None:
        dev["status"] = status

    # Actualiza last_seen si tiene IP nueva o pasa a online
    if (status is not None and status == "online") or ip is not None:
        dev["last_seen"] = _now_iso()

    # Recalcula automáticamente el estado actual
    computed_status = compute_device_status(dev)
    dev["status"] = computed_status

    devices[mac_key] = dev
    save_devices(network_id, devices)

    # actualizar metadatos de la red (device_count, last_scan)
    try:
        data = _load_all()
        nets = data.setdefault("networks", {})
        net = nets.get(network_id)
        if net is not None:
            net["device_count"] = len(devices)
            # actualizar last_scan solo si online (opcional)
            if status == "online":
                net["last_scan"] = _now_iso()
            _save_all(data)
    except Exception:
        # no crítico — continuar
        pass

    return dev

def delete_host(network_id: str, mac: str):
    """
    Elimina un host específico de una red del archivo devices_<network_id>.json.
    """
    path = _devices_file(network_id)
    if not os.path.exists(path):
        print(f"[ADVERTENCIA] No existe el archivo de dispositivos para la red {network_id}")
        return

    try:
        with open(path, "r", encoding="utf-8") as f:
            devices = json.load(f)
    except Exception as e:
        print(f"[ERROR] No se pudo leer el archivo {path}: {e}")
        return

    if mac in devices:
        devices.pop(mac)
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(devices, f, indent=2, ensure_ascii=False)
            print(f"[INFO] Host {mac} eliminado correctamente de la red {network_id}")
        except Exception as e:
            print(f"[ERROR] No se pudo guardar el archivo tras eliminar el host: {e}")
    else:
        print(f"[INFO] No se encontró el host {mac} en la red {network_id}")

def compute_device_status(dev: dict) -> str:
    """Devuelve 'online' si el dispositivo se ha visto en la última hora, 'offline' en caso contrario."""
    last_seen_str = dev.get("last_seen")
    if not last_seen_str:
        return "offline"
    try:
        last_seen = datetime.fromisoformat(last_seen_str)
    except Exception:
        return "offline"
    if (datetime.now() - last_seen).total_seconds() <= ONLINE_THRESHOLD:
        return "online"
    return "offline"

def refresh_all_device_statuses(network_id: str):
    """
    Recalcula y actualiza el campo 'status' de todos los dispositivos
    según su 'last_seen' almacenado.
    """
    devices = load_devices(network_id)
    changed = False
    for mac, dev in devices.items():
        new_status = compute_device_status(dev)
        if dev.get("status") != new_status:
            dev["status"] = new_status
            changed = True
    if changed:
        save_devices(network_id, devices)

# Exportar nombres esperados por otros módulos
__all__ = [
    "load_devices", "save_devices", "update_device",
    "list_networks", "create_network", "_load_all",
    "get_network_cidr"
]
