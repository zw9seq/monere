# app/main.py
from fastapi import FastAPI, Request, Form, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
import asyncio, subprocess, uuid, time, os, json
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
import ipaddress, threading
from starlette.middleware.base import BaseHTTPMiddleware

from .network import (
    scan_network_for, ping_sweep, get_default_interface_network,
    discover_ports_with_nmap, service_scan_with_nmap
)
from .storage import (
    load_devices, save_devices, update_device,
    create_network, list_networks, _load_all, get_network_cidr,
    update_network, delete_network, refresh_all_device_statuses
)

# ================================================================
# App & Templates
# ================================================================
app = FastAPI()
templates = Jinja2Templates(directory="app/templates")

NETWORKS_FILE = os.path.join("data", "networks.json")


OUI_PATH = os.path.join(os.path.dirname(__file__), "..", "config", "oui.json")
OUI_PATH = os.path.abspath(OUI_PATH)

try:
    with open(OUI_PATH, "r", encoding="utf-8") as f:
        OUI_DB = json.load(f)
    print(f"OUI database cargada con {len(OUI_DB)} entradas desde {OUI_PATH}.")
except Exception as e:
    print(f"[WARN] No se pudo cargar oui.json ({OUI_PATH}): {e}")
    OUI_DB = {}

# ================================================================
# Funciones al arranque de la app
# ================================================================

@app.on_event("startup")
async def on_startup():
    networks = list_networks()
    for network_id in networks.keys():
        refresh_all_device_statuses(network_id)
    print("[INFO] Estados actualizados al iniciar la app.")
    asyncio.create_task(background_scanner())
    
# ================================================================
# Parar tcpdump al cerrar la app
# ================================================================
    
@app.on_event("shutdown")
async def cleanup_sniffers():
    for scan_id in list(sniff_sessions.keys()):
        stop_tcpdump_sniffer(scan_id)
        
# ================================================================
# Estado global
# ================================================================
active_network: str | None = None                # red seleccionada actualmente
ONLINE_THRESHOLD = 3600  # segundos, 1 hora

ping_sweep_status: dict = {}                      # estado de ping sweep por network_id
port_scan_status: dict = {}                       # estado de port scans por scan_id

# Executor y semáforo para limitar nmap concurrentes
_executor = ThreadPoolExecutor(max_workers=3)
_nmap_semaphore = asyncio.Semaphore(3)

# mapa local para relacionar scan_id -> metadata (network_id, mac, ip)
sniff_sessions = {}

# ================================================================
# Utilidades
# ================================================================
def is_private_ip(ip: str) -> bool:
    """Valida si la IP es privada (seguridad para escaneo)."""
    try:
        return ipaddress.ip_address(ip).is_private
    except Exception:
        return False

def set_active_network(network_id: str):
    """Marca la red actual como activa."""
    global active_network
    active_network = network_id
    print(f"[INFO] Red activa establecida: {network_id}")

           
def get_device_status(dev: dict) -> str:
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

def get_mac_vendor(mac: str) -> str:
    """
    Devuelve el nombre del fabricante (vendor) según los 3 primeros bytes de la MAC.
    Usa el archivo local oui.json previamente cargado.
    """
    if not mac:
        return "Desconocido"
    clean_mac = mac.upper().replace(":", "").replace("-", "")
    prefix = clean_mac[:6]  # Ej: "404F42"
    return OUI_DB.get(prefix, "Desconocido")

# ================================================================
# Control de acceso único por IP
# ================================================================
app_in_use = False
app_last_client_ip = None
last_activity = 0
MAX_INACTIVITY = 500  # segundos (5 min)

def log_access(event: str, client_ip: str):
    """Registrar eventos de acceso con hora legible"""
    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [{event}] Usuario: {client_ip}")

class SingleUserMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        global app_in_use, last_user_ip, last_activity

        client_ip = request.client.host
        now = time.time()

        # Si el usuario actual es el mismo y sigue activo → actualizamos su timestamp
        if app_in_use and client_ip == last_user_ip:
            last_activity = now
            return await call_next(request)

        # Si hay otro usuario, comprobamos si ha expirado
        if app_in_use and client_ip != last_user_ip:
            if now - last_activity < MAX_INACTIVITY:
                # Bloqueamos el acceso
                log_access("ACCESO BLOQUEADO (en uso)", client_ip)
                return HTMLResponse("""
                <!DOCTYPE html>
                <html lang="es">
                <head>
                  <meta charset="UTF-8">
                  <title>Acceso denegado</title>
                  <script src="https://cdn.tailwindcss.com"></script>
                </head>
                <body class="bg-gray-900 text-gray-100 flex items-center justify-center min-h-screen">
                  <div class="text-center bg-gray-800 p-8 rounded-2xl shadow-lg border border-gray-700">
                    <h1 class="text-3xl font-bold text-red-400 mb-4">⚠️ Aplicación en uso</h1>
                    <p class="text-gray-300">Actualmente la aplicación está siendo utilizada por otro usuario.</p>
                    <p class="text-gray-400 mt-2">Vuelve a intentarlo más tarde.</p>
                  </div>
                </body>
                </html>
                """, status_code=403)
            else:
                # Timeout de inactividad alcanzado → liberamos bloqueo
                log_access("SESIÓN EXPIRADA", last_user_ip)
                app_in_use = False
                last_user_ip = None

        # Si llegamos aquí, nadie está usando la app → asignamos control al nuevo usuario
        app_in_use = True
        last_user_ip = client_ip
        last_activity = now
        log_access("NUEVO USUARIO CONECTADO", client_ip)
        return await call_next(request)

# Añadimos el middleware a FastAPI
app.add_middleware(SingleUserMiddleware)

# ================================================================
# Keepalive para mantener sesión activa
# ================================================================
@app.get("/keepalive")
async def keepalive():
    global last_activity
    last_activity = time.time()
    return {"status": "ok", "ts": last_activity}

# ================================================================
# Rutas: listado / creación de redes
# ================================================================
@app.get("/", response_class=HTMLResponse)
@app.get("/networks", response_class=HTMLResponse)
async def networks_index(request: Request):
    networks = list_networks()
    return templates.TemplateResponse("networks.html", {"request": request, "networks": networks})

@app.post("/networks/create")
async def networks_create(name: str = Form(...), cidr: str = Form(...)):
    net_id = str(uuid.uuid4())[:8]
    create_network(net_id, name, cidr)
    return RedirectResponse(url=f"/network/{net_id}", status_code=303)

# ================================================================
# Editar red existente
# ================================================================
@app.post("/networks/{network_id}/edit")
async def networks_edit(
    network_id: str,
    name: str = Form(None),
    cidr: str = Form(None)
):
    try:
        update_network(network_id, name=name, cidr=cidr)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    return RedirectResponse(url="/networks", status_code=303)

# ================================================================
# Borrar red
# ================================================================
@app.post("/networks/{network_id}/delete")
async def networks_delete(network_id: str):
    delete_network(network_id)
    return RedirectResponse(url="/networks", status_code=303)

# ================================================================
# Panel de red individual
# ================================================================
@app.get("/network/{network_id}", response_class=HTMLResponse)
async def view_network(request: Request, network_id: str):
    networks = list_networks()
    network = networks.get(network_id)
    if not network:
        return RedirectResponse(url="/networks", status_code=303)

    set_active_network(network_id)
    devices = load_devices(network_id)

    # ⚡️ Extraer el nombre de la red (por si acaso no lo tuviera)
    network_name = network.get("name", f"Red {network_id[:4]}")

    return templates.TemplateResponse("index.html", {
        "request": request,
        "network_id": network_id,
        "network_name": network_name,
        "network": network,
        "devices": devices,
    })

# ================================================================
# Panel de host individual
# ================================================================
@app.get("/host/{mac}", response_class=HTMLResponse)
async def host_detail(request: Request, mac: str):
    # Detectar si la petición viene de fetch() o es navegación normal
    is_ajax = request.headers.get("x-requested-with") == "XMLHttpRequest" or "fetch" in request.headers.get("accept", "")

    # Si no hay red activa
    if not active_network:
        # En llamadas AJAX devolvemos error en JSON
        if is_ajax:
            return JSONResponse({"error": "No active network"}, status_code=400)
        # En navegación normal, redirigimos como antes
        return templates.TemplateResponse(
            "networks.html",
            {"request": request, "networks": list_networks()},
            status_code=200,
        )

    # Buscar el dispositivo
    devices = load_devices(active_network)
    dev = devices.get(mac)

    if not dev:
        if is_ajax:
            return JSONResponse({"error": "Device not found"}, status_code=404)
        return templates.TemplateResponse(
            "index.html",
            {
                "request": request,
                "network_id": active_network,
                "network": list_networks().get(active_network, {}),
                "devices": devices,
            },
            status_code=200,
        )

    vendor = get_mac_vendor(mac)
    return templates.TemplateResponse("host.html", {
        "request": request,
        "network_id": active_network,
        "mac": mac,
        "device": dev,
        "vendor": vendor
    })

# ================================================================
# API Devices
# ================================================================
@app.get("/api/{network_id}/devices")
async def api_devices(network_id: str):
    devices = load_devices(network_id)
    # calcular estado al vuelo
    for mac, dev in devices.items():
        dev["status"] = get_device_status(dev)
    return JSONResponse(devices)

@app.post("/update_name/{network_id}")
async def update_name(network_id: str, mac: str = Form(...), name: str = Form(...)):
    devices = load_devices(network_id)
    devices[mac] = devices.get(mac, {})
    devices[mac]["name"] = name
    save_devices(network_id, devices)
    return {"mac": mac, "name": name}

# ================================================================
# Ping
# ================================================================
@app.post("/ping/{network_id}/{mac}")
async def ping_device(network_id: str, mac: str):
    devices = load_devices(network_id)
    dev = devices.get(mac)
    if not dev:
        raise HTTPException(status_code=404, detail="Device not found")
    ip = dev.get("ip")
    if not ip:
        raise HTTPException(status_code=400, detail="No IP for device")

    result = subprocess.run(
        ["ping", "-c", "1", "-W", "1", ip],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    status = "online" if result.returncode == 0 else "offline"
    updated = update_device(network_id, mac, ip=ip if status=="online" else None, status=status)
    return {"mac": mac, "status": updated.get("status"), "last_seen": updated.get("last_seen")}

# ================================================================
# Actualizar nota del dispositivo
# ================================================================

@app.post("/update_note/{network_id}/{mac}")
async def update_note(network_id: str, mac: str, request: Request):
    data = await request.json()
    note = data.get("note", "").strip()

    if len(note) > 500:
        raise HTTPException(status_code=400, detail="La nota supera el límite de 500 caracteres.")

    devices = load_devices(network_id)
    dev = devices.get(mac)
    if not dev:
        raise HTTPException(status_code=404, detail="Device not found")

    dev["note"] = note
    save_devices(network_id, devices)

    return {"status": "ok", "note": note}

# ================================================================
# ARP Scan manual
# ================================================================
@app.post("/scan/{network_id}/arp")
async def scan_arp(network_id: str):
    devices = scan_network_for(network_id)
    return {"status": "ok", "count": len(devices)}

# ================================================================
# Ping Sweep 
# ================================================================
@app.post("/scan/{network_id}/ping_sweep")
async def start_ping_sweep(network_id: str):

    if network_id not in ping_sweep_status:
        ping_sweep_status[network_id] = {
            "running": False,
            "started_at": None,
            "finished_at": None,
            "processed": 0,
            "total": 0,
            "found_count": 0,
            "found_ips": []
        }
    status = ping_sweep_status[network_id]
    if status["running"]:
        return {"status": "already_running"}

    target = get_network_cidr(network_id) or get_default_interface_network()
    status.update({
        "running": True,
        "started_at": datetime.now().isoformat(timespec="seconds"),
        "processed": 0,
        "total": 0,
        "found_count": 0,
        "found_ips": []
    })

    def progress_cb(processed, total, found_count):
        s = ping_sweep_status.get(network_id)
        if s is not None:
            s["processed"] = processed
            s["total"] = total
            s["found_count"] = found_count

    async def runner():
        try:
            found = await ping_sweep(network_id, target, timeout=1, concurrency=120, progress_cb=progress_cb)
            s = ping_sweep_status.get(network_id)
            if s is not None:
                s["found_ips"] = found
                s["found_count"] = len(found)
        except Exception as e:
            ping_sweep_status[network_id]["error"] = str(e)
        finally:
            s = ping_sweep_status.get(network_id)
            if s is not None:
                s["running"] = False
                s["finished_at"] = datetime.now().isoformat(timespec="seconds")

    asyncio.create_task(runner())
    return {"status": "started", "network_id": network_id, "target": target}


@app.get("/scan/{network_id}/ping_sweep/status")
async def ping_sweep_status_api(network_id: str):
    return ping_sweep_status.get(network_id, {"running": False, "processed": 0, "total": 0, "found_count": 0})


@app.get("/scan/{network_id}/ping_sweep/result")
async def ping_sweep_result(network_id: str):
    s = ping_sweep_status.get(network_id)
    if not s:
        return {"found_count": 0, "found_ips": []}
    return {"found_count": s.get("found_count", 0), "found_ips": s.get("found_ips", [])}


# ================================================================
# Background scanner (ARP automático)
# ================================================================
async def background_scanner():
    while True:
        try:
            if active_network:
                try:
                    scan_network_for(active_network)
                except Exception as e:
                    print(f"[background_scanner] error scanning {active_network}: {e}")
        except Exception as e:
            print(f"[background_scanner] unexpected error: {e}")
        await asyncio.sleep(15)

# ================================================================
# Port scan por host
# ================================================================
async def start_host_portscan(network_id: str, mac: str, ip: str) -> str:
    scan_id = str(uuid.uuid4())[:8]
    port_scan_status[scan_id] = {
        "running": True,
        "network_id": network_id,
        "mac": mac,
        "ip": ip,
        "started_at": time.time(),
        "processed_step": 0,
        "total_steps": 2,
        "result": None,
        "error": None
    }

    async def runner():
        async with _nmap_semaphore:
            try:
                ports = await asyncio.get_event_loop().run_in_executor(_executor, discover_ports_with_nmap, ip)
                port_scan_status[scan_id]["processed_step"] = 1 
                svc_result = await asyncio.get_event_loop().run_in_executor(_executor, service_scan_with_nmap, ip, ports) if ports else {}
                devices = load_devices(network_id)
                dev = devices.get(mac, {})
                dev["ip"] = ip
                dev["ports"] = {str(p): svc_result.get(p, {"state": "open", "service": {}}) for p in ports}
                dev["last_portscan"] = datetime.now().isoformat(timespec="seconds")
                devices[mac] = dev
                save_devices(network_id, devices)   
                port_scan_status[scan_id]["result"] = {"ports": dev["ports"]}
            except Exception as e:
                port_scan_status[scan_id]["error"] = str(e)
            finally:
                port_scan_status[scan_id]["running"] = False
                port_scan_status[scan_id]["finished_at"] = time.time()

    asyncio.create_task(runner())
    return scan_id

@app.post("/scan/{network_id}/{mac}/ports")
async def api_start_host_ports_scan(network_id: str, mac: str):
    devices = load_devices(network_id)
    dev = devices.get(mac)
    if not dev:
        raise HTTPException(status_code=404, detail="Device not found")
    ip = dev.get("ip")
    if not ip:
        raise HTTPException(status_code=400, detail="Device has no IP")
    if not is_private_ip(ip):
        raise HTTPException(status_code=400, detail="IP not allowed")

    scan_id = await start_host_portscan(network_id, mac, ip)
    return {"status": "started", "scan_id": scan_id}

@app.get("/scan/ports/{scan_id}/status")
async def portscan_status(scan_id: str):
    return port_scan_status.get(scan_id, {"running": False})


# ================================================================
# Sniffing de tráfico
# ================================================================

def start_tcpdump_sniffer(scan_id: str, iface: str, target_ip: str):
    """
    Inicia un sniffer tcpdump en background sobre un host específico.
    """
    cmd = ["tcpdump", "-n", "-l", "-i", iface, "-U", f"host {target_ip}"]
    print(f"[+] Starting tcpdump sniffer {scan_id} on iface={iface} target={target_ip}")
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            bufsize=1
        )
    except Exception as e:
        raise RuntimeError(f"tcpdump start failed: {e}")

    sniff_sessions[scan_id] = {
        "iface": iface,
        "ip": target_ip,
        "captured_at": datetime.now().isoformat(timespec="seconds"),
        "total_packets": 0,
        "total_bytes": 0,
        "packets": [],      # historial completo en memoria (no guardado)
        "status": "running",
        "proc": proc,
    }

    def reader():
        for line in proc.stdout:
            sess = sniff_sessions.get(scan_id)
            if not sess or not sess.get("running", True):
                break
            line_str = line.strip()
            sess["total_packets"] += 1
            sess["packets"].append(line_str)

            # límite de memoria (últimos 500)
            if len(sess["packets"]) > 500:
                sess["packets"] = sess["packets"][-500:]

        # cuando termina el bucle
        sess = sniff_sessions.get(scan_id)
        if sess:
            sess["status"] = "stopped"
        print(f"[-] tcpdump sniffer {scan_id} stopped")

    threading.Thread(target=reader, daemon=True).start()
    return scan_id


def stop_tcpdump_sniffer(scan_id: str):
    sess = sniff_sessions.get(scan_id)
    if not sess:
        raise HTTPException(status_code=404, detail="Sniffer not found")

    proc = sess.get("proc")
    if proc and hasattr(proc, "terminate"):
        try:
            proc.terminate()
        except Exception as e:
            print(f"[WARN] Error terminating sniffer: {e}")
    sess["status"] = "stopped"
    sess["running"] = False
    print(f"[x] tcpdump sniffer {scan_id} terminated")


@app.post("/sniff/{network_id}/{mac}/start")
async def start_sniffer(network_id: str, mac: str):
    devices = load_devices(network_id)
    dev = devices.get(mac)
    if not dev:
        raise HTTPException(status_code=404, detail="Device not found")

    ip = dev.get("ip")
    if not ip:
        raise HTTPException(status_code=400, detail="Device has no IP")

    # Obtener interfaz local
    try:
        from .network import get_default_interface_network
        iface = get_default_interface_network(return_iface=True)
    except Exception as e:
        print(f"[WARN] Error detecting interface: {e}")
        iface = os.getenv("DEFAULT_IFACE", "eth0")

    if not iface:
        raise HTTPException(status_code=400, detail="No network interface available")

    scan_id = str(uuid.uuid4())[:8]
    start_tcpdump_sniffer(scan_id, iface, ip)
    return {"status": "started", "scan_id": scan_id, "iface": iface, "target": ip}


@app.get("/sniff/{scan_id}/status")
async def sniff_status(scan_id: str, last_index: int = 0):
    """
    Devuelve solo los nuevos paquetes desde last_index para permitir scroll incremental.
    """
    sess = sniff_sessions.get(scan_id)
    if not sess:
        return {"status": "not_found"}

    packets = sess.get("packets", [])
    new_packets = packets[last_index:]
    next_index = last_index + len(new_packets)

    return {
        "status": sess.get("status"),
        "iface": sess.get("iface"),
        "ip": sess.get("ip"),
        "new_packets": new_packets,
        "next_index": next_index,
        "total_packets": len(packets),
    }


@app.post("/sniff/{scan_id}/stop")
async def stop_sniffer(scan_id: str):
    sess = sniff_sessions.get(scan_id)
    if not sess:
        raise HTTPException(status_code=404, detail="Sniffer not found")

    stop_tcpdump_sniffer(scan_id)

    # guardar resumen en DB (solo lo último, como antes)
    if sess.get("ip") and sess.get("iface"):
        devices = load_devices(active_network)
        for mac, d in devices.items():
            if d.get("ip") == sess["ip"]:
                d["traffic_stats"] = {
                    "ip": sess["ip"],
                    "iface": sess["iface"],
                    "captured_at": sess["captured_at"],
                    "total_packets": sess["total_packets"],
                    "last_packets": sess.get("packets", [])[-10:],
                }
                devices[mac] = d
                break
        save_devices(active_network, devices)

    return {"status": "stopped", "scan_id": scan_id}
