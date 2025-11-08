# 🛰️ Monere — Network Device Scanner & Dashboard

Monere is a lightweight web application built with **FastAPI** that allows users to **scan local networks**, **identify connected devices**, and **display detailed information** such as IP, MAC address, manufacturer, and connection status.  
It’s designed for local network monitoring with a modern, minimal interface and can be easily deployed in a **Docker container**.

---

## 🚀 **Features**

* 🕵️‍♂️ **Network Discovery** — Perform full subnet scans to identify active devices using **ICMP ping sweeps**.
* 🧭 **ARP-Based MAC Resolution** — Retrieve each device’s hardware (MAC) address and resolve its manufacturer using the **OUI database**.
* 🔍 **Port Scanning with Nmap** — Analyze each host to detect **open ports and active services**.
* 📡 **Live Packet Sniffing** — Capture and inspect live traffic from selected interfaces for network activity monitoring.
* 🌐 **Interactive Web Dashboard** — View all devices, scan history, and host details in a **modern Tailwind-powered interface**.
* 💾 **Persistent Data Storage** — Network and host data are saved under `/data` for persistence between container restarts.
* 🐳 **Containerized Deployment** — Fully operational via **Docker** with simple `docker compose up -d` setup.
* ⚙️ **High Performance Backend** — Built with **FastAPI**, **async I/O**, and **threaded scanning** for efficient execution.

---
## 🧰 **Tech Stack**

| Layer          | Technology                           | Description                                     |
| -------------- | ------------------------------------ | ----------------------------------------------- |
| **Backend**    | FastAPI                              | Asynchronous Python web framework               |
| **Frontend**   | Jinja2 + Tailwind CSS                | Dynamic HTML templating and responsive styling  |
| **Networking** | Scapy, Nmap (python-nmap), netifaces | ARP scanning, ping sweeps, and port enumeration |
| **Sniffing**   | Tcpdump                              | Packet capture and live traffic analysis        |
| **Storage**    | JSON files (networks.json, oui.json) | Lightweight persistent local storage            |
| **Deployment** | Docker & Docker Compose              | Containerized environment with host networking  |
| **Language**   | Python 3.11+                         | Modern async syntax and typing support          |

---

## 📦 Requirements

To run Monere, you’ll need:

- **Docker** and **Docker Compose** installed  
- A **Linux host** (for full ARP access)  
- Root or elevated privileges (to allow raw socket operations)

---

## ⚙️ Installation & Setup

1. **Clone the repository**
   ```bash
   git clone https://github.com/zw9seq/monere.git
   cd monere
   ```
2. **Configure the network interface**
   Edit the `docker-compose.yml` file and change the environment variable:

   ```yaml
   container_name: monere_app
   network_mode: "host"
   environment:
      - SNIFFER_IFACE=wlan0           # MODIFY THIS
   volumes:
      - ./data:/app/data
   ```

3. **Build and run the container**

   ```bash
   sudo docker compose build
   sudo docker compose up -d
   ```

4. **Access the web UI**
   Open your browser and go to:
   👉 `http://<host-ip>:8000`

   *([http://localhost:8000](http://localhost:8000))*

---

## 🗂️ Project Structure

```
monere/
├── app/
│   ├── __init__.py
│   ├── main.py              # FastAPI entry point and route definitions
│   ├── network.py           # Handles network scanning (ping, ports, ARP)
│   ├── storage.py           # Persistent data handling for networks and hosts
│   └── templates/           # HTML templates (Jinja2)
│       ├── index.html       # Main dashboard
│       ├── networks.html    # List of scanned networks
│       ├── host.html        # Host details and port scan view
│       └── error.html       # Error page
├── config/
│   └── oui.json             # MAC vendor database (backup or reference copy)
├── data/
│   └── networks.json        # Stored network data
├── docker-compose.yml       # Docker Compose configuration
├── Dockerfile               # Docker build file
└── requirements.txt         # Python dependencies

```

---

## 🔒 Permissions & Networking Notes

Because Monere uses **ARP scanning** and raw sockets:

* The container runs in **host network mode** (`network_mode: host`)
* Requires **NET_ADMIN** and **NET_RAW** capabilities
* Only works properly on **Linux** hosts

Docker Compose handles this automatically:

```yaml
network_mode: "host"
cap_add:
  - NET_RAW
  - NET_ADMIN
```

---

## 🧠 **How It Works**

Monere combines multiple network inspection techniques to give you a full picture of your LAN:

1. **Network Identification**
   Using `netifaces`, Monere automatically detects the system’s active interface and subnet (e.g., `192.168.1.0/24`).

2. **Ping Sweep**
   It performs a **parallel ICMP ping sweep** across the subnet to find active hosts quickly and efficiently.

3. **ARP Resolution**
   Once hosts respond, the app retrieves their **MAC addresses** using ARP requests, mapping each to a manufacturer via the **OUI database**.

4. **Port Scanning (Nmap)**
   For each discovered host, Monere can run an **Nmap scan** to identify **open TCP/UDP ports** and detect services.

5. **Packet Sniffing**
   The integrated sniffer (using Tcpdump) captures and inspects **real-time packets**, allowing monitoring of active network traffic from the web interface.

6. **Storage & Dashboard**
   All data (networks, hosts, scan results) is saved under `/data/`, ensuring persistence.
   The FastAPI backend serves an intuitive dashboard showing network activity, host details, and scan history.

---

## 📸 Screenshots

> *Add some screenshots of the dashboard and scan results here*

```
<PLACEHOLDER: Add image links or embeds>
```

---

## 🌟 Contributing

Pull requests and feature suggestions are welcome!
Feel free to open an issue or contribute improvements — especially UI enhancements or network integrations.

---

## 🧩 Troubleshooting

| Problem                       | Likely Cause                  | Solution                  |
| ----------------------------- | ----------------------------- | ------------------------- |
| App runs but no MACs detected | Container not in host network | Use `network_mode: host`  |
| Permission denied errors      | Missing `NET_ADMIN` or root   | Add `cap_add` to compose  |
| Can't access web UI           | Wrong IP or port              | Use host IP:8000          |
| No devices found              | Network isolation or firewall | Ensure container sees LAN |

---

## 👤 Author

**zw9seq**
📅 Built with 💻 + ☕

For more details: https://zw9seq.github.io/proyectos/monere

⭐ If you find this tool useful, consider giving the repo a **star**!

---

## 📄 License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.

---

> *“Monere gives you visibility into your local network — clean, fast, and self-hosted.”*

---
