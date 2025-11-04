# 🛰️ Monere — Network Device Scanner & Dashboard

Monere is a lightweight web application built with **FastAPI** that allows users to **scan local networks**, **identify connected devices**, and **display detailed information** such as IP, MAC address, manufacturer, and connection status.  
It’s designed for local network monitoring with a modern, minimal interface and can be easily deployed in a **Docker container**.

---

## 🚀 Features

- 🕵️‍♂️ **Automatic Network Discovery** — Detect all active hosts within your LAN.  
- 🧭 **ARP-based MAC Resolution** — Retrieve vendor and hardware details from MAC addresses.  
- 🌐 **Modern Web Dashboard** — Built with Jinja2 + Tailwind CSS for a clean and responsive UI.  
- 💾 **Persistent Storage** — Saves discovered networks and device data locally in `/data`.  
- 🐳 **Docker-Ready** — Runs as a self-contained container, easily deployable on any Linux host.  
- ⚙️ **FastAPI Backend** — Asynchronous and lightweight for high responsiveness.

---

## 🧰 Tech Stack

| Layer | Technology |
|-------|-------------|
| Backend | FastAPI (Python 3.11+) |
| Frontend | Jinja2 Templates + Tailwind CSS |
| Networking | Scapy, netifaces |
| Deployment | Docker + Docker Compose |
| Storage | Local JSON-based persistence |

---

## 📦 Requirements

To run Monere, you’ll need:

- **Docker** and **Docker Compose** installed  
- A **Linux host** (for full ARP access)  
- Root or elevated privileges (to allow raw socket operations)
- 
---

## ⚙️ Installation & Setup

### 🐳 Using Docker (recommended)

1. **Clone the repository**
   ```bash
   git clone https://github.com/zw9seq/monere.git
   cd monere
   ```

2. **Build and run the container**

   ```bash
   sudo docker compose up -d
   ```

3. **Access the web UI**
   Open your browser and go to:
   👉 `http://<host-ip>:8000`

   *(e.g. [http://192.168.1.232:8000](http://192.168.1.232:8000))*

---

## 🗂️ Project Structure

```
monere/
├── app/
│   ├── main.py              # FastAPI entrypoint
│   ├── storage.py           # Handles network/device data persistence
│   ├── templates/           # Jinja2 templates (UI)
│   ├── static/              # Static assets (CSS, JS)
│   └── ...                  
├── data/                    # Persistent data storage (mounted volume)
├── oui.json                 # MAC manufacturer database
├── Dockerfile               # Container definition
├── docker-compose.yml       # Deployment configuration
├── requirements.txt         # Python dependencies
└── README.md
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

## 🧠 How It Works

1. Monere identifies your local subnet via `netifaces`.
2. It performs a parallel **ARP scan** to detect active devices.
3. Each MAC address is resolved against the `oui.json` database to identify the manufacturer.
4. The results are stored locally and displayed in a clean web dashboard.

*(You can trigger scans manually or automatically based on your setup.)*

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
