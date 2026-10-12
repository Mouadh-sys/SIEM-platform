```python
raw_text = """SIEM‑Lab – End‑to‑End Security‑Information‑Event‑Management Demo  
=============================================================
A fully‑containerised, reproducible lab that ingests SSH auth logs, detects brute‑force attacks with OpenSearch Alerting, enriches every incident with a local MISP threat‑intel instance, and visualises everything in a dark‑mode React dashboard.
📦  Quick start
# 1️⃣  Clone & enter the repo
git clone <your‑fork-url> siem-lab && cd siem-lab

# 2️⃣  Bring the whole stack up (SIEM + MISP)
make up                 # builds images, starts containers, runs bootstrap scripts

# 3️⃣  Run a deterministic demo (two attacker IPs)
make demo               # replays logs, waits for the monitor, prints incidents

# 4️⃣  Clean everything (volumes + generated auth.log)
make reset
Target    What it does
make up    docker compose -f docker-compose.yml -f docker-compose.misp.yml up -d  → waits for health, creates OpenSearch index template, registers the Alerting webhook & bucket‑level monitor, boots MISP (creates admin key, enables OSINT feeds, seeds a demo event).
make demo    Generates 12 failed logins from 203.0.113.42 and 12 from 198.51.100.77, waits ≤ 2 min for the Alerting monitor to fire, then GET /incidents (shows two enriched incidents).
make reset    Stops all containers, removes named volumes, deletes the generated data/fluent-bit/auth.log.
make logs    Tail logs of every service (docker compose logs -f).
🏗  Architecture (high‑level)
+----------------+      +----------------+      +-------------------+
|  Fluent‑Bit    | -->  |  Kafka (3.8)   | -->  | Data‑Prepper 2.10 |
| (tail auth.log)|      |                |      | (parse → index) |
+----------------+      +----------------+      +-------------------+
                                                          |
                                                          v
+----------------+      +----------------+      +-------------------+
|  OpenSearch 2.18| <-- |  Alerting      | <-- |  Bucket‑level     |
|  (index +      |      |  (webhook →    |      |  monitor 1 min    |
|   dashboards)  |      |    FastAPI)    |      |  count>5 @ 5 min |
+----------------+      +----------------+      +-------------------+
        ^                          |
        |                          v
        |                +-------------------+
        |                |  FastAPI 0.109    |
        |                |  /webhook/opensearch|
        |                |  - stores raw payload|
        |                |  - enriches via MISP |
        |                |  - writes SQLite    |
        |                +-------------------+
        |                          |
        |                          v
        |                +-------------------+
        |                |  React + Vite UI  |
        |                |  (port 5173)      |
        |                +-------------------+
        |
        v
+-------------------+
|   MISP 2.4.180    |
|  (core + modules) |
|  TLS proxy 8443   |
+-------------------+
All containers share the siem-net Docker network, so service names (opensearch, kafka, misp-core, …) resolve automatically.
🔧  Configuration
All secrets and tunables live in .env (never committed).
# ------------------------------------------------------------
# Core versions (pinned)
# ------------------------------------------------------------
OPENSEARCH_VERSION=2.18.0
OPENSEARCH_DASHBOARDS_VERSION=2.18.0
KAFKA_VERSION=3.8.0
DATA_PREPPER_VERSION=2.10.1
FLUENT_BIT_VERSION=3.2.2

# ------------------------------------------------------------
# Ports (host → container)
# ------------------------------------------------------------
OPENSEARCH_PORT=9200
DASHBOARDS_PORT=5601
KAFKA_PORT=9092
FASTAPI_PORT=8000
FRONTEND_PORT=5173

# ------------------------------------------------------------
# OpenSearch JVM heap (keeps RAM < 1 GiB)
# ------------------------------------------------------------
OPENSEARCH_JAVA_OPTS=-Xms512m -Xmx1g

# ------------------------------------------------------------
# MISP (stage‑8)
# ------------------------------------------------------------
MISP_FQDN=localhost
MISP_EMAIL=admin@siem.local
MISP_PASSWORD=SuperSecretMispPass!
MISP_ADMIN_KEY=changeme_admin_key_32chars_long
MISP_DB_ROOT_PASSWORD=RootDbPass!
MISP_DB_PASSWORD=MispDbPass!
MISP_VERIFY_TLS=false          # self‑signed cert in demo
IOC_PROVIDER=misp              # static | misp
Never commit real passwords – the file is in .gitignore.
🛠  Services & exposed ports
Service
OpenSearch
OpenSearch‑Dashboards
Kafka
Fluent‑Bit
Data‑Prepper
FastAPI backend
React frontend (nginx)
MISP
MariaDB
Redis
All containers have health‑checks (see docker‑compose*.yml). make up blocks until every service reports healthy (timeout 2‑3 min).
📚  Stage summary (what each make target builds)
Stage    Deliverable
1‑4 (in repo history)    Fluent‑Bit → Kafka → Data‑Prepper → OpenSearch index template
5A    Alerting webhook channel + bucket‑level monitor ssh‑bruteforce‑by‑ip (1 min, last 5 min, count>5). FastAPI webhook stores raw payload, fetches active alerts, creates one incident per bucket key (multi‑IP safe).
5B (optional)    Security‑Analytics detector (Sigma rule) – not required for demo.
6    Full FastAPI surface: GET /health, GET /incidents?status&severity, GET /incidents/{id}, GET /incidents/{id}/timeline, PATCH /incidents/{id} (status + analyst_note), GET /stats, GET /api/ioc/{ip} + CORS for localhost:5173. Seed script scripts/seed_incidents.py adds 30 historic rows.
7    React + Vite + Tailwind dashboard (dark SOC theme). Overview KPI cards, severity pie, events‑per‑minute line, top attackers; Incidents table with clickable detail modal (timeline, IOC badge, status/note edit); auto‑refresh 10 s; error banner; “Open in OpenSearch Dashboards” link.
8 (this commit)    MISP stack (MariaDB, Redis, core, modules, TLS nginx proxy). scripts/setup_misp.py – idempotent: creates automation API key, enables CIRCL & Botvrij feeds (best‑effort), creates event “SIEM demo IOCs” with two ip‑src attributes (to_ids=true). Portal gains ioc.py provider abstraction (MISP / static), 3 s timeout, 5 min in‑memory cache, graceful fallback (static-fallback). Incident enrichment raises severity, stores ioc_matched, ioc_source, ioc_events, ioc_tags, ioc_first_seen and adds a timeline line. Front‑end shows “Malicious (MISP) – SIEM demo IOCs” badge with link to MISP event and an IOC‑matched incidents KPI.
✅  Verification checklist (run after make up)
# 1️⃣  MISP UI reachable (self‑signed cert → accept in browser)
curl -k -s -o /dev/null -w "%{http_code}" https://localhost:8443/   # → 200

# 2️⃣  MISP REST search for demo IOCs (needs automation key)
AUTO_KEY=$(docker exec misp-core \
  awk -F\" '/AUTOMATION_KEY/ {print $4}' /var/www/MISP/app/Config/bootstrap.php 2>/dev/null \
  || echo "$MISP_ADMIN_KEY")
curl -k -s -H "Authorization: $AUTO_KEY" -H "Accept: application/json" \
  -X POST https://localhost:8443/attributes/restSearch \
  -d '{"returnFormat":"json","value":"203.0.113.42","type":"ip-src","to_ids":1,"limit":5}' | jq .

# 3️⃣  Portal IOC endpoint (should report source "MISP")
curl -s http://localhost:8000/api/ioc/203.0.113.42 | jq .
# {"ip":"203.0.113.42","malicious":true,"source":"MISP","events":[{"id":1,"title":"SIEM demo IOCs"}],...}

# 4️⃣  Run the demo (generates two incidents, each enriched)
make demo
# → JSON shows two incidents, both `ioc_matched:true`, severity bumped +1, timeline entry "IOC match from MISP (event 1)"

# 5️⃣  Fallback test – stop MISP and query again
docker stop misp-core
curl -s http://localhost:8000/api/ioc/203.0.113.42 | jq .
# → source becomes "static-fallback", malicious:false
docker start misp-core
All commands should return HTTP 200 and the expected JSON structure.
📈  Resource usage (typical on a 16 GiB laptop)
Service
OpenSearch (heap 512 m‑1 g)
OpenSearch‑Dashboards
Kafka
Data‑Prepper
Fluent‑Bit
FastAPI backend
React front‑end (nginx)
MISP core
MISP modules
MariaDB
Redis
MISP proxy (nginx)
Total
Well inside a typical development machine; lower OpenSearch heap (-Xms256m -Xmx512m) if you need to run on 8 GiB.
📂  Repository layout (relevant parts)
.
├── .env                     # all secrets / tunables (git‑ignored)
├── docker-compose.yml       # SIEM core stack
├── docker-compose.misp.yml  # MISP stack (same network)
├── Makefile                 # up / demo / reset / logs
├── scripts/
│   ├── bootstrap.sh         # wait‑for‑health, index template, detector
│   ├── setup_detector.py    # idempotent webhook + monitor
│   ├── setup_misp.py        # idempotent MISP bootstrap
│   ├── replay_auth_log.py   # generates brute‑force auth.log lines
│   └── seed_incidents.py    # 30 historic incidents (for UI)
├── config/
│   ├── fluent-bit/          # parsers, lua normaliser
│   ├── data-prepper/        # pipeline YAML
│   └── misp/
│       ├── nginx.conf       # TLS termination for MISP
│       └── certs/           # self‑signed cert/key (generated once)
├── portal/
│   ├── backend/
│   │   ├── app/
│   │   │   ├── main.py          # FastAPI routes (incl. /api/ioc)
│   │   │   ├── database.py      # SQLite + enrichment helpers
│   │   │   └── ioc.py           # provider abstraction (MISP / static)
│   │   └── Dockerfile
│   └── frontend/
│       ├── src/
│       │   ├── App.jsx
│       │   ├── components/IOCBadge.jsx
│       │   └── …
│       ├── Dockerfile
│       └── nginx.conf
└── README.md                # <-- this file
🤝  Contributing / Extending
- Add a new log source – drop a Fluent‑Bit input in config/fluent-bit/ and extend the Data‑Prepper pipeline.  

- Swap the IOC provider – set IOC_PROVIDER=static in .env or implement another class in ioc.py.

- Add more Alerting monitors – reuse scripts/setup_detector.py as a template.  

- Dashboard widgets – drop a new Recharts component into src/components/ and import it in OverviewPage or IncidentsPage.

Pull‑requests welcome!
📜  License
MIT – see LICENSE for details.
Happy hunting! 🚀"""

print("Length of raw text:", len(raw_text))


```

```text
Length of raw text: 9942


```

```python
text = raw_text

# Replace non-breaking spaces and hyphen variations
text = text.replace('\xa0', ' ').replace('‑', '-')

print("Cleaned character replacements complete.")


```

```text
Cleaned character replacements complete.


```

# SIEM-Lab – End-to-End Security-Information-Event-Management Demo

A fully-containerised, reproducible lab that ingests SSH auth logs, detects brute-force attacks with OpenSearch Alerting, enriches every incident with a local MISP threat-intel instance, and visualises everything in a dark-mode React dashboard.

---

## 📦 Quick Start

```bash
# 1️⃣ Clone & enter the repo
git clone <your-fork-url> siem-lab && cd siem-lab

# 2️⃣ Bring the whole stack up (SIEM + MISP)
make up                 # builds images, starts containers, runs bootstrap scripts

# 3️⃣ Run a deterministic demo (two attacker IPs)
make demo               # replays logs, waits for the monitor, prints incidents

# 4️⃣ Clean everything (volumes + generated auth.log)
make reset

```

| Target | What it does |
| --- | --- |
| `make up` | `docker compose -f docker-compose.yml -f docker-compose.misp.yml up -d` → waits for health, creates OpenSearch index template, registers the Alerting webhook & bucket-level monitor, boots MISP (creates admin key, enables OSINT feeds, seeds a demo event). |
| `make demo` | Generates 12 failed logins from `203.0.113.42` and 12 from `198.51.100.77`, waits ≤ 2 min for the Alerting monitor to fire, then `GET /incidents` (shows two enriched incidents). |
| `make reset` | Stops all containers, removes named volumes, deletes the generated `data/fluent-bit/auth.log`. |
| `make logs` | Tail logs of every service (`docker compose logs -f`). |

---

## 🏗 Architecture (high-level)

```text
+----------------+      +----------------+      +-------------------+
|  Fluent-Bit    | -->  |  Kafka (3.8)   | -->  | Data-Prepper 2.10 |
| (tail auth.log)|      |                |      | (parse → index)   |
+----------------+      +----------------+      +-------------------+
                                                          |
                                                          v
+----------------+      +----------------+      +-------------------+
| OpenSearch 2.18| <--  |  Alerting      | <--  |  Bucket-level     |
| (index +       |      |  (webhook →    |      |  monitor 1 min    |
|  dashboards)   |      |   FastAPI)     |      |  count>5 @ 5 min  |
+----------------+      +----------------+      +-------------------+
        ^                          |
        |                          v
        |                +-------------------+
        |                |  FastAPI 0.109    |
        |                | /webhook/opensearch|
        |                |- stores raw payload|
        |                |- enriches via MISP |
        |                |- writes SQLite    |
        |                +-------------------+
        |                          |
        |                          v
        |                +-------------------+
        |                |  React + Vite UI  |
        |                |  (port 5173)      |
        |                +-------------------+
        |
        v
+-------------------+
|   MISP 2.4.180    |
| (core + modules)  |
| TLS proxy 8443    |
+-------------------+

```

All containers share the `siem-net` Docker network, so service names (`opensearch`, `kafka`, `misp-core`, …) resolve automatically.

---

## 🔧 Configuration

All secrets and tunables live in `.env` (never committed).

```env
# ------------------------------------------------------------
# Core versions (pinned)
# ------------------------------------------------------------
OPENSEARCH_VERSION=2.18.0
OPENSEARCH_DASHBOARDS_VERSION=2.18.0
KAFKA_VERSION=3.8.0
DATA_PREPPER_VERSION=2.10.1
FLUENT_BIT_VERSION=3.2.2

# ------------------------------------------------------------
# Ports (host → container)
# ------------------------------------------------------------
OPENSEARCH_PORT=9200
DASHBOARDS_PORT=5601
KAFKA_PORT=9092
FASTAPI_PORT=8000
FRONTEND_PORT=5173

# ------------------------------------------------------------
# OpenSearch JVM heap (keeps RAM < 1 GiB)
# ------------------------------------------------------------
OPENSEARCH_JAVA_OPTS=-Xms512m -Xmx1g

# ------------------------------------------------------------
# MISP (stage-8)
# ------------------------------------------------------------
MISP_FQDN=localhost
MISP_EMAIL=admin@siem.local
MISP_PASSWORD=SuperSecretMispPass!
MISP_ADMIN_KEY=changeme_admin_key_32chars_long
MISP_DB_ROOT_PASSWORD=RootDbPass!
MISP_DB_PASSWORD=MispDbPass!
MISP_VERIFY_TLS=false          # self-signed cert in demo
IOC_PROVIDER=misp              # static | misp

```

> **Note:** Never commit real passwords – the `.env` file is included in `.gitignore`.

---

## 🛠 Services & Exposed Ports

| Service | Host Port / Network Access |
| --- | --- |
| OpenSearch | `9200` |
| OpenSearch-Dashboards | `5601` |
| Kafka | `9092` |
| Fluent-Bit | Internal (`siem-net`) |
| Data-Prepper | Internal (`siem-net`) |
| FastAPI backend | `8000` |
| React frontend (nginx) | `5173` |
| MISP | `8443` (TLS) |
| MariaDB | Internal (`siem-net`) |
| Redis | Internal (`siem-net`) |

All containers have health-checks (see `docker-compose*.yml`). `make up` blocks until every service reports healthy (timeout 2–3 min).

---

## 📚 Stage Summary (what each stage builds)

| Stage | Deliverable |
| --- | --- |
| **1–4** (in repo history) | Fluent-Bit → Kafka → Data-Prepper → OpenSearch index template |
| **5A** | Alerting webhook channel + bucket-level monitor `ssh-bruteforce-by-ip` (1 min, last 5 min, count > 5). FastAPI webhook stores raw payload, fetches active alerts, creates one incident per bucket key (multi-IP safe). |
| **5B** (optional) | Security-Analytics detector (Sigma rule) – not required for demo. |
| **6** | Full FastAPI surface: `GET /health`, `GET /incidents?status&severity`, `GET /incidents/{id}`, `GET /incidents/{id}/timeline`, `PATCH /incidents/{id}` (`status` + `analyst_note`), `GET /stats`, `GET /api/ioc/{ip}` + CORS for `localhost:5173`. Seed script `scripts/seed_incidents.py` adds 30 historic rows. |
| **7** | React + Vite + Tailwind dashboard (dark SOC theme). Overview KPI cards, severity pie, events-per-minute line, top attackers; Incidents table with clickable detail modal (timeline, IOC badge, status/note edit); auto-refresh 10 s; error banner; “Open in OpenSearch Dashboards” link. |
| **8** (this commit) | MISP stack (MariaDB, Redis, core, modules, TLS nginx proxy). `scripts/setup_misp.py` – idempotent: creates automation API key, enables CIRCL & Botvrij feeds (best-effort), creates event “SIEM demo IOCs” with two `ip-src` attributes (`to_ids=true`). Portal gains `ioc.py` provider abstraction (MISP / static), 3 s timeout, 5 min in-memory cache, graceful fallback (`static-fallback`). Incident enrichment raises severity, stores `ioc_matched`, `ioc_source`, `ioc_events`, `ioc_tags`, `ioc_first_seen` and adds a timeline line. Front-end shows “Malicious (MISP) – SIEM demo IOCs” badge with link to MISP event and an IOC-matched incidents KPI. |

---

## ✅ Verification Checklist (run after `make up`)

```bash
# 1️⃣ MISP UI reachable (self-signed cert → accept in browser)
curl -k -s -o /dev/null -w "%{http_code}" https://localhost:8443/   # → 200

# 2️⃣ MISP REST search for demo IOCs (needs automation key)
AUTO_KEY=$(docker exec misp-core \
  awk -F\" '/AUTOMATION_KEY/ {print $4}' /var/www/MISP/app/Config/bootstrap.php 2>/dev/null \
  || echo "$MISP_ADMIN_KEY")
curl -k -s -H "Authorization: $AUTO_KEY" -H "Accept: application/json" \
  -X POST https://localhost:8443/attributes/restSearch \
  -d '{"returnFormat":"json","value":"203.0.113.42","type":"ip-src","to_ids":1,"limit":5}' | jq .

# 3️⃣ Portal IOC endpoint (should report source "MISP")
curl -s http://localhost:8000/api/ioc/203.0.113.42 | jq .
# {"ip":"203.0.113.42","malicious":true,"source":"MISP","events":[{"id":1,"title":"SIEM demo IOCs"}],...}

# 4️⃣ Run the demo (generates two incidents, each enriched)
make demo
# → JSON shows two incidents, both `ioc_matched:true`, severity bumped +1, timeline entry "IOC match from MISP (event 1)"

# 5️⃣ Fallback test – stop MISP and query again
docker stop misp-core
curl -s http://localhost:8000/api/ioc/203.0.113.42 | jq .
# → source becomes "static-fallback", malicious:false
docker start misp-core

```

All commands should return HTTP 200 and the expected JSON structure.

---

## 📈 Resource Usage (typical on a 16 GiB laptop)

* OpenSearch (heap 512M–1G)
* OpenSearch-Dashboards
* Kafka
* Data-Prepper
* Fluent-Bit
* FastAPI backend
* React front-end (nginx)
* MISP core
* MISP modules
* MariaDB
* Redis
* MISP proxy (nginx)

Well inside a typical development machine capacity; lower OpenSearch heap (`-Xms256m -Xmx512m`) if you need to run on 8 GiB RAM.

---

## 📂 Repository Layout (relevant parts)

```text
.
├── .env                     # all secrets / tunables (git-ignored)
├── docker-compose.yml       # SIEM core stack
├── docker-compose.misp.yml  # MISP stack (same network)
├── Makefile                 # up / demo / reset / logs
├── scripts/
│   ├── bootstrap.sh         # wait-for-health, index template, detector
│   ├── setup_detector.py    # idempotent webhook + monitor
│   ├── setup_misp.py        # idempotent MISP bootstrap
│   ├── replay_auth_log.py   # generates brute-force auth.log lines
│   └── seed_incidents.py    # 30 historic incidents (for UI)
├── config/
│   ├── fluent-bit/          # parsers, lua normaliser
│   ├── data-prepper/        # pipeline YAML
│   └── misp/
│       ├── nginx.conf       # TLS termination for MISP
│       └── certs/           # self-signed cert/key (generated once)
├── portal/
│   ├── backend/
│   │   ├── app/
│   │   │   ├── main.py          # FastAPI routes (incl. /api/ioc)
│   │   │   ├── database.py      # SQLite + enrichment helpers
│   │   │   └── ioc.py           # provider abstraction (MISP / static)
│   │   └── Dockerfile
│   └── frontend/
│       ├── src/
│       │   ├── App.jsx
│       │   ├── components/IOCBadge.jsx
│       │   └── …
│       ├── Dockerfile
│       └── nginx.conf
└── README.md                # <-- this file

```

---

## 🤝 Contributing / Extending

* **Add a new log source:** Drop a Fluent-Bit input in `config/fluent-bit/` and extend the Data-Prepper pipeline.
* **Swap the IOC provider:** Set `IOC_PROVIDER=static` in `.env` or implement another class in `ioc.py`.
* **Add more Alerting monitors:** Reuse `scripts/setup_detector.py` as a template.
* **Dashboard widgets:** Drop a new Recharts component into `src/components/` and import it in `OverviewPage` or `IncidentsPage`.

Pull requests welcome!

---

## 📜 License

MIT – see [LICENSE](https://www.google.com/search?q=LICENSE) for details.

Happy hunting! 🚀