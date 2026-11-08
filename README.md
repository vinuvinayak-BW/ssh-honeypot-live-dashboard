# SSH Honeypot with Live Dashboard

## Start here: run it on Windows

This guide assumes you have never installed a Python project before. Follow
the steps in order; you do not need Git, Docker, Redis, or a database to open
the dashboard and try a local SSH login.

### What this project does

Think of it as a **fake SSH login door** that records knocks. The honeypot
listens for SSH login attempts, saves what the visitor tried, and rejects every
login. A small web dashboard reads those records and displays counts, a live
feed, and a map when location data is available. It never gives a visitor a
real shell or access to your files.

> **Important:** This project records attempted passwords as plain text in
> `logs/events.jsonl`. Use only made-up passwords while testing. The SSH
> listener binds to all network interfaces on port 2222, so start with local
> testing only. Do not forward port 2222 from your router or expose it to the
> public internet until you understand the security and isolation notes below.

### 1. Download the project

1. Open the [project on GitHub](https://github.com/vinuvinayak-BW/ssh-honeypot-live-dashboard).
2. Click the green **Code** button, then choose **Download ZIP**.
3. In File Explorer, right-click the downloaded ZIP and choose **Extract All**.
4. Move the extracted folder somewhere easy to find, for example
   `C:\Projects\ssh-honeypot-live-dashboard`.

You can choose a different folder. The commands below work from inside that
folder.

### 2. Install Python

Install Python 3.10 or newer from the official
[Python 3.13 Windows download page](https://www.python.org/downloads/release/python-31317/).
During setup, select **Add python.exe to PATH** if the installer shows that
option. When setup finishes, close and reopen any PowerShell windows.

### 3. Open PowerShell in the project folder

1. Open the extracted `ssh-honeypot-live-dashboard` folder in File Explorer.
2. Click the address bar at the top of the window.
3. Type `powershell` and press **Enter**.

Use a normal PowerShell window, not **Run as administrator**. The honeypot
refuses to run as Administrator.

### 4. Install the project’s Python packages and create its SSH key

Copy and run these commands in that PowerShell window, one at a time:

```powershell
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe honeypot.py --init
```

The first command creates a private Python work area named `.venv` inside the
project folder. The next two install the packages the project needs. The last
command creates the SSH host key once. These commands create `state` and
`logs` folders automatically as the programs run. If `py` is not recognized,
Python may not be installed correctly; install it, reopen PowerShell, and try
again.

### 5. Start the two parts of the project

The honeypot and dashboard are separate programs, so keep two PowerShell
windows open.

**Window 1 — start the fake SSH login door**

Open PowerShell in the project folder again, then run:

```powershell
.\.venv\Scripts\python.exe honeypot.py
```

Keep this window open. It should say that it is listening on port 2222.

**Window 2 — start the dashboard**

Open another PowerShell window in the same folder, then run:

```powershell
.\.venv\Scripts\python.exe server.py
```

Keep this window open too. Then open [http://127.0.0.1:8080](http://127.0.0.1:8080)
in your web browser. `127.0.0.1` means “this computer.” The dashboard is for
your local computer; its web and WebSocket ports are not opened to your network.

### 6. Make one safe test attempt

If Windows has the OpenSSH Client installed, open a **third** PowerShell or
Command Prompt window and run this as one line:

```text
ssh -p 2222 -o StrictHostKeyChecking=no -o UserKnownHostsFile=NUL -o PreferredAuthentications=password -o PubkeyAuthentication=no demo@127.0.0.1
```

When SSH asks for a password, enter a made-up test value. The honeypot will
reject it, and the dashboard should show the login attempt. The password is
written to the local log in plain text, so never enter a password you use
anywhere else. If `ssh` is not recognized, install the **OpenSSH Client**
optional Windows feature or skip this test; the dashboard can still run.

### What the optional warnings mean

* **No GeoLite2 database:** the feed still works, but local IPs will not have
  map markers or country/state locations. GeoLite2 setup is described later.
* **Redis is unavailable:** the project uses an in-memory copy of its optional
  DShield blocklist. The dashboard still works.
* **No internet:** the dashboard itself can run, but its online map tiles and
  external DShield feed may be unavailable.

To stop either program, focus its PowerShell window and press **Ctrl+C**.

---

## Project overview

This is a small SSH honeypot. It listens on **TCP port 2222**, rejects all
credentials, and writes each attempt as one JSON line. A Python WebSocket
server reads that file and updates a single-page dashboard with a live feed,
summary cards, top usernames, a map, country/state rankings, and an
attempts-per-minute graph.

It can also pull **external real-world attack observations** (SANS ISC
DShield, any JSON export, or your own webhook) through a pluggable connector
layer. Those observations appear on the same map and feed, labelled with their
source, without being mixed into the honeypot's own counters.

Geolocation is **local-only**: a MaxMind GeoLite2 City database is read
asynchronously, and there is no ip-api.com fallback. A background worker also
caches the DShield SSH blocklist in Redis every four hours and marks matching
attempts with `dshield_listed`.

The application itself has no web framework. The optional `docker-compose.yml`
adds an Nginx TLS/authentication edge for Linux deployments; the honeypot and
dashboard services remain loopback-bound on the host. Runtime pieces:

```
[ attacker ] --TCP/2222--> [ honeypot.py ]
                                  |
                                  | appends one JSON line per event
                                  v
                         logs/events.jsonl
                          /              \
          tail + geolocation              \ tail + byte-offset checkpoint
                  |                        \
          [ server.py ]  WS :8765          v
                  ^                  [ forwarder.py ] --TLS--> [ Elasticsearch ]
                  |                                              or [ ClickHouse ]
                  | normalize + geolocate
          [ connectors.py ] <-- sources.json
           /       |        \
     DShield   JSON feed   webhook (POST /api/ingest)
                  |
                  | WebSocket
                  v
     [ dashboard/index.html ]  HTTP :8080
```

`forwarder.py` is optional and outbound-only: it never listens on a port and
does not change dashboard behavior. Skip it if you only need the local
dashboard.

* `honeypot.py` — SSH listener on 2222. Rejects all logins, denies every
  channel (shell, exec, SFTP, PTY, forwarding), and writes the event log.
* `server.py` — tails the log, enriches with a local MaxMind GeoLite2
  database, annotates attempts against the Redis-cached DShield blocklist,
  broadcasts over WebSocket on **8765**, and serves the static dashboard on
  **8080**. It also aggregates geolocated attempts by country and state/region.
* `enrichment.py` — asynchronous MaxMind reader plus the Redis-backed DShield
  blocklist worker. Geo lookups run in a worker thread so the event loop never
  blocks; the blocklist is refreshed every four hours.
* `connectors.py` — pluggable external data sources. Polls feeds or accepts
  webhook pushes, normalizes them to the honeypot event schema, deduplicates,
  and persists them separately in `logs/external_events.jsonl`.
* `sources.json` — which external connectors are enabled and how to reach them.
* `dashboard/index.html` — one HTML file (Leaflet + Chart.js from CDNs; Esri Dark Gray map tiles).
* `forwarder.py` — optional stdlib-only tailer that ships the JSONL logs to a
  centralized Elasticsearch or ClickHouse cluster over TLS, with a resumable
  byte-offset checkpoint. See *Centralized forwarding* below.
* `deploy/` — systemd sandbox units, an Elasticsearch index template, and a
  ClickHouse schema.

---

## Prerequisites

* Python **3.10+** (verified on 3.11 and 3.13).
* An SSH client for testing (Windows OpenSSH is built in; Linux/macOS have
  OpenSSH).
* A **MaxMind GeoLite2-City** database (`.mmdb`) for geolocation. Without it,
  events still stream but the map has no markers.
* Optional: **Redis 6+** for the DShield blocklist cache. If Redis is absent,
  the worker keeps an in-memory snapshot and logs a warning; the rest of the
  dashboard is unaffected.
* Internet access for the Leaflet/Chart.js CDNs and the DShield feed
  (`isc.sans.edu`). Use `--no-external` to skip the connector and
  `--no-blocklist` to skip the blocklist worker when the host is offline.
* Centralized forwarding (optional) needs outbound HTTPS to your
  Elasticsearch or ClickHouse endpoint. It uses only the standard library, so
  no extra Python package is required.

---

## Detailed Windows reference

Use a **normal, non-elevated** terminal. The honeypot refuses to run with an
Administrator token.

### Step 1 — Install dependencies

```powershell
# Open PowerShell in the project folder first (see "Start here" above).
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

Expected: pip installs `paramiko`, `websockets`, `geoip2`, `redis`, and
their dependencies.

### Step 2 — Generate the host key once

```powershell
.\.venv\Scripts\python.exe honeypot.py --init
```

Expected:

```text
[init] generating 2048-bit RSA host key (a few seconds)...
[init] wrote C:\...\state\host_rsa.key
[init] keep this file read-only for the honeypot account
```

The running honeypot only **reads** this key. It is deliberately generated by
a separate setup command so the long-running process only needs write access
to `logs/`.

### Step 3 — Start the honeypot (terminal 1)

```powershell
.\.venv\Scripts\python.exe honeypot.py
```

Expected:

```text
[honeypot] listening on 0.0.0.0:2222
[honeypot] banner: SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5
[honeypot] events: C:\...\logs\events.jsonl
[honeypot] all logins are rejected; no shell/exec/SFTP is enabled
```

Leave this terminal open.

### Step 4 — Start the WebSocket server + dashboard (terminal 2)

```powershell
.\.venv\Scripts\python.exe server.py
```

Expected:

```text
[server] log: C:\...\logs\events.jsonl (0 historical events)
[server] external events: 0
[server] websocket: ws://127.0.0.1:8765
[server] dashboard: http://127.0.0.1:8080
[sources] 2 active / 3 configured (sources.json)
[sources]   dshield-ssh: dshield enabled -> https://isc.sans.edu/api/threatlist/openbl_ssh?json
[sources]   json-example: json_feed disabled -> https://example.com/attacks.json
[sources]   webhook: webhook enabled -> /api/ingest
[geo] lookup: MaxMind (GeoLite2-City.mmdb)
[server] waiting for new events...
```

External sources are on by default (`sources.json`). The DShield poller makes
one outbound HTTPS request every 5 minutes; the webhook is only active when
`HONEYPOT_INGEST_TOKEN` is set. Start with `--no-external` if you want the
honeypot feed only, or `--sources PATH` to use another config.

### Step 5 — Open the dashboard

<http://127.0.0.1:8080>

The dashboard is one page with three anchored sections — **Overview**, **Attack
Map**, and **Rankings** — in the top navigation. It is a live view, not a
historical report:

* **Overview** — five summary cards (local attempts, unique source IPs,
  external observations, SSH connections, and attempts in the last 30 minutes),
  a live ticker, an attempts-per-minute chart for the local sensor, top
  usernames, and a recent-activity table with search, scope filters, a DShield
  filter, and “Show more” paging.
* **Attack Map** — a Leaflet world map with all-time country and state/region
  aggregates, live rings for individual geolocated attempts, zoom/pan, a
  legend, marker popups, and a country/state search box.
* **Rankings** — sortable all-time country and state/region tables, recent
  source IPs, and the **Real-world feeds** panel with connector status, last
  poll, and observation count.

Scope labels are explicit. `attempts`, `connections`, top usernames, and the
30-minute chart are **local honeypot** traffic. `unique_ips` and the location
rankings include **external** observations. External observations are counted
separately in `external_attempts` and never inflate local attempt counts. The
source IP ranking is built from the browser's recent buffer, not all-time data.

The dashboard starts with loading placeholders and switches to empty, partial,
or error states when there is no data, no geolocation, or the WebSocket cannot
be reached. Filters and the connection status stay visible in every state.

Geolocation requires a public IP and a local MaxMind GeoLite2-City database
(`--geoip-db`, or `GeoLite2-City.mmdb` in the project root). There is no
third-party geolocation fallback: without the database, events still appear in
the feed, but they have no map marker or country/state ranking entry, and the
map explains that location data is missing. Private, loopback, and invalid
addresses are never looked up. IP geolocation is approximate: it can identify
an ISP exit point rather than an attacker's physical location, and state/region
availability varies by database.

### Step 6 — Attack it from terminal 3

```powershell
ssh -p 2222 -o StrictHostKeyChecking=no -o UserKnownHostsFile=NUL `
    -o PreferredAuthentications=password -o PubkeyAuthentication=no `
    root@127.0.0.1
```

Type any password (for example `hunter2`). Expected SSH output:

```text
root@127.0.0.1's password:
Permission denied (password,publickey,keyboard-interactive).
```

The dashboard should immediately:

* increment **Login attempts** and **Connections**;
* add `127.0.0.1` and `root : hunter2` to the live ticker and feed;
* add `root` to **Top usernames**;
* add a bar to the chart.

Inspect the raw log:

```powershell
Get-Content .\logs\events.jsonl -Tail 4
```

Expected (one JSON object per line, pretty-printed here):

```json
{"id":"…","ts":"2026-10-31T12:34:56.789Z","event":"connection","connection_id":"…","src_ip":"127.0.0.1","src_port":51515}
{"id":"…","ts":"2026-10-31T12:34:56.901Z","event":"auth_attempt","connection_id":"…","src_ip":"127.0.0.1","src_port":51515,"client_version":"SSH-2.0-OpenSSH_for_Windows_9.5","username":"root","auth_type":"password","password":"hunter2","key_type":null,"key_fingerprint":null,"key_bits":null}
```

The map stays empty for `127.0.0.1` **on purpose**: private/loopback addresses
are never sent to a geolocation service. To verify the map, append a test
event with a public IP (Step 7).

### Step 7 — Verify geolocation and the map

With `server.py` still running, paste this into a fourth PowerShell terminal:

```powershell
@'
import datetime, json, pathlib
p = pathlib.Path("logs/events.jsonl")
event = {
    "id": "demo-" + datetime.datetime.now().strftime("%H%M%S%f"),
    "ts": datetime.datetime.now(datetime.timezone.utc)
        .isoformat(timespec="milliseconds").replace("+00:00", "Z"),
    "event": "auth_attempt",
    "connection_id": "demo",
    "src_ip": "8.8.8.8",
    "src_port": 44444,
    "client_version": "SSH-2.0-OpenSSH_9.6",
    "username": "admin",
    "auth_type": "password",
    "password": "demo-password",
    "key_type": None,
    "key_fingerprint": None,
    "key_bits": None,
}
with p.open("a", encoding="utf-8") as fh:
    fh.write(json.dumps(event) + "\n")
print("appended demo event")
'@ | .\.venv\Scripts\python.exe -
```

Expected in the server terminal:

```text
[server] waiting for new events...
```

(no error) and in the dashboard: a cyan pulse and marker near the United
States for `8.8.8.8`, plus `admin` in the ticker and top usernames. The marker
needs a MaxMind GeoLite2-City database; without one the event still appears,
but with `geo: null`, `geo_status: "unavailable"`, and no marker. That is the
required graceful failure behavior.

To reset the demo data: stop `server.py`, stop `honeypot.py`, delete
`logs\events.jsonl`, and restart both.

---

## If 2222 / 8765 / 8080 are already in use

Docker Desktop, WSL, or another honeypot may already own these ports. The
programs fail loudly rather than silently sharing a port. Use alternate ports
for the whole stack:

```powershell
# terminal 1
.\.venv\Scripts\python.exe honeypot.py --port 2223

# terminal 2
.\.venv\Scripts\python.exe server.py --ws-port 8775 --http-port 8090
```

Open <http://127.0.0.1:8090/?ws=ws://127.0.0.1:8775> and test with
`ssh -p 2223 ...`. The defaults in the code and systemd units remain
2222/8765/8080; only use alternates when the ports are occupied.

Check who owns a port:

```powershell
Get-NetTCPConnection -LocalPort 2222,8765,8080 -State Listen |
    Select-Object LocalAddress,LocalPort,OwningProcess
Get-Process -Id <OwningProcess>
```

```bash
sudo ss -ltnp | grep -E '2222|8765|8080'
```

---

## Quick start (Linux / macOS)

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python honeypot.py --init
python honeypot.py          # terminal 1
# terminal 2:
python server.py
```

Test from terminal 3:

```bash
ssh -p 2222 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    root@127.0.0.1
```

Open <http://127.0.0.1:8080>.

---

## What each component does

### `honeypot.py`

* Listens on `0.0.0.0:2222` (configurable with `--host` / `--port`).
* Sends `SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5` as the identification
  string (`--banner` to change it).
* Accepts password, public-key, and keyboard-interactive attempts, records
  them, and returns `AUTH_FAILED` every time.
* Records: timestamp, source IP/port, connection id, client SSH version,
  username, auth type, password (for password/keyboard-interactive), key type,
  key bits, and SHA-256 fingerprint (for public keys).
* Denies every channel request: `shell`, `exec`, `subsystem` (SFTP), `pty`,
  X11, agent forwarding, and `direct-tcpip`.
* Writes **one JSON object per line** to `logs/events.jsonl` and `fsync`s each
  line so the dashboard sees it immediately.
* Bounds attacker-controlled fields to 512 characters, allows at most 64
  concurrent sockets, and closes a connection after 20 auth attempts or 120
  seconds.

### `server.py`

* Reads the log from the beginning once at startup to rebuild aggregate
  statistics, then tails new lines. It survives truncation/rotation.
* On each WebSocket connection, sends a `snapshot` containing the current
  stats and the last 100 events, so a newly opened dashboard is immediately
  populated.
* Enriches `auth_attempt` events asynchronously with latitude/longitude from a
  local MaxMind `GeoLite2-City.mmdb` (`enrichment.py`):
  * lookups run in a worker thread, so a slow disk does not stall the feed;
  * private/loopback/invalid addresses are classified locally and never
    looked up;
  * without a database, or when a lookup misses, `geo` stays `null` and
    `geo_status` is `unavailable` — the event is still broadcast;
  * there is no ip-api.com or other third-party geolocation fallback.
* Maintains an optional Redis-backed DShield blocklist (`--redis-url`) and
  marks matching events with `dshield_listed`; without Redis the worker keeps
  an in-memory snapshot.
* Broadcasts `event` messages to every connected dashboard.
* Rejects browser WebSocket connections whose `Origin` is not the dashboard
  origin (localhost by default), so a random website cannot read the feed.
  Use `--allow-origin https://your.host` behind a reverse proxy.
* Serves `dashboard/` over HTTP on 8080 and WebSocket on 8765, both bound to
  `127.0.0.1` by default.
* Loads `sources.json`, runs the enabled connectors, merges their events into
  the same broadcast stream, and exposes them via `POST /api/ingest[/<id>]`.
  Disable all of it with `--no-external`, or point at another file with
  `--sources PATH`.

WebSocket message shapes:

```json
{"type":"snapshot","stats":{...},"recent":[...]}
{"type":"event","event":{...},"stats":{...}}
```

`stats` includes `external_attempts` and `sources` alongside the honeypot
counters (`attempts`, `connections`, `unique_ips`, `unique_usernames`,
`location_rankings`, ...). See *Real-world monitoring* below.

### `connectors.py`

* `BaseSource` owns the poll loop, status reporting, and deduplication.
* `DShieldSource` reads the public SANS ISC DShield API (no key).
* `JsonFeedSource` polls any HTTP(S) JSON endpoint and maps its fields.
* `WebhookSource` validates a bearer token and accepts pushed events.
* `ConnectorManager` loads `sources.json`, starts pollers, and hands pushed
  events to the asyncio loop.
* `ExternalEventStore` appends enriched external events to
  `logs/external_events.jsonl`, rotating at 5 MB and loading the last 5000 on
  startup.
* Every external event is marked `external: true` with `source_id` /
  `source_name`, so it is counted separately from traffic that actually hit
  this sensor.

### `forwarder.py`

* Optional outbound-only shipper for centralized search. Never listens on a
  port and never writes `logs/`.
* Supports Elasticsearch `_bulk` and ClickHouse HTTP `JSONEachRow`.
* Resumes from a byte-offset checkpoint in `state/`, survives rotation and
  truncation, and ignores partial lines.
* Verifies TLS by default; supports a private CA and mTLS. Credentials come
  from environment variables.
* Retries transient failures with capped backoff and exits loudly on
  permanent `4xx` errors (other than `408`/`429`) rather than advancing the
  checkpoint.
* Full setup and query examples: *Centralized forwarding* above.

### `dashboard/index.html`

* One static page with three anchored sections and scroll-spy navigation:
  **Overview**, **Attack Map**, and **Rankings**.
* Opens a WebSocket to `ws://<dashboard-host>:8765` (override with
  `?ws=wss://example.com/ws`) and reconnects with exponential backoff.
* Overview: summary cards, a live ticker, an attempts-per-minute chart for the
  last 30 minutes, top usernames, and a recent-activity table with search,
  local/external scope filters, a DShield filter, and progressive “Show more”
  paging.
* Attack Map: Leaflet with Esri Dark Gray base and label tiles. Country and
  state/region aggregates are all-time; live rings mark geolocated attempts
  (local cyan, external amber, DShield-listed red). Live markers expire after
  30 minutes. Supports zoom/pan, a legend, marker popups, and country/state
  search. The sensor location is not in the dataset, so no target marker is
  drawn.
* Rankings: sortable all-time country and state/region tables with relative
  bars, a recent source IP table built from the browser buffer, and connector
  status cards.
* States: loading skeletons, empty states, a missing-geolocation explanation,
  and a WebSocket error state with retry. Filters stay visible.
* Accessibility: landmark and heading structure, labelled controls, `aria-sort`
  on sortable tables, visible keyboard focus, `aria-pressed` on toggles,
  reduced-motion support, and a mobile card layout for tables.
* All attacker-controlled strings are inserted with `textContent`, not
  `innerHTML`, so a malicious username/password cannot inject HTML.

---

## Real-world monitoring (external sources)

The honeypot only sees traffic that reaches **your** port 2222. Feature 3 adds
a connector layer for observations collected elsewhere: public threat feeds,
your own JSON exports, or pushes from another sensor. Everything is configured
in `sources.json`; there is no vendor code in the dashboard.

External observations:

* appear in the live feed and ticker with an amber `external` badge;
* appear on the map (amber live rings) and in the all-time country/state
  rankings and hotspots;
* are counted in `external_attempts`, not in `attempts`;
* contribute to `unique_ips` (so that figure is hybrid) but do **not** change
  honeypot `connections`, attempts-per-minute, top usernames, or unique
  usernames;
* are stored separately in `logs/external_events.jsonl`.

### `sources.json`

The file is a JSON object with a `sources` array. `${VAR}` anywhere in the file
is replaced from the environment, so tokens do not need to be written to disk.

Common fields:

| Field | Required | Meaning |
| --- | --- | --- |
| `id` | yes | Stable id used in events, dedup keys, and `/api/ingest/<id>` |
| `type` | yes | `dshield`, `json_feed`, or `webhook` |
| `name` | no | Label shown on the dashboard (defaults to `id`) |
| `enabled` | no | Default `true`; set `false` to keep a source configured but off |
| `interval` | no | Seconds between polls, minimum 10, default 300 (poll sources only) |

Unknown types are skipped with a message; a bad entry does not stop the server.

#### `dshield` — SANS ISC public feed (enabled by default)

```json
{
  "id": "dshield-ssh",
  "type": "dshield",
  "name": "SANS ISC DShield SSH",
  "enabled": true,
  "feed": "openbl_ssh",
  "interval": 300,
  "limit": 25
}
```

* `feed: "openbl_ssh"` (default) — the DShield SSH brute-force blocklist:
  source IP, first seen, last seen. `limit` caps how many rows are ingested
  per poll (1–100).
* `feed: "topips"` — DShield's top attacking IPs across all protocols, with
  `reports`, `targets`, and `rank`.
* No API key. The server sends a descriptive `User-Agent` and polls every
  5 minutes; keep it polite. See <https://isc.sans.edu/api/>.

Access required: **outbound HTTPS to `isc.sans.edu`**. No account, no token.

#### `json_feed` — any HTTP(S) JSON endpoint

```json
{
  "id": "my-export",
  "type": "json_feed",
  "name": "My attack export",
  "enabled": true,
  "url": "https://example.com/attacks.json",
  "interval": 300,
  "timeout": 10,
  "headers": { "Authorization": "Bearer ${MY_FEED_TOKEN}" },
  "records_path": "data.items",
  "mapping": {
    "src_ip": "source.address",
    "ts": "observed_at",
    "username": "login",
    "auth_type": "method",
    "password": "credential",
    "client_version": "ssh.client",
    "src_port": "source.port"
  }
}
```

* `url` — endpoint returning JSON.
* `headers` — optional request headers; use `${VAR}` for secrets.
* `records_path` — dotted/indexed path to the record list (`data.items`,
  `results[0].events`). Without it the connector accepts a top-level array or
  looks for `events`, `data`, `results`, `items`, `records`, or `indicators`.
* `mapping` — maps our field names to paths in the record. Unmapped fields fall
  back to common names such as `src_ip`, `ip`, `ipv4`, `timestamp`, `date`,
  `username`, `user`, `password`.
* `timeout` — HTTP timeout in seconds, default 10.
* Up to 100 records are ingested per poll.

A record is skipped if it has no valid public or private IP literal. Missing
fields are defaulted (`username: "(external)"`, `auth_type: "external"`), so a
minimal feed only needs an IP.

Access required: **outbound HTTPS to the feed host**; a token only if that
endpoint requires one.

#### `webhook` — push events from another sensor

```json
{
  "id": "webhook",
  "type": "webhook",
  "name": "Operator webhook",
  "enabled": true,
  "token_env": "HONEYPOT_INGEST_TOKEN"
}
```

Set the token before starting the server:

```powershell
$env:HONEYPOT_INGEST_TOKEN = "a-long-random-value"
.\.venv\Scripts\python.exe server.py
```

If the variable is missing, the source is disabled and the dashboard shows
`disabled / missing token`. `token` may be used instead of `token_env`, but an
environment variable is safer.

Endpoints (same HTTP server as the dashboard):

```text
POST /api/ingest            # any enabled webhook source
POST /api/ingest/<source-id> # a specific webhook source
Authorization: Bearer <token>
# or
X-Honeypot-Token: <token>
```

Body: a JSON object, an array of objects, or `{"events": [...]}`. Example:

```powershell
$body = @{ events = @(
  @{ ip = "203.0.113.77"; user = "admin"; auth_type = "password";
     password = "p@ss"; client = "SSH-2.0-libssh" }
) } | ConvertTo-Json -Depth 5

Invoke-RestMethod -Method Post -Uri "http://127.0.0.1:8080/api/ingest" `
  -Headers @{ Authorization = "Bearer $env:HONEYPOT_INGEST_TOKEN" } `
  -ContentType "application/json" -Body $body
```

```bash
curl -sS -X POST http://127.0.0.1:8080/api/ingest \
  -H "Authorization: Bearer $HONEYPOT_INGEST_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"ip":"203.0.113.77","user":"admin","auth_type":"password"}'
```

Responses: `202 {"accepted": n, "source": "webhook"}`, `400` bad JSON,
`401` bad/missing token, `413` body outside 1–262144 bytes, `503` external
sources disabled. At most 100 records are accepted per request. A webhook
`mapping` block works the same as for `json_feed`.

Access required: **inbound HTTP to the dashboard port** from the pushing
sensor (localhost by default). Do not expose it to the internet without TLS
and a strong token; preferably keep it on a private network or behind a
reverse proxy.

### What Google and Instagram can actually provide

Neither Google nor Instagram publishes SSH honeypot telemetry. There is no
official feed of "SSH attacks from Google/Instagram", and scraping Instagram
is both against its terms and useless for this purpose. Use them only as
sources of *your own* export or alert data:

| Provider | What exists | Access needed | How to connect here |
| --- | --- | --- | --- |
| Google Cloud (Cloud Armor / Cloud Logging / VPC Flow Logs) | Security events and denied requests for **your** GCP project | A GCP project, IAM permission to read logs (`roles/logging.viewer`), and either the Logging API, a BigQuery export, or a Pub/Sub push subscription | Export/transform to JSON and expose it as a signed URL consumed by `json_feed`, or run a small forwarder that POSTs to `/api/ingest` |
| Google Threat Intelligence / VirusTotal (optional) | Reputation for IPs/domains, not SSH attempts | API key and quota | Poll its JSON API with `json_feed`; map the indicator IP and timestamp |
| Google Workspace / Takeout exports | Account audit logs, not attacker SSH traffic | Workspace admin export | Convert to JSON and serve it to `json_feed`, or push it via webhook |
| Instagram Graph API | Media, comments, account metadata for accounts you manage | Meta app, app review, user access token with `instagram_basic` (and related) permissions | It does not return SSH data; do not use it for attack monitoring. If you have a separate alert export, use `json_feed`/webhook |
| Instagram account security alerts | Login alerts for your own account | Manual export / email alerts | Parse your own export and POST normalized records to `/api/ingest` |

In short: **DShield is the only ready-to-use real-world SSH feed here.** Google
and Instagram require you to bring your own export or alert pipeline; the
connector layer is what makes that possible without changing code.

Other public feeds that fit the same `json_feed` connector: AbuseIPDB,
AlienVault OTX, GreyNoise, and CINSscore (each needs its own account/API key).
Check each provider's terms and rate limits.

### Counting, deduplication, and accuracy

* External events use the normal `auth_attempt` shape plus `external: true`,
  `source_id`, `source_name`, `source_url`, and optional `external_id`,
  `reports`, `targets`, `rank`, `first_seen`, `last_seen`.
* Deduplication key: `external_id` when the feed supplies one, otherwise
  `source_id + src_ip + UTC date`. The recent-key set is bounded to 20,000
  entries and seeded from `logs/external_events.jsonl` on startup, so a
  restart does not re-ingest the same observations.
* The DShield `openbl_ssh` feed is a **blocklist**, not a live attack on your
  sensor. Its timestamp is the feed's `lastseen` date, and one row is one
  source IP for that day. `topips` rows use the poll time.
* External events are observations from other vantage points. They can be
  stale, duplicated across feeds, or wrong. Geolocation is approximate, and
  attackers commonly use VPNs, proxies, and cloud hosts.
* Because external rows are not your sensor's traffic, they are excluded from
  `attempts`, the per-minute chart, and username rankings. The feed header
  shows the combined event count; the **Login attempts** stat stays
  honeypot-only.

### Persistence and reset

* External events are appended to `logs/external_events.jsonl` **after**
  geolocation, so a restart does not repeat lookups.
* The store rotates to `external_events.jsonl.1` at 5 MB and loads the last
  5,000 events at startup.
* To reset only external data, stop `server.py`, delete
  `logs/external_events.jsonl` (and `.1`), and restart. `logs/events.jsonl` is
  untouched.
* The honeypot log remains the authoritative record of traffic that reached
  this sensor.

### Disabling Feature 3

```powershell
.\.venv\Scripts\python.exe server.py --no-external
```

This starts no pollers, disables `/api/ingest`, and leaves the honeypot feed
exactly as it was before Feature 3.

---

## Centralized forwarding (Elasticsearch / ClickHouse)

`forwarder.py` is an optional, outbound-only process. It tails the same JSONL
files, batches complete lines, and sends them over TLS to a centralized
Elasticsearch or ClickHouse cluster. It does not listen on a port, does not
change the dashboard, and uses only the Python standard library — the same
`.venv` that runs the honeypot runs the forwarder.

If you already operate Vector or Fluent Bit, its file source can ship
`logs/events.jsonl` too; the schema and idempotency notes below still apply.
The included forwarder exists so you do not need a second runtime.

### How it works

* Tails `logs/events.jsonl` (and, with `--include-external`,
  `logs/external_events.jsonl`).
* Consumes only complete lines. A half-written line stays in the file until the
  writer finishes it.
* Batches up to `--batch-size` events or `--flush-interval` seconds, whichever
  comes first.
* Saves a byte-offset checkpoint **after** the backend acknowledges a batch.
  On restart it resumes from that offset. Rotation or truncation is detected
  and the file restarts at byte 0.
* TLS certificate verification is on by default. A private CA and mTLS client
  certificates are supported.
* Credentials are read from environment variables, never from the command
  line.
* At-least-once delivery: Elasticsearch uses the event `id` as `_id`, and
  ClickHouse uses `ReplacingMergeTree`, so retries converge instead of
  duplicating.
* Bounded memory: at most one batch is buffered. If the backend is down the
  forwarder retries with capped exponential backoff and leaves the rest of the
  log on disk.

### Elasticsearch

Install the index template once:

```bash
curl -sS -X PUT "https://es.example.com:9200/_index_template/ssh-honeypot" \
  -H "Content-Type: application/json" \
  -H "Authorization: ApiKey $HONEYPOT_ES_API_KEY" \
  --cacert /etc/ssl/certs/internal-ca.pem \
  --data-binary @deploy/elasticsearch-index-template.json
```

Set credentials and run:

```bash
export HONEYPOT_ES_API_KEY="..."      # or HONEYPOT_ES_USER / HONEYPOT_ES_PASSWORD
python forwarder.py \
  --backend elasticsearch \
  --url https://es.example.com:9200 \
  --ca-cert /etc/ssl/certs/internal-ca.pem \
  --include-external
```

On Windows PowerShell:

```powershell
$env:HONEYPOT_ES_API_KEY = "..."
.\.venv\Scripts\python.exe forwarder.py --backend elasticsearch `
  --url https://es.example.com:9200 `
  --ca-cert C:\certs\internal-ca.pem --include-external
```

* Documents go to daily indices named `ssh-honeypot-YYYY-MM-DD`
  (`--index-prefix` changes the prefix).
* `_id` is the honeypot event id, or a deterministic hash for records without
  an `id`.
* `@timestamp` and `ingested_at` are added for Kibana/ES|QL.
* The template uses 1 shard and 1 replica. On a single-node cluster set
  `number_of_replicas` to `0` in the template, or the index stays yellow.
* Without `HONEYPOT_ES_API_KEY` or `HONEYPOT_ES_USER`, the forwarder continues
  unauthenticated and prints a warning. Use that only for a secured network.
* Per-document mapping errors are logged and skipped so one malformed event
  cannot block the pipeline; transport-level `4xx` errors still stop the
  forwarder without advancing the checkpoint.

### ClickHouse

Apply the schema once:

```bash
clickhouse-client --secure --host ch.example.com --user honeypot \
  --password "$HONEYPOT_CH_PASSWORD" \
  --queries-file deploy/clickhouse-schema.sql
```

Run:

```bash
export HONEYPOT_CH_USER="honeypot"
export HONEYPOT_CH_PASSWORD="..."
python forwarder.py \
  --backend clickhouse \
  --url https://ch.example.com:8443 \
  --database ssh_honeypot --table events \
  --include-external
```

* Uses the ClickHouse HTTP interface with `INSERT ... FORMAT JSONEachRow`.
* `ReplacingMergeTree(ingested_at)` with `ORDER BY (src_ip, ts, id)` makes
  retries converge. Query with `FINAL`, or run `OPTIMIZE TABLE ... FINAL`, when
  you need deduplicated reads.
* Rows are partitioned by month and carry flat `geo_*` columns.
* The schema stores the attempted `password` in plaintext. Restrict access as
  described under *Security notes for the forwarder*.

### TLS and authentication

| Option | Purpose |
| --- | --- |
| (default) | Verify the server certificate with the system CA store |
| `--ca-cert FILE` | Verify with a private/internal CA bundle |
| `--client-cert FILE --client-key FILE` | Present an mTLS client certificate |
| `--insecure` | Disable verification (prints a warning; testing only) |
| `--allow-plaintext` | Permit `http://` (local test backend only) |

Credentials:

| Backend | Environment variables |
| --- | --- |
| Elasticsearch | `HONEYPOT_ES_API_KEY`, or `HONEYPOT_ES_USER` + `HONEYPOT_ES_PASSWORD` |
| ClickHouse | `HONEYPOT_CH_USER`, `HONEYPOT_CH_PASSWORD` |

Override the names with `--api-key-env`, `--username-env`, and
`--password-env`. Never pass secrets as command-line flags: they appear in the
process list and shell history.

### Backfill and one-shot runs

`--start beginning` (the default) ships existing history the first time;
`--start end` skips it. Once a checkpoint exists, `--start` is ignored. To
backfill the current backlog and exit:

```bash
python forwarder.py --backend elasticsearch \
  --url https://es.example.com:9200 \
  --log /var/log/ssh-honeypot/events.jsonl \
  --once --verbose
```

`--once` exits when the current backlog is acknowledged; it does not wait for
new events. Omit it for a long-running service.

### Scaling across multiple honeypot nodes

* Run one forwarder per honeypot host. Apart from its local checkpoint file it
  is stateless, so nodes never coordinate with each other.
* Give every sensor a distinct `--index-prefix` (Elasticsearch) or
  database/table (ClickHouse), or add a `sensor` field before shipping, so you
  can tell nodes apart. The event schema does not include a hostname.
* Elasticsearch scales by adding data nodes and raising `number_of_shards` for
  future daily indices in the template; existing indices keep their shard
  count.
* ClickHouse scales with sharding/replication at the cluster layer; the
  forwarder simply writes to the endpoint you configure.
* Keep each host's `state/forwarder-*.json` on persistent storage and never
  copy it between hosts: it records device/inode/offset values for that host's
  files.
* Several forwarders may retry the same batch after a network failure;
  idempotent ids make that safe.

### systemd

`deploy/ssh-honeypot-forwarder.service` is a sandboxed unit. Edit the backend,
URL, and log path, put credentials in `/etc/ssh-honeypot/forwarder.env` (mode
`0600`), then:

```bash
sudo cp deploy/ssh-honeypot-forwarder.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now ssh-honeypot-forwarder
journalctl -u ssh-honeypot-forwarder -f
```

The unit runs as the `honeypot` user, reads the program and log read-only, and
writes only its state directory.

### Query examples

Elasticsearch (Kibana Dev Tools or `curl`). Attempts by country, honeypot
traffic only:

```json
GET ssh-honeypot-*/_search
{
  "size": 0,
  "query": { "term": { "external": false } },
  "aggs": {
    "by_country": {
      "terms": { "field": "geo.country_code", "size": 20 }
    }
  }
}
```

Top attempted usernames in the last 24 hours:

```json
GET ssh-honeypot-*/_search
{
  "size": 0,
  "query": {
    "bool": {
      "filter": [
        { "term": { "event": "auth_attempt" } },
        { "range": { "@timestamp": { "gte": "now-24h" } } }
      ]
    }
  },
  "aggs": { "users": { "terms": { "field": "username", "size": 20 } } }
}
```

ClickHouse:

```sql
SELECT geo_country_code, count() AS attempts
FROM ssh_honeypot.events FINAL
WHERE event = 'auth_attempt' AND NOT external
  AND ts >= now() - INTERVAL 1 DAY
GROUP BY geo_country_code
ORDER BY attempts DESC
LIMIT 20;

SELECT username, count() AS attempts
FROM ssh_honeypot.events FINAL
WHERE event = 'auth_attempt' AND ts >= now() - INTERVAL 1 DAY
GROUP BY username
ORDER BY attempts DESC
LIMIT 20;
```

### Retention

The forwarder never deletes local or remote data. Use Elasticsearch ILM /
index lifecycle policies, or a ClickHouse TTL (there is a commented example in
`deploy/clickhouse-schema.sql`). The local JSONL remains the source of truth
for the dashboard.

### Security notes for the forwarder

* The `password` field is plaintext by design. Give the backend writer
  write-only access to the honeypot index/table, and restrict read access to
  operators who are allowed to see attempted credentials.
* Use a dedicated backend user, not an admin or the `elastic` superuser.
* Keep `forwarder.env`, CA files, and client keys out of the repository and
  mode `0600`.
* `--insecure` and `--allow-plaintext` are for local testing only.
* The forwarder is outbound-only. Do not open an inbound port for it.

---

## Isolation (non-negotiable)

The honeypot is designed so attacker activity cannot reach the host:

1. **Unprivileged process.** `honeypot.py` refuses to start as root or with a
   Windows Administrator token. Run it as a dedicated standard user (or, for
   local testing, your normal non-admin account).
2. **No shell or command path.** Every Paramiko channel callback returns
   failure. There is no `subprocess`, `os.system`, `exec`, SFTP server, or
   file-opening code in the request path. Authentication always returns
   `AUTH_FAILED`.
3. **One writable path.** The running process opens only
   `<log-dir>/events.jsonl` in append mode. The host key is read-only and is
   created by `--init` before the service starts.
4. **One listening socket.** The honeypot binds only TCP/2222. The dashboard
   and WebSocket server are separate processes on separate ports and bind to
   `127.0.0.1` by default.
5. **Deployment sandbox.** The included systemd unit uses
   `ProtectSystem=strict`, `ProtectHome=yes`, `PrivateTmp=yes`,
   `NoNewPrivileges=yes`, an empty capability set, and
   `ReadWritePaths=/var/log/ssh-honeypot`. On Windows, use a standard local
   user plus ACLs and firewall rules (below).
6. **Defense in depth.** Paramiko is the only parser of attacker input. Keep
   it patched. For hostile internet exposure, run the honeypot in a dedicated
   VM/container as well; the code itself still never grants host access.

### Windows: dedicated standard user

The current project lives under your user profile. For a real deployment,
copy it somewhere the dedicated account can read, for example
`C:\ssh-honeypot`, and use a system-wide Python installation (the “Install for
all users” option). A per-user Python under `C:\Users\...` may be unreadable
to the honeypot account.

Elevated PowerShell, once:

```powershell
$Source = "C:\path\to\ssh-honeypot-live-dashboard"
$Target = "C:\ssh-honeypot"

robocopy $Source $Target /E /XD .venv logs state __pycache__ /NFL /NDL /NJH /NJS
New-Item -ItemType Directory -Force "$Target\logs" | Out-Null

# System-wide Python is assumed here. Create the venv in the target.
python -m venv "$Target\.venv"
& "$Target\.venv\Scripts\python.exe" -m pip install -r "$Target\requirements.txt"
& "$Target\.venv\Scripts\python.exe" "$Target\honeypot.py" --init

$Password = Read-Host -AsSecureString "Password for the ssh-honeypot account"
New-LocalUser -Name "ssh-honeypot" -Password $Password `
    -FullName "SSH Honeypot" -Description "Unprivileged honeypot account" `
    -AccountNeverExpires -PasswordNeverExpires

# Read/execute the program; modify only the log directory; read the host key.
icacls $Target /grant "ssh-honeypot:(OI)(CI)RX"
icacls "$Target\logs" /grant "ssh-honeypot:(OI)(CI)M"
icacls "$Target\state" /grant "ssh-honeypot:R"

# Only 2222 is reachable from outside. 8080/8765 stay loopback-only anyway.
New-NetFirewallRule -DisplayName "SSH Honeypot 2222" -Direction Inbound `
    -Protocol TCP -LocalPort 2222 -Action Allow
New-NetFirewallRule -DisplayName "Block honeypot dashboard" -Direction Inbound `
    -Protocol TCP -LocalPort 8080,8765 -Action Block
```

Start the honeypot as that user from a normal PowerShell:

```powershell
$cred = Get-Credential -UserName "ssh-honeypot" -Message "Honeypot account"
$hp = Start-Process -FilePath "C:\ssh-honeypot\.venv\Scripts\python.exe" `
    -ArgumentList "honeypot.py" `
    -WorkingDirectory "C:\ssh-honeypot" `
    -Credential $cred `
    -RedirectStandardOutput "C:\ssh-honeypot\logs\honeypot.out" `
    -RedirectStandardError  "C:\ssh-honeypot\logs\honeypot.err" `
    -PassThru
$hp.Id
```

Stop it with `Stop-Process -Id <pid>`. If `Start-Process -Credential` is
blocked by policy, use
`runas /user:ssh-honeypot "C:\ssh-honeypot\.venv\Scripts\python.exe C:\ssh-honeypot\honeypot.py"`.

Run `server.py` as your normal account (it only reads the log):

```powershell
& "C:\ssh-honeypot\.venv\Scripts\python.exe" "C:\ssh-honeypot\server.py"
```

If Python is installed only for your user, the `ssh-honeypot` account cannot
load it. Either install Python for all users, or grant traverse/read access
to the Python installation directory. Do not “fix” this by making the
honeypot account an Administrator.

### Linux: systemd sandbox

```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin honeypot
sudo mkdir -p /opt/ssh-honeypot /etc/ssh-honeypot /var/log/ssh-honeypot

sudo cp honeypot.py server.py forwarder.py requirements.txt /opt/ssh-honeypot/
sudo cp -r dashboard /opt/ssh-honeypot/

sudo python3 -m venv /opt/ssh-honeypot/.venv
sudo /opt/ssh-honeypot/.venv/bin/pip install -r /opt/ssh-honeypot/requirements.txt

sudo env HONEYPOT_STATE_DIR=/etc/ssh-honeypot \
    /opt/ssh-honeypot/.venv/bin/python /opt/ssh-honeypot/honeypot.py --init

sudo chown -R root:root /opt/ssh-honeypot /etc/ssh-honeypot
sudo chown -R honeypot:honeypot /var/log/ssh-honeypot
sudo chmod 750 /var/log/ssh-honeypot
sudo chgrp honeypot /etc/ssh-honeypot/host_rsa.key
sudo chmod 640 /etc/ssh-honeypot/host_rsa.key

sudo cp deploy/ssh-honeypot.service deploy/ssh-honeypot-dashboard.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now ssh-honeypot ssh-honeypot-dashboard
```

Verify:

```bash
systemctl status ssh-honeypot --no-pager
ss -ltnp | grep -E '2222|8765|8080'
```

Expected: `2222` on `0.0.0.0`/`[::]`; `8765` and `8080` on `127.0.0.1` only.

Centralized forwarding is optional and independent of the two units above.
Copy `deploy/ssh-honeypot-forwarder.service`, put credentials in
`/etc/ssh-honeypot/forwarder.env`, and follow *Centralized forwarding* to
install the Elasticsearch template or ClickHouse schema first.

Firewall (example with ufw):

```bash
sudo ufw allow 2222/tcp
sudo ufw deny 8080/tcp
sudo ufw deny 8765/tcp
```

### Hosting the dashboard securely

The dashboard has **no login** and displays attacker IPs, usernames, and
passwords. Do not expose `8765` or `8080` to the internet.

* **Recommended: SSH tunnel** (nothing new exposed):

  ```bash
  ssh -L 8080:127.0.0.1:8080 -L 8765:127.0.0.1:8765 user@honeypot-host
  ```

  Then open <http://127.0.0.1:8080> on your laptop. Both ports are forwarded
  over SSH.

* **Reverse proxy**: the included Compose deployment below provides Nginx,
  automatic Let's Encrypt certificates, and either Basic Auth or OAuth2 Proxy.
  It proxies `/` to `127.0.0.1:8080` and `/ws` to `127.0.0.1:8765` while both
  application services stay bound to loopback.

* Keep the services bound to `127.0.0.1`. If you change `--ws-host` /
  `--http-host` to `0.0.0.0`, you must add a firewall and authentication.

### Docker Compose: Nginx, Let's Encrypt, and authentication

The included `docker-compose.yml` is an optional **Linux Docker Engine** edge
proxy. Nginx and OAuth2 Proxy use host networking so they can reach the
existing host services on `127.0.0.1`; ports 8080 and 8765 are not published.
This deliberately does not work with ordinary Docker Desktop bridge networking
on Windows/macOS. Keep the Python services running on the host as usual.

Requirements: a Linux server with Docker Compose v2, a public DNS A record for
the dashboard hostname, inbound TCP ports 80 and 443 allowed, and the existing
server running on `127.0.0.1:8080`/`:8765`. If the DNS zone has an AAAA record,
it must point to a working IPv6 listener too. Let's Encrypt HTTP-01 validation
requires the hostname to resolve to this server and port 80 to be reachable.

#### 1. Set the hostname and email

```bash
cp .env.proxy.example .env.proxy
chmod 600 .env.proxy
```

Edit `.env.proxy`: set `DOMAIN` to the public hostname and `LE_EMAIL` to an
address for certificate notices. Leave `AUTH_MODE=basic` for the default.
`.env.proxy` and certificate data are ignored by Git.

#### 2. Allow the HTTPS page's WebSocket Origin

The dashboard automatically uses `wss://<DOMAIN>/ws` when loaded over HTTPS.
The Python WebSocket server also checks the browser Origin, so allow the exact
site origin. For the included systemd unit, create an override:

```bash
sudo systemctl edit ssh-honeypot-dashboard
```

Add this drop-in, replacing the hostname and keeping the unit's existing log
and port arguments:

```ini
[Service]
ExecStart=
ExecStart=/opt/ssh-honeypot/.venv/bin/python /opt/ssh-honeypot/server.py --log /var/log/ssh-honeypot/events.jsonl --ws-host 127.0.0.1 --ws-port 8765 --http-host 127.0.0.1 --http-port 8080 --allow-origin https://dashboard.example.com
```

Then run `sudo systemctl daemon-reload && sudo systemctl restart ssh-honeypot-dashboard`.

#### 3A. Start with Basic Authentication

Create a bcrypt password file; the command prompts for the password rather
than placing it in shell history:

```bash
mkdir -p proxy/auth
docker run --rm -it -v "$PWD/proxy/auth:/auth" httpd:2.4-alpine \
  htpasswd -B /auth/.htpasswd dashboard-admin
chmod 640 proxy/auth/.htpasswd
```

Start the edge proxy and obtain the first certificate:

```bash
docker compose --env-file .env.proxy up -d --build edge
docker compose --env-file .env.proxy logs -f edge
```

Open `https://<DOMAIN>`. Nginx requests the initial certificate on first
startup and renews it every 12 hours when due. Port 80 serves only the ACME
challenge and redirects ordinary traffic to HTTPS after issuance. Basic Auth
protects both the dashboard page and its WebSocket endpoint.

#### 3B. Use OAuth2 Proxy instead

Register an OIDC application with your identity provider using callback URL
`https://<DOMAIN>/oauth2/callback`. In `.env.proxy`, set `AUTH_MODE=oauth2`,
the issuer URL, client ID/secret, an explicit allowed email domain, and a
random cookie secret. Generate a cookie secret with:

```bash
python3 -c 'import secrets,base64; print(base64.urlsafe_b64encode(secrets.token_bytes(32)).decode())'
```

Start both services with the OAuth2 profile:

```bash
docker compose --env-file .env.proxy --profile oauth2 up -d --build
docker compose --env-file .env.proxy --profile oauth2 logs -f
```

OAuth2 Proxy listens only on `127.0.0.1:4180`; Nginx uses its `/auth` endpoint
to protect the dashboard and WebSocket. The OAuth2 Proxy image is pinned to
v7.15.5. Its Nginx `auth_request` integration follows the [official guide](https://oauth2-proxy.github.io/oauth2-proxy/configuration/integrations/nginx/).

#### Operations and limits

* Nginx binds public ports 80/443 via Linux host networking; confirm no other
  host process already owns those ports. OAuth2 Proxy's port 4180 and the
  dashboard's 8080/8765 remain loopback-only.
* The dashboard displays sensitive telemetry, including attempted credentials.
  Use Basic Auth with a unique strong password, or restrict the OIDC allowed
  email domain to trusted accounts. Do not expose the application ports.
* To change auth modes, set `AUTH_MODE` to `basic` or `oauth2` and recreate the
  edge container. OAuth mode additionally requires `--profile oauth2`.
* Stop the proxy with `docker compose --env-file .env.proxy down`. Certificate
  state persists under `proxy/data/letsencrypt`.

---

## GeoIP setup

The map and country/state rankings need a local MaxMind **GeoLite2-City**
database. There is no third-party geolocation fallback.

1. Create a free MaxMind account and download **GeoLite2-City** (`.mmdb`).
2. Put it at `GeoLite2-City.mmdb` in the project root, or pass
   `--geoip-db C:\path\to\GeoLite2-City.mmdb`.
3. Restart `server.py`. Expected: `[geo] lookup: MaxMind (GeoLite2-City.mmdb)`.

Lookups are asynchronous (`asyncio.to_thread`) and cached in memory. No
attacker IP leaves the machine. Without the database the server prints
`[geo] lookup: disabled (...)`; events still stream, but they have no
coordinates or country/state ranking entry, and the map says location data is
missing.

Private, loopback, link-local, and reserved addresses are classified locally
and never looked up. That is why `127.0.0.1` has no map marker.

---

## Event log format

One JSON object per line. `connection` events have no credentials;
`auth_attempt` events do.

| Field | Meaning |
| --- | --- |
| `id` | Unique event id (used by the dashboard to deduplicate reconnects) |
| `ts` | UTC timestamp, ISO-8601 with milliseconds and `Z` |
| `event` | `connection` or `auth_attempt` |
| `connection_id` | Short id shared by events from one TCP connection |
| `src_ip`, `src_port` | Attacker address |
| `client_version` | SSH identification string, when known |
| `username` | Attempted username |
| `auth_type` | `password`, `publickey`, or `keyboard-interactive` |
| `password` | Attempted password (plaintext by design) |
| `key_type`, `key_bits`, `key_fingerprint` | Public-key details, when offered |
| `geo` | `{lat, lon, city, country, country_code, source}` or `null` |
| `geo_status` | `ok`, `private`, `invalid`, `unavailable`, or `n/a` |

The dashboard adds `geo`/`geo_status` in memory before broadcasting; the
honeypot itself never makes network lookups.

External observations use the same `auth_attempt` shape and are written to
`logs/external_events.jsonl` instead of `logs/events.jsonl`:

| Field | Meaning |
| --- | --- |
| `external` | Always `true` for connector-sourced events |
| `source_id`, `source_name` | Connector id and dashboard label |
| `source_url` | Feed URL, when the source has one |
| `external_id` | Feed's own id, used for deduplication when present |
| `reports`, `targets`, `rank` | Optional feed metadata (DShield `topips`) |
| `first_seen`, `last_seen` | Optional feed dates (DShield `openbl_ssh`) |

External events carry the same `geo`/`geo_status` enrichment as local ones.

---

## Operations

### Log rotation

The tailer handles truncation and replacement. On Linux, use `copytruncate`:

```text
/var/log/ssh-honeypot/events.jsonl {
    daily
    rotate 14
    compress
    missingok
    notifempty
    copytruncate
}
```

On Windows, stop both processes, move/delete `logs\events.jsonl`, and restart.
The server rebuilds statistics from whatever remains. The forwarder detects
truncation and restarts that file at byte 0, so `copytruncate` is safe.

### Ports

| Port | Process | Default bind | Exposure |
| --- | --- | --- | --- |
| 2222/tcp | `honeypot.py` | `0.0.0.0` | The only attacker-facing port |
| 8765/tcp | `server.py` WebSocket | `127.0.0.1` | Operator only |
| 8080/tcp | `server.py` static page + `POST /api/ingest` | `127.0.0.1` | Operator only |
| none | `forwarder.py` | outbound only | No listener |

Change them with `--port`, `--ws-port`, `--http-port`. If you change the
WebSocket port, also open the dashboard with `?ws=ws://host:NEWPORT`. The
webhook shares the HTTP port, so moving the dashboard also moves
`/api/ingest`.

### Reset statistics

Stop `server.py` and `honeypot.py`, remove `logs/events.jsonl`, restart both.
There is no database; the log is the only state.

To reset only the external observations, remove `logs/external_events.jsonl`
(and `external_events.jsonl.1`) while the server is stopped. To clear both,
remove both logs. External sources will re-poll from scratch on the next
start, subject to their own feed contents.

---

## Troubleshooting

| Symptom | Fix |
| --- | --- |
| `ModuleNotFoundError: paramiko` | Use `.\.venv\Scripts\python.exe` (or activate the venv), not the system Python |
| `Host key not found` | Run `python honeypot.py --init` once |
| `Refusing to run with an Administrator token` / `as root` | Open a normal terminal or run as the dedicated unprivileged user |
| `Address already in use` on 2222 | `Get-NetTCPConnection -LocalPort 2222` (Windows) or `ss -ltnp \| grep 2222` (Linux) |
| Dashboard says Reconnecting or Offline | Is `server.py` running? Is 8765 blocked? Check the server terminal |
| Events appear in the log but not the dashboard | Confirm `server.py --log` points at the same file |
| Real-world feeds panel (under Rankings) is empty | `sources.json` is missing or every source is disabled; do not start with `--no-external` |
| Webhook card says `disabled` / `missing token` | Set `HONEYPOT_INGEST_TOKEN` in the same terminal **before** starting `server.py` |
| DShield card shows `error` | Outbound HTTPS to `isc.sans.edu` is blocked or the API is rate-limiting; see the server terminal |
| `POST /api/ingest` returns 401 | Token mismatch or missing header; use `Authorization: Bearer <token>` or `X-Honeypot-Token` |
| External IPs look old | `openbl_ssh` is a blocklist; its timestamp is the feed's `lastseen` date, not the poll time |
| Duplicate external events after restart | Check that `logs/external_events.jsonl` was not deleted; dedup is `source + IP + UTC date` when the feed has no id |
| Forwarder: `CERTIFICATE_VERIFY_FAILED` | Pass `--ca-cert` for a private CA, make sure the certificate's hostname matches `--url`, or fix the system CA store. Do not use `--insecure` in production |
| Forwarder: Elasticsearch `401` / `403` | Set `HONEYPOT_ES_API_KEY` or `HONEYPOT_ES_USER`/`HONEYPOT_ES_PASSWORD`; the role needs `create_index` and `create`/`index` on `ssh-honeypot-*` |
| Forwarder: ClickHouse `401` / `516` | Set `HONEYPOT_CH_USER`/`HONEYPOT_CH_PASSWORD`; confirm the user can `INSERT` into the configured database/table |
| Forwarder: `permanent backend error: HTTP 400` | Schema or mapping mismatch. Install `deploy/elasticsearch-index-template.json` or apply `deploy/clickhouse-schema.sql` before shipping |
| Forwarder: `checkpoint ... belongs to backend ...` | Use a separate `--checkpoint` per backend, or delete the stale checkpoint if you are intentionally switching |
| Forwarder ships nothing on first run | `--start end` skips existing history; use `--start beginning`, or check that `--log` points at the real file |
| Forwarder exits immediately with `--once` | Expected: it ships the current backlog and stops. Drop `--once` for continuous shipping |
| Forwarder: `refusing plaintext HTTP` | Use an `https://` URL. `--allow-plaintext` is only for a local test backend |
| Duplicate rows after a retry | Expected at-least-once behavior. Elasticsearch `_id` and ClickHouse `ReplacingMergeTree` converge; query ClickHouse with `FINAL` for deduplicated reads |
| Map is empty for local tests | `127.0.0.1` is private and intentionally not geolocated; use the Step 7 demo event or a real public source |
| Map is empty for public IPs | No MaxMind GeoLite2-City database, or the IP is private/unlocated; add the database and restart `server.py` |
| Map/chart blank, page unstyled | Leaflet/Chart.js CDNs are blocked; allow `unpkg.com` and `cdn.jsdelivr.net`, or vendor those files |
| Map shows OpenStreetMap 403 tiles | Refresh the dashboard after updating; it now uses Esri Dark Gray tiles. If those are blocked by the network, allow `server.arcgisonline.com` or configure an accessible tile service. |
| `ssh` warns about the host key | Expected on every restart; use `-o StrictHostKeyChecking=no -o UserKnownHostsFile=NUL` only for testing |

---

## Security notes

* **The log contains plaintext attempted passwords.** Treat it as sensitive.
  The honeypot creates it `0600`; keep the log directory restricted, rotate
  it, and never commit `logs/`.
* **The dashboard is unauthenticated.** Bind it to localhost and use an SSH
  tunnel or an authenticated TLS reverse proxy. Do not expose 8080/8765.
* **`/api/ingest` is token-authenticated, not encrypted.** It shares the
  dashboard HTTP port and is loopback-only by default. If you must expose it,
  put it behind TLS, use a long random token, and rate-limit it. Keep feed
  credentials in `sources.json` as `${ENV_VAR}` placeholders, never as
  committed values.
* **External feeds are untrusted input.** Field sizes are bounded and the
  dashboard renders strings with `textContent`, but a feed can still insert
  arbitrary IPs and usernames into the map and rankings. Only enable feeds you
  trust. `logs/external_events.jsonl` can contain pushed credentials and must
  be protected like `logs/events.jsonl`.
* **The honeypot is not a substitute for a patched host.** It rejects
  attacker logins and has no shell path, but Paramiko still parses untrusted
  input. Patch dependencies (`pip install -U -r requirements.txt`) and use the
  systemd sandbox or a dedicated VM for internet-facing deployments.
* **The forwarder copies plaintext credentials to another system.** The
  backend index/table inherits the sensitivity of `logs/events.jsonl`. Use a
  dedicated write-only backend user, TLS with verification, restricted network
  access, and a retention policy. Keep `forwarder.env` and client keys out of
  the repository.
* **Only 2222 should be reachable.** Verify with `ss -ltnp` / `netstat -ano`
  and a firewall rule. The dashboard ports should show `127.0.0.1`, not
  `0.0.0.0`.
* **Do not run this on a machine with data you cannot afford to lose.**
  Isolate it. That is the point.
