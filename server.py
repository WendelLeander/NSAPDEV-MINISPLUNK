"""
==============================================================================
  Mini-Splunk: Concurrent Syslog Analytics Server  —  server.py  (Indexer)
==============================================================================
  NSAPDEV Server Application Project
  Author  : Wendel Walter A. Lander
  Course  : NSAPDEV (Server Application Development)
  Term/AY : 2nd Term AY 2025-2026

  Architecture : Client-Server, Thread-per-Connection, Shared In-Memory Store
  Protocol     : Custom pipe-delimited TCP/IPv4 over UTF-8
==============================================================================
"""

import socket
import threading
import re
import sys
import signal
import time

# ─────────────────────────────────────────────────────────────────────────────
# CONFIGURATION
# ─────────────────────────────────────────────────────────────────────────────
DEFAULT_HOST = "0.0.0.0"
DEFAULT_PORT = 8080
BUFFER_SIZE  = 4096

# ─────────────────────────────────────────────────────────────────────────────
# MODULE 1 — PARSING MODULE
# Transforms raw syslog text into structured dictionaries.
# Supports two patterns:
#   A) Logs that explicitly carry a severity token  (WARN / ERROR / INFO …)
#   B) Standard RFC-3164-style logs without an explicit severity field
#      → severity is inferred from well-known keywords in the message body.
# ─────────────────────────────────────────────────────────────────────────────

# Pattern A: explicit severity embedded in the line
_PATTERN_WITH_SEVERITY = re.compile(
    r"^(?P<timestamp>[A-Z][a-z]{2}\s{1,2}\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<hostname>\S+)\s+"
    r"(?P<daemon>\S+)\s+"
    r"(?P<severity>INFO|WARN|WARNING|ERROR|DEBUG|CRIT|CRITICAL|NOTICE|ALERT|EMERG)\s+"
    r"(?P<message>.+)$",
    re.IGNORECASE,
)

# Pattern B: standard RFC-3164 / typical Linux auth-log format
_PATTERN_STANDARD = re.compile(
    r"^(?P<timestamp>[A-Z][a-z]{2}\s{1,2}\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<hostname>\S+)\s+"
    r"(?P<daemon>\S+?)(?:\[\d+\])?:\s+"
    r"(?P<message>.+)$",
)

# Severity inference keywords (ordered: most specific first)
_SEV_KEYWORDS = [
    (re.compile(r"\b(crit(?:ical)?|emerg(?:ency)?|alert)\b",   re.I), "CRIT"),
    (re.compile(r"\b(error|err|fail(?:ed|ure)?|invalid|reset)\b", re.I), "ERROR"),
    (re.compile(r"\b(warn(?:ing)?)\b",                           re.I), "WARN"),
    (re.compile(r"\b(debug)\b",                                  re.I), "DEBUG"),
]


def _infer_severity(message: str) -> str:
    """Infer severity from keywords present in the message text."""
    for pattern, level in _SEV_KEYWORDS:
        if pattern.search(message):
            return level
    return "INFO"


def parse_line(raw_line: str) -> dict | None:
    """
    Parse a single syslog line into a structured dictionary.

    Returns a dict with keys: timestamp, hostname, daemon, severity, message.
    Returns None if the line cannot be parsed.
    """
    raw_line = raw_line.strip()
    if not raw_line:
        return None

    # Try Pattern A first (explicit severity)
    m = _PATTERN_WITH_SEVERITY.match(raw_line)
    if m:
        entry = m.groupdict()
        entry["severity"] = entry["severity"].upper()
        return entry

    # Fall back to Pattern B (standard format, infer severity)
    m = _PATTERN_STANDARD.match(raw_line)
    if m:
        entry = m.groupdict()
        entry["severity"] = _infer_severity(entry["message"])
        return entry

    return None


# ─────────────────────────────────────────────────────────────────────────────
# MODULE 2 — DATA STORAGE MODULE
# Single source of truth; enforces strict concurrency control via RLock.
# ─────────────────────────────────────────────────────────────────────────────

class LogStore:
    """
    Thread-safe in-memory log repository.

    Locking strategy
    ────────────────
    • INGEST (write)  → acquires the lock exclusively before appending.
    • SEARCH / COUNT  → acquires the lock for read (RLock allows re-entrancy
                        from same thread but still blocks a concurrent PURGE).
    • PURGE           → acquires the lock exclusively; no reads or writes may
                        proceed while the clear operation is in progress.
    """

    def __init__(self):
        self._logs: list[dict] = []
        self._lock = threading.RLock()      # Re-entrant mutex
        self._stats = {"ingested": 0, "purged": 0}

    # ── Write ──────────────────────────────────────────────────────────────
    def insert_logs(self, entries: list[dict]) -> int:
        """Append a batch of parsed log entries. Returns count inserted."""
        with self._lock:
            self._logs.extend(entries)
            self._stats["ingested"] += len(entries)
            return len(entries)

    # ── Read ───────────────────────────────────────────────────────────────
    def get_logs(self) -> list[dict]:
        """Return a snapshot of all indexed log entries."""
        with self._lock:
            return list(self._logs)

    def count(self) -> int:
        """Return the current number of indexed entries."""
        with self._lock:
            return len(self._logs)

    # ── Exclusive Write (PURGE) ────────────────────────────────────────────
    def clear_logs(self) -> int:
        """
        Atomically erase all log entries.
        Acquires the exclusive lock — no concurrent reads or writes allowed.
        Returns the number of entries erased.
        """
        with self._lock:
            n = len(self._logs)
            self._logs.clear()
            self._stats["purged"] += n
            return n

    # ── Stats ──────────────────────────────────────────────────────────────
    def stats(self) -> dict:
        with self._lock:
            return {**self._stats, "current": len(self._logs)}


# Singleton data store shared across all worker threads
_store = LogStore()


# ─────────────────────────────────────────────────────────────────────────────
# MODULE 3 — QUERY ENGINE MODULE
# Executes analytical and administrative commands against the data store.
# ─────────────────────────────────────────────────────────────────────────────

def _format_entry(e: dict) -> str:
    return f"{e['timestamp']} {e['hostname']} {e['daemon']} [{e['severity']}] {e['message']}"


def query_search_date(date_str: str) -> tuple[int, list[str]]:
    logs = _store.get_logs()
    results = [_format_entry(e) for e in logs if e["timestamp"].startswith(date_str)]
    return len(results), results


def query_search_host(hostname: str) -> tuple[int, list[str]]:
    logs = _store.get_logs()
    results = [_format_entry(e) for e in logs if e["hostname"].lower() == hostname.lower()]
    return len(results), results


def query_search_daemon(daemon: str) -> tuple[int, list[str]]:
    logs = _store.get_logs()
    results = [_format_entry(e) for e in logs
               if e["daemon"].lower().startswith(daemon.lower())]
    return len(results), results


def query_search_severity(level: str) -> tuple[int, list[str]]:
    logs = _store.get_logs()
    results = [_format_entry(e) for e in logs if e["severity"].upper() == level.upper()]
    return len(results), results


def query_search_keyword(keyword: str) -> tuple[int, list[str]]:
    logs = _store.get_logs()
    kw_lower = keyword.lower()
    results = [_format_entry(e) for e in logs if kw_lower in e["message"].lower()]
    return len(results), results


def query_count_keyword(keyword: str) -> int:
    logs = _store.get_logs()
    kw_lower = keyword.lower()
    return sum(1 for e in logs if kw_lower in e["message"].lower())


# ─────────────────────────────────────────────────────────────────────────────
# MODULE 4 — NETWORK MODULE (Worker Thread Logic)
# Receives raw bytes, decodes the pipe-delimited protocol, dispatches commands.
# ─────────────────────────────────────────────────────────────────────────────

def _recv_all(sock: socket.socket, expected_size: int) -> bytes:
    """Reliably receive exactly `expected_size` bytes from the socket.
    Returns partial data if the connection is closed before all bytes arrive."""
    data = b""
    while len(data) < expected_size:
        try:
            chunk = sock.recv(min(BUFFER_SIZE, expected_size - len(data)))
        except (ConnectionResetError, ConnectionAbortedError, OSError):
            break  # Remote end closed forcibly — return whatever arrived
        if not chunk:
            break
        data += chunk
    return data


def _send(sock: socket.socket, message: str):
    """UTF-8 encode and send a message, prefixed with a 4-byte length header."""
    encoded = message.encode("utf-8")
    length  = len(encoded).to_bytes(4, "big")
    sock.sendall(length + encoded)


def _recv_message(sock: socket.socket) -> str:
    """Receive a length-prefixed UTF-8 message."""
    raw_len = _recv_all(sock, 4)
    if len(raw_len) < 4:
        return ""
    msg_len = int.from_bytes(raw_len, "big")
    return _recv_all(sock, msg_len).decode("utf-8", errors="replace")


def handle_client(client_sock: socket.socket, addr: tuple):
    thread_name = threading.current_thread().name
    print(f"  [{thread_name}] Connection from {addr[0]}:{addr[1]}")

    # Detect silently-dead clients (no FIN/RST) so recv() doesn't block forever
    client_sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)

    try:
        raw = _recv_message(client_sock)
        if not raw:
            _send(client_sock, "ERROR|Empty request received.")
            return

        # ── Protocol Dispatch ──────────────────────────────────────────────
        parts = raw.split("|", 2)
        category = parts[0].upper() if parts else ""

        # ── UPLOAD (INGEST) ────────────────────────────────────────────────
        # REPLACEMENT — parses and indexes in batches as data streams in
        # ── UPLOAD (INGEST) ──────────────────────────────────────────────────────
        # ── UPLOAD (INGEST) ────────────────────────────────────────────────
        if category == "UPLOAD":
            if len(parts) < 3:
                _send(client_sock, "ERROR|Malformed UPLOAD request.")
                return

            try:
                declared_size = int(parts[1])
            except ValueError:
                _send(client_sock, "ERROR|Invalid file size in UPLOAD header.")
                return

            BATCH_SIZE = 10000
            total_count = 0
            skipped = 0
            batch = []
            leftover = parts[2]  # _recv_message already consumed the frame;
            bytes_received = len(leftover.encode("utf-8"))  # this may be partial
            aborted = bytes_received < declared_size

            if aborted:
                print(f"  [{thread_name}] Client disconnected mid-transfer "
                      f"({bytes_received}/{declared_size} bytes received). "
                      f"Retaining partial ingest…")

            # The streaming while loop below is a safety net for any bytes that
            # arrived after _recv_message (shouldn't happen with current protocol,
            # but kept for robustness).
            try:
                while bytes_received < declared_size:
                    chunk = client_sock.recv(BUFFER_SIZE)
                    if not chunk:
                        break
                    bytes_received += len(chunk)
                    leftover += chunk.decode("utf-8", errors="replace")

                    while "\n" in leftover:
                        line, leftover = leftover.split("\n", 1)
                        entry = parse_line(line)
                        if entry:
                            batch.append(entry)
                        else:
                            skipped += 1

                        if len(batch) >= BATCH_SIZE:
                            total_count += _store.insert_logs(batch)
                            batch.clear()

            except (ConnectionResetError, ConnectionAbortedError, OSError) as e:
                print(f"  [{thread_name}] Connection lost during streaming: {e}. "
                      f"Retaining partial ingest…")
                aborted = True

            # Always process and commit whatever arrived — complete or partial
            for line in leftover.splitlines():
                entry = parse_line(line)
                if entry:
                    batch.append(entry)
                else:
                    skipped += 1

                if len(batch) >= BATCH_SIZE:
                    total_count += _store.insert_logs(batch)
                    batch.clear()

            if batch:
                total_count += _store.insert_logs(batch)

            status = "partial" if aborted else "complete"
            print(f"  [{thread_name}] INGEST ({status}): {total_count} entries indexed, "
                  f"{skipped} lines skipped.")

            if not aborted:
                _send(client_sock,
                      f"SUCCESS|Successfully parsed and indexed {total_count} entries. "
                      f"({skipped} lines were unparseable and skipped.)")
            # If aborted, client is already gone — attempting _send would throw

        # ── QUERY ──────────────────────────────────────────────────────────
        elif category == "QUERY":
            if len(parts) < 3:
                _send(client_sock, "ERROR|Malformed QUERY request.")
                return

            sub_cmd = parts[1].upper()
            payload = parts[2]

            if sub_cmd == "SEARCH_DATE":
                n, results = query_search_date(payload)
                body = "\n".join(f"{i+1}. {r}" for i, r in enumerate(results))
                _send(client_sock, f"RESULTS|{n}|{body}")

            elif sub_cmd == "SEARCH_HOST":
                n, results = query_search_host(payload)
                body = "\n".join(f"{i+1}. {r}" for i, r in enumerate(results))
                _send(client_sock, f"RESULTS|{n}|{body}")

            elif sub_cmd == "SEARCH_DAEMON":
                n, results = query_search_daemon(payload)
                body = "\n".join(f"{i+1}. {r}" for i, r in enumerate(results))
                _send(client_sock, f"RESULTS|{n}|{body}")

            elif sub_cmd == "SEARCH_SEVERITY":
                n, results = query_search_severity(payload)
                body = "\n".join(f"{i+1}. {r}" for i, r in enumerate(results))
                _send(client_sock, f"RESULTS|{n}|{body}")

            elif sub_cmd == "SEARCH_KEYWORD":
                n, results = query_search_keyword(payload)
                body = "\n".join(f"{i+1}. {r}" for i, r in enumerate(results))
                _send(client_sock, f"RESULTS|{n}|{body}")

            elif sub_cmd == "COUNT_KEYWORD":
                count = query_count_keyword(payload)
                _send(client_sock, f"COUNT|{count}")

            else:
                _send(client_sock, f"ERROR|Unknown sub-command '{sub_cmd}'.")

        # ── ADMIN ──────────────────────────────────────────────────────────
        elif category == "ADMIN":
            sub_cmd = parts[1].upper() if len(parts) > 1 else ""

            if sub_cmd == "PURGE":
                erased = _store.clear_logs()
                print(f"  [{thread_name}] PURGE: {erased} entries erased.")
                _send(client_sock,
                      f"SUCCESS|{erased} indexed log entries have been erased.")

            elif sub_cmd == "STATUS":
                s = _store.stats()
                msg = (f"STATUS|Total ingested: {s['ingested']} | "
                       f"Current in memory: {s['current']} | "
                       f"Total purged: {s['purged']}")
                _send(client_sock, msg)

            elif sub_cmd == "DUMP":
                # payload is the number of entries to show (default 5)
                try:
                    limit = int(parts[2]) if len(parts) > 2 and parts[2].strip() else 5
                except ValueError:
                    limit = 5

                logs = _store.get_logs()
                sample = logs[:limit]
                total = len(logs)

                lines = [f"--- Showing {len(sample)} of {total} entries in RAM ---"]
                for i, entry in enumerate(sample, 1):
                    lines.append(
                        f"\nEntry #{i}:"
                        f"\n  timestamp : {entry['timestamp']}"
                        f"\n  hostname  : {entry['hostname']}"
                        f"\n  daemon    : {entry['daemon']}"
                        f"\n  severity  : {entry['severity']}"
                        f"\n  message   : {entry['message']}"
                    )
                _send(client_sock, "DUMP|" + "\n".join(lines))

            else:
                _send(client_sock, f"ERROR|Unknown ADMIN sub-command '{sub_cmd}'.")

        else:
            _send(client_sock, f"ERROR|Unknown request category '{category}'.")

    except Exception as exc:
        print(f"  [{thread_name}] ERROR handling {addr}: {exc}")
        try:
            _send(client_sock, f"ERROR|Server exception: {exc}")
        except Exception:
            pass
    finally:
        client_sock.close()
        print(f"  [{thread_name}] Connection closed for {addr[0]}:{addr[1]}")


# ─────────────────────────────────────────────────────────────────────────────
# MASTER LISTENER — Main Thread
# Exclusively binds, listens, and dispatches; never processes data itself.
# ─────────────────────────────────────────────────────────────────────────────

def start_server(host: str = DEFAULT_HOST, port: int = DEFAULT_PORT):
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        server_sock.bind((host, port))
    except OSError as e:
        print(f"[ERROR] Cannot bind to {host}:{port} — {e}")
        sys.exit(1)

    server_sock.listen(10)

    print("=" * 62)
    print("  Mini-Splunk Syslog Analytics Server  —  ACTIVE")
    print("=" * 62)
    print(f"  Listening on  : {host}:{port}")
    print(f"  Concurrency   : Thread-per-Connection (threading.Thread)")
    print(f"  Shared state  : In-memory list protected by RLock")
    print("  Press Ctrl+C to shut down.")
    print("-" * 62)

    # Graceful shutdown on SIGINT/SIGTERM
    def _shutdown(sig, frame):
        print("\n[SERVER] Shutdown signal received. Closing socket…")
        server_sock.close()
        sys.exit(0)

    signal.signal(signal.SIGINT,  _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    thread_counter = 0
    while True:
        try:
            client_sock, addr = server_sock.accept()
        except OSError:
            break  # Socket was closed by signal handler

        thread_counter += 1
        worker = threading.Thread(
            target=handle_client,
            args=(client_sock, addr),
            name=f"Worker-{thread_counter}",
            daemon=True,
        )
        worker.start()
        print(f"  [Master] Dispatched {worker.name} for {addr[0]}:{addr[1]}  "
              f"| Active threads: {threading.active_count() - 1}")


# ─────────────────────────────────────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    host = DEFAULT_HOST
    port = DEFAULT_PORT

    if len(sys.argv) >= 2:
        port = int(sys.argv[1])
    if len(sys.argv) >= 3:
        host = sys.argv[2]

    start_server(host, port)
