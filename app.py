import csv
import io
import json
import os
import queue
import sys
import threading
import time
import uuid

from flask import Flask, Response, jsonify, render_template, request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

app = Flask(__name__)
app.config["TEMPLATES_AUTO_RELOAD"] = True

_active_scans: dict = {}


def _sse(data: dict) -> str:
    return f"data: {json.dumps(data, ensure_ascii=False)}\n\n"


def _stream(scan_id: str, timeout: int = 120):
    scan = _active_scans.get(scan_id)
    if not scan:
        yield _sse({"type": "error", "message": "Escaneo no encontrado"})
        return

    q = scan["queue"]
    while True:
        try:
            msg = q.get(timeout=timeout)
            yield _sse(msg)
            if msg["type"] in ("complete", "error"):
                break
        except queue.Empty:
            yield _sse({"type": "heartbeat"})

    _active_scans.pop(scan_id, None)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/detect-cidr")
def api_detect_cidr():
    from scripts.utils import detect_local_cidr
    cidr = detect_local_cidr()
    return jsonify({"cidr": cidr, "success": cidr is not None})


@app.route("/api/validate-cidr")
def api_validate_cidr():
    cidr = request.args.get("cidr", "")
    from scripts.utils import validate_cidr
    return jsonify({"valid": validate_cidr(cidr), "cidr": cidr})


@app.route("/api/scan/arp", methods=["POST"])
def api_scan_arp():
    data = request.json or {}
    cidr = data.get("cidr", "").strip()

    if not cidr:
        return jsonify({"error": "El campo CIDR es requerido"}), 400

    from scripts.utils import validate_cidr
    if not validate_cidr(cidr):
        return jsonify({"error": f"CIDR inválido: '{cidr}'"}), 400

    scan_id = str(uuid.uuid4())
    q: queue.Queue = queue.Queue()
    _active_scans[scan_id] = {"queue": q, "cancelled": False}

    def _do_arp():
        try:
            from scripts.utils import run_arp_scan
            q.put({"type": "started", "cidr": cidr, "timestamp": time.time()})
            start = time.time()

            def _on_host(host):
                if _active_scans.get(scan_id, {}).get("cancelled"):
                    raise InterruptedError("Escaneo cancelado por el usuario")
                q.put({"type": "host_found", "host": host})

            hosts = run_arp_scan(cidr, callback=_on_host)
            elapsed = round(time.time() - start, 2)
            q.put({"type": "complete", "total": len(hosts), "elapsed": elapsed})

        except InterruptedError:
            q.put({"type": "cancelled"})
        except Exception as exc:
            q.put({"type": "error", "message": str(exc)})

    threading.Thread(target=_do_arp, daemon=True).start()
    return jsonify({"scan_id": scan_id})


@app.route("/api/scan/stream/<scan_id>")
def api_scan_stream(scan_id: str):
    return Response(
        _stream(scan_id, timeout=120),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.route("/api/scan/cancel/<scan_id>", methods=["POST"])
def api_scan_cancel(scan_id: str):
    scan = _active_scans.get(scan_id)
    if scan:
        scan["cancelled"] = True
    return jsonify({"success": True})


@app.route("/api/nmap", methods=["POST"])
def api_nmap():
    data = request.json or {}
    ip = data.get("ip", "").strip()
    port_range = data.get("ports", "1-1024").strip()

    if not ip:
        return jsonify({"error": "La dirección IP es requerida"}), 400

    scan_id = str(uuid.uuid4())
    q: queue.Queue = queue.Queue()
    _active_scans[scan_id] = {"queue": q, "cancelled": False}

    def _do_nmap():
        try:
            from scripts.utils import nmap_scan, get_service_name, assess_risk
            q.put({"type": "started", "ip": ip, "ports": port_range})
            start = time.time()
            raw_ports = nmap_scan(ip, port_range)
            elapsed = round(time.time() - start, 2)

            port_details = [
                {"port": p, "service": get_service_name(p)}
                for p in sorted(raw_ports)
            ]
            risk = assess_risk(raw_ports)
            q.put({
                "type": "complete",
                "ip": ip,
                "ports": port_details,
                "risk": risk,
                "elapsed": elapsed,
            })
        except Exception as exc:
            q.put({"type": "error", "message": str(exc)})

    threading.Thread(target=_do_nmap, daemon=True).start()
    return jsonify({"scan_id": scan_id})


@app.route("/api/nmap/stream/<scan_id>")
def api_nmap_stream(scan_id: str):
    return Response(
        _stream(scan_id, timeout=300),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.route("/api/export/csv", methods=["POST"])
def api_export_csv():
    data = request.json or {}
    hosts = data.get("hosts", [])

    if not hosts:
        return jsonify({"error": "Sin datos para exportar"}), 400

    output = io.StringIO()
    fieldnames = ["ip", "mac", "hostname", "vendor", "open_ports", "risk_level"]
    writer = csv.DictWriter(output, fieldnames=fieldnames, extrasaction="ignore")
    writer.writeheader()
    for h in hosts:
        row = {
            "ip": h.get("ip", ""),
            "mac": h.get("mac", ""),
            "hostname": h.get("hostname", "N/A"),
            "vendor": h.get("vendor", "Desconocido"),
            "open_ports": ", ".join(str(p) for p in h.get("open_ports", [])),
            "risk_level": h.get("risk", {}).get("level", "SAFE"),
        }
        writer.writerow(row)

    output.seek(0)
    ts = time.strftime("%Y%m%d_%H%M%S")
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={
            "Content-Disposition": f'attachment; filename="netwatcher_{ts}.csv"'
        },
    )


@app.route("/api/export/json", methods=["POST"])
def api_export_json():
    data = request.json or {}
    hosts = data.get("hosts", [])
    if not hosts:
        return jsonify({"error": "Sin datos para exportar"}), 400

    ts = time.strftime("%Y%m%d_%H%M%S")
    return Response(
        json.dumps(hosts, indent=2, ensure_ascii=False),
        mimetype="application/json",
        headers={
            "Content-Disposition": f'attachment; filename="netwatcher_{ts}.json"'
        },
    )


if __name__ == "__main__":
    print("=" * 60)
    print("  [*] NetWatcher Web Dashboard v2.0")
    print("  [>] http://localhost:5000")
    print("=" * 60)
    app.run(debug=True, threaded=True, host="0.0.0.0", port=5000)
