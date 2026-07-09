from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pathlib import Path
from typing import Any, Dict, Optional

from app.sniffer import PacketCaptureManager, serialize_record

APP_ROOT = Path(__file__).resolve().parent
TEMPLATE_DIR = APP_ROOT / "templates"
STATIC_DIR = APP_ROOT / "static"

app = FastAPI(title="NetPulse", version="0.1.0")
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

manager = PacketCaptureManager()


@app.get("/", include_in_schema=False)
def index() -> FileResponse:
    return FileResponse(TEMPLATE_DIR / "index.html")


@app.get("/api/interfaces")
def list_interfaces() -> Dict[str, Any]:
    return {"interfaces": manager.list_interfaces()}


@app.post("/api/start")
def start_capture(payload: Dict[str, Any]) -> Dict[str, Any]:
    interface = payload.get("interface")
    filter_expression = payload.get("filter")
    return manager.start(interface=interface, filter_expression=filter_expression)


@app.post("/api/stop")
def stop_capture() -> Dict[str, Any]:
    return manager.stop()


@app.get("/api/packets")
def get_packets(
    protocol: Optional[str] = None,
    ip_address: Optional[str] = None,
    port: Optional[int] = None,
    search: Optional[str] = None,
    limit: int = 200,
) -> Dict[str, Any]:
    packets = manager.filter_packets(protocol=protocol, ip_address=ip_address, port=port, search=search, limit=limit)
    return {"packets": [serialize_record(packet) for packet in packets]}


@app.get("/api/packets/{packet_id}")
def get_packet(packet_id: str) -> Dict[str, Any]:
    for packet in manager._packets:
        if packet["id"] == packet_id:
            return serialize_record(packet)
    raise HTTPException(status_code=404, detail="Packet not found")


@app.get("/api/stats")
def get_stats() -> Dict[str, Any]:
    return manager.get_stats()


@app.get("/api/export/json")
def export_json() -> Response:
    body = manager.export_json().encode("utf-8")
    return Response(body, media_type="application/json", headers={"Content-Disposition": 'attachment; filename="netpulse-capture.json"'})


@app.get("/api/export/csv")
def export_csv() -> Response:
    body = manager.export_csv().encode("utf-8")
    return Response(body, media_type="text/csv", headers={"Content-Disposition": 'attachment; filename="netpulse-capture.csv"'})


@app.get("/api/export/pcap")
def export_pcap() -> StreamingResponse:
    body = manager.export_pcap()
    return StreamingResponse(iter([body]), media_type="application/octet-stream", headers={"Content-Disposition": 'attachment; filename="netpulse-capture.pcap"'})


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
