from __future__ import annotations

import csv
import json
import re
import tempfile
import uuid
from collections import Counter
from datetime import datetime, timezone
from io import StringIO
from pathlib import Path
from typing import Any, Dict, List, Optional

from scapy.all import AsyncSniffer, get_if_list, wrpcap
from scapy.arch.windows import get_windows_if_list
from scapy.layers.dns import DNS
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import Ether
from scapy.packet import Packet, Raw


class PacketCaptureManager:
    def __init__(self, max_packets: int = 1000) -> None:
        self.max_packets = max_packets
        self._packets: List[Dict[str, Any]] = []
        self._sniffer: Optional[AsyncSniffer] = None
        self.interface: Optional[str] = None
        self.filter_expression: Optional[str] = None
        self.is_running = False

    def list_interfaces(self) -> List[Dict[str, str]]:
        try:
            windows_interfaces = get_windows_if_list()
            if windows_interfaces:
                return [self._build_interface_option(item) for item in windows_interfaces]
        except Exception:
            pass

        try:
            raw_names = get_if_list()
            return [{"value": name, "name": self._friendly_interface_name(name)} for name in raw_names]
        except Exception:
            return [{"value": "lo", "name": "Loopback"}, {"value": "eth0", "name": "Ethernet"}]

    def _build_interface_option(self, interface: Dict[str, Any]) -> Dict[str, str]:
        raw_name = str(interface.get("name") or "").strip()
        description = str(interface.get("description") or "").strip()
        return {"value": raw_name, "name": self._friendly_interface_name(raw_name, description)}

    def _friendly_interface_name(self, raw_name: Optional[str], description: Optional[str] = None) -> str:
        candidate = (raw_name or description or "").strip()
        if not candidate:
            return "Network interface"

        lowered = candidate.lower()
        if "device\\npf" in lowered or "device/npf" in lowered or "npf" in lowered:
            if description:
                return self._friendly_interface_name(description)
            return "Network interface"

        cleaned = re.sub(r"-(WFP|QoS|Native WiFi Filter Driver|Native MAC Layer LightWeight Filter|Packet Scheduler|Filter Driver).*$", "", candidate)
        cleaned = re.sub(r"\s*#\d+$", "", cleaned)
        cleaned = re.sub(r"^Local Area Connection\*\s*", "Ethernet ", cleaned)
        cleaned = re.sub(r"^Local Area Connection\s*", "Ethernet ", cleaned)
        cleaned = cleaned.replace("Wi-Fi", "Wi-Fi")

        if cleaned.startswith("Ethernet"):
            return cleaned

        if cleaned in {"", "Unknown"}:
            return description or "Network interface"

        return cleaned

    def start(self, interface: Optional[str] = None, filter_expression: Optional[str] = None) -> Dict[str, Any]:
        if self.is_running:
            return {"status": "running", "interface": self.interface}

        chosen_interface = interface or (self.interface or self.list_interfaces()[0] if self.list_interfaces() else "lo")
        self.interface = chosen_interface
        self.filter_expression = filter_expression.strip() if filter_expression else None
        self._sniffer = AsyncSniffer(
            iface=chosen_interface,
            prn=self._on_packet,
            store=False,
            filter=self.filter_expression,
        )
        self._sniffer.start()
        self.is_running = True
        return {"status": "started", "interface": self.interface, "filter": self.filter_expression or ""}

    def stop(self) -> Dict[str, Any]:
        if self._sniffer is not None:
            try:
                self._sniffer.stop()
            except Exception:
                pass
        self._sniffer = None
        self.is_running = False
        return {"status": "stopped"}

    def add_packet(self, packet: Packet) -> Dict[str, Any]:
        summary = summarize_packet(packet)
        self._packets.append(summary)
        if len(self._packets) > self.max_packets:
            self._packets.pop(0)
        return summary

    def _on_packet(self, packet: Packet) -> None:
        self.add_packet(packet)

    def filter_packets(
        self,
        protocol: Optional[str] = None,
        ip_address: Optional[str] = None,
        port: Optional[int] = None,
        search: Optional[str] = None,
        limit: int = 200,
    ) -> List[Dict[str, Any]]:
        filtered: List[Dict[str, Any]] = []
        for record in reversed(self._packets):
            if protocol and not protocol_matches(record["protocol"], protocol):
                continue
            if ip_address and ip_address not in {record["source_ip"], record["destination_ip"]}:
                continue
            if port and port not in {record["source_port"], record["destination_port"]}:
                continue
            if search:
                haystack = " ".join(
                    [
                        record["protocol"],
                        record["source_ip"] or "",
                        record["destination_ip"] or "",
                        record["payload_preview"],
                        record["raw_summary"],
                    ]
                ).lower()
                if search.lower() not in haystack:
                    continue
            filtered.append(record)
            if len(filtered) >= limit:
                break
        return list(reversed(filtered))

    def get_stats(self) -> Dict[str, Any]:
        protocol_counter = Counter(packet["protocol"] for packet in self._packets)
        top_talkers = Counter()
        for packet in self._packets:
            if packet["source_ip"]:
                top_talkers[packet["source_ip"]] += 1
            if packet["destination_ip"]:
                top_talkers[packet["destination_ip"]] += 1

        return {
            "packet_count": len(self._packets),
            "protocol_breakdown": [
                {"name": name, "count": count} for name, count in sorted(protocol_counter.items(), key=lambda item: item[1], reverse=True)
            ],
            "top_talkers": [
                {"ip": ip, "count": count} for ip, count in top_talkers.most_common(5)
            ],
        }

    def export_json(self) -> str:
        return json.dumps([serialize_record(packet) for packet in self._packets], indent=2)

    def export_csv(self) -> str:
        buffer = StringIO()
        fieldnames = ["timestamp", "source_ip", "destination_ip", "source_port", "destination_port", "protocol", "packet_size", "payload_preview"]
        writer = csv.DictWriter(buffer, fieldnames=fieldnames)
        writer.writeheader()
        for packet in self._packets:
            writer.writerow({key: packet.get(key, "") for key in fieldnames})
        return buffer.getvalue()

    def export_pcap(self) -> bytes:
        packet_objects = [packet["packet_obj"] for packet in self._packets if packet.get("packet_obj") is not None]
        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as temp_file:
            temp_path = Path(temp_file.name)
        wrpcap(str(temp_path), packet_objects)
        return temp_path.read_bytes()


def summarize_packet(packet: Packet) -> Dict[str, Any]:
    protocol = classify_protocol(packet)
    payload = extract_payload(packet)
    payload_preview = (payload[:120].replace("\r", " ").replace("\n", " ") if payload else "")
    source_ip, destination_ip = extract_ip_addresses(packet)
    source_port, destination_port = extract_ports(packet)
    packet_size = len(bytes(packet))
    return {
        "id": str(uuid.uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "source_port": source_port,
        "destination_port": destination_port,
        "protocol": protocol,
        "packet_size": packet_size,
        "payload_preview": payload_preview,
        "payload_hex": payload.encode("latin1", errors="replace").hex() if payload else "",
        "raw_summary": packet.summary(),
        "details": build_detail_fields(packet),
        "packet_obj": packet,
    }


def classify_protocol(packet: Packet) -> str:
    if packet.haslayer(DNS):
        return "DNS"

    payload = extract_payload(packet)
    if packet.haslayer(TCP) and looks_like_http(payload):
        return "HTTP"
    if packet.haslayer(TCP):
        return "TCP"
    if packet.haslayer(UDP):
        return "UDP"
    if packet.haslayer(ICMP):
        return "ICMP"
    return "Other"


def extract_payload(packet: Packet) -> str:
    if packet.haslayer(Raw):
        load = bytes(packet[Raw].load)
        return load.decode("latin1", errors="replace")
    return ""


def extract_ip_addresses(packet: Packet) -> tuple[Optional[str], Optional[str]]:
    if packet.haslayer(IP):
        ip_layer = packet[IP]
        return ip_layer.src, ip_layer.dst
    return None, None


def extract_ports(packet: Packet) -> tuple[Optional[int], Optional[int]]:
    if packet.haslayer(TCP):
        tcp_layer = packet[TCP]
        return int(tcp_layer.sport), int(tcp_layer.dport)
    if packet.haslayer(UDP):
        udp_layer = packet[UDP]
        return int(udp_layer.sport), int(udp_layer.dport)
    return None, None


def looks_like_http(payload: str) -> bool:
    normalized = payload.lstrip().lower()
    return normalized.startswith(("get ", "post ", "head ", "put ", "delete ", "http/"))


def build_detail_fields(packet: Packet) -> Dict[str, Any]:
    details: Dict[str, Any] = {"layers": []}
    if packet.haslayer(Ether):
        details["layers"].append({"name": "Ethernet", "fields": {"src": packet[Ether].src, "dst": packet[Ether].dst}})
    if packet.haslayer(IP):
        details["layers"].append(
            {
                "name": "IP",
                "fields": {
                    "src": packet[IP].src,
                    "dst": packet[IP].dst,
                    "ttl": packet[IP].ttl,
                    "proto": packet[IP].proto,
                },
            }
        )
    if packet.haslayer(TCP):
        details["layers"].append(
            {
                "name": "TCP",
                "fields": {
                    "sport": packet[TCP].sport,
                    "dport": packet[TCP].dport,
                    "flags": packet[TCP].sprintf("%TCP.flags%"),
                },
            }
        )
    if packet.haslayer(UDP):
        details["layers"].append(
            {
                "name": "UDP",
                "fields": {
                    "sport": packet[UDP].sport,
                    "dport": packet[UDP].dport,
                },
            }
        )
    if packet.haslayer(ICMP):
        details["layers"].append({"name": "ICMP", "fields": {"type": packet[ICMP].type, "code": packet[ICMP].code}})
    if packet.haslayer(DNS):
        details["layers"].append({"name": "DNS", "fields": {"qd": packet[DNS].qd, "qr": packet[DNS].qr}})
    return details


def protocol_matches(record_protocol: str, selected_protocol: str) -> bool:
    record_protocol = record_protocol.lower()
    selected_protocol = selected_protocol.lower()

    if selected_protocol in {"udp", "dns"}:
        return record_protocol in {"udp", "dns"}
    if selected_protocol in {"tcp", "http"}:
        return record_protocol in {"tcp", "http"}
    return record_protocol == selected_protocol


def serialize_record(record: Dict[str, Any]) -> Dict[str, Any]:
    payload = dict(record)
    payload.pop("packet_obj", None)
    return payload
