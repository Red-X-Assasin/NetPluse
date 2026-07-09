from scapy.layers.dns import DNS
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.packet import Raw

from app.sniffer import PacketCaptureManager, summarize_packet


def test_summarize_packet_detects_http_details():
    packet = IP(src="192.168.1.10", dst="8.8.8.8") / TCP(sport=54321, dport=80) / Raw(load="GET / HTTP/1.1\r\nHost: example.com")

    summary = summarize_packet(packet)

    assert summary["protocol"] == "HTTP"
    assert summary["source_ip"] == "192.168.1.10"
    assert summary["destination_ip"] == "8.8.8.8"
    assert summary["source_port"] == 54321
    assert summary["destination_port"] == 80
    assert summary["payload_preview"].startswith("GET")


def test_manager_filters_packets_by_protocol_and_ip():
    manager = PacketCaptureManager()
    udp_packet = IP(src="10.0.0.2", dst="10.0.0.3") / UDP(sport=53, dport=53) / DNS(qd=1)
    tcp_packet = IP(src="10.0.0.2", dst="10.0.0.4") / TCP(sport=4000, dport=80) / Raw(load="hello")

    manager.add_packet(udp_packet)
    manager.add_packet(tcp_packet)

    filtered = manager.filter_packets(protocol="UDP", ip_address="10.0.0.3")

    assert len(filtered) == 1
    assert filtered[0]["protocol"] == "DNS"
