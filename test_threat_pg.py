from datetime import datetime
from database import insert_packet, insert_threat

print("Inserting packet...")

packet = {
    "timestamp": datetime.utcnow().isoformat(),
    "src_ip": "192.168.1.105",
    "dst_ip": "8.8.8.8",
    "src_port": 54321,
    "dst_port": 53,
    "protocol": "UDP",
    "packet_size": 64,
    "ttl": 64,
    "tcp_flags": None,

    # REQUIRED FIELDS
    "http_method": None,
    "http_host": None,
    "http_path": None,
    "icmp_type": None,

    "raw_summary": "Test Packet"
}

packet_id = insert_packet(packet, 0.35, True)

print("Packet ID:", packet_id)
print("Inserting threat...")

threat = {
    "timestamp": datetime.utcnow().isoformat(),
    "threat_type": "Port Scan",
    "severity": "LOW",
    "src_ip": "192.168.1.105",
    "dst_ip": "8.8.8.8",
    "src_port": 54321,
    "dst_port": 53,
    "protocol": "UDP",
    "threat_score": 0.35,
    "description": "Manual test threat",
    "packet_id": packet_id,
    "resolved": 0
}

insert_threat(threat)

print("✅ Test threat inserted into PostgreSQL")