from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import Any, Dict, List

from scapy.all import IP, TCP, UDP, ICMP, ARP, DNS, rdpcap, sniff


@dataclass
class PacketInfo:
    index: int
    timestamp: str
    protocol: str
    src: str
    dst: str
    length: int
    flags: str
    info: str


def _protocol_name(packet: Any) -> str:
    if packet.haslayer(TCP):
        return 'TCP'
    if packet.haslayer(UDP):
        return 'UDP'
    if packet.haslayer(ICMP):
        return 'ICMP'
    if packet.haslayer(ARP):
        return 'ARP'
    if packet.haslayer(DNS):
        return 'DNS'
    return 'OTHER'


def _extract_flags(packet: Any) -> str:
    flags = []
    if packet.haslayer(TCP):
        tcp = packet[TCP]
        if tcp.flags.S:
            flags.append('S')
        if tcp.flags.A:
            flags.append('A')
        if tcp.flags.F:
            flags.append('F')
        if tcp.flags.R:
            flags.append('R')
        if tcp.flags.P:
            flags.append('P')
        if tcp.flags.U:
            flags.append('U')
        if tcp.flags.E:
            flags.append('E')
        if not flags:
            flags.append('.')
        return ''.join(flags)
    if packet.haslayer(ICMP):
        return 'ICMP'
    if packet.haslayer(DNS):
        return 'DNS'
    return '---'


def _packet_info(packet: Any, index: int) -> PacketInfo:
    protocol = _protocol_name(packet)
    src = packet[IP].src if packet.haslayer(IP) else (
        packet[ARP].psrc if packet.haslayer(ARP) else 'unknown'
    )
    dst = packet[IP].dst if packet.haslayer(IP) else (
        packet[ARP].pdst if packet.haslayer(ARP) else 'unknown'
    )
    length = len(packet)
    flags = _extract_flags(packet)

    if packet.haslayer(DNS):
        dns = packet[DNS]
        qname = dns.qd.qname.decode('utf-8', 'ignore') if dns.qd is not None else 'N/A'
        info = f'DNS {qname}'
    elif packet.haslayer(TCP):
        tcp = packet[TCP]
        info = f'{tcp.sport}->{tcp.dport}'
    elif packet.haslayer(UDP):
        udp = packet[UDP]
        info = f'{udp.sport}->{udp.dport}'
    else:
        info = packet.summary()

    return PacketInfo(
        index=index,
        timestamp=str(packet.time),
        protocol=protocol,
        src=src,
        dst=dst,
        length=length,
        flags=flags,
        info=info,
    )


def read_pcap_file(path: str) -> List[Dict[str, Any]]:
    packets = rdpcap(path)
    return [_packet_info(packet, idx).to_dict() for idx, packet in enumerate(packets)]


def capture_live(interface: str | None = None, timeout: int = 10, packet_count: int = 1000) -> List[Dict[str, Any]]:
    packets = sniff(iface=interface, timeout=timeout, count=packet_count, store=True)
    return [_packet_info(packet, idx).to_dict() for idx, packet in enumerate(packets)]


# For dataclass serialization
PacketInfo.to_dict = lambda self: asdict(self)  # type: ignore[attr-defined]
