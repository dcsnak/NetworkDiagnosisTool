from __future__ import annotations

from collections import Counter
from typing import Any, Dict, List


def _percent(value: int, total: int) -> float:
    return round((value / total) * 100, 2) if total else 0.0


def analyze_packets(packet_list: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    if not packet_list:
        return []

    protocols = Counter(item.get('protocol', 'UNKNOWN') for item in packet_list)
    sources = Counter(item.get('src', 'unknown') for item in packet_list)
    dests = Counter(item.get('dst', 'unknown') for item in packet_list)
    dns_queries = sum(1 for item in packet_list if item.get('protocol') == 'DNS' and 'DNS' in str(item.get('info', '')))
    tcp_packets = sum(1 for item in packet_list if item.get('protocol') == 'TCP')
    udp_packets = sum(1 for item in packet_list if item.get('protocol') == 'UDP')
    icmp_packets = sum(1 for item in packet_list if item.get('protocol') == 'ICMP')
    arp_packets = sum(1 for item in packet_list if item.get('protocol') == 'ARP')

    issues: List[Dict[str, Any]] = []

    if dns_queries and dns_queries > 0:
        issues.append({
            'severity': 'medium',
            'title': 'DNS query activity detected',
            'detail': 'Packet capture contains DNS traffic. Check for resolution failures or DNS server latency.',
            'recommendation': 'Verify the configured DNS server and check for service blackouts or name resolution timeout.'
        })

    if tcp_packets and tcp_packets > 0:
        issues.append({
            'severity': 'medium',
            'title': 'TCP session traffic observed',
            'detail': f'{tcp_packets} TCP packets were seen in the trace. Review retransmissions and connection resets.',
            'recommendation': 'Inspect handshake completion, retransmission counts, and firewall rules for interrupted sessions.'
        })

    if udp_packets and udp_packets > 0:
        issues.append({
            'severity': 'low',
            'title': 'UDP traffic present',
            'detail': f'{udp_packets} UDP packets were captured. High UDP load can affect VoIP or game traffic.',
            'recommendation': 'Verify whether the traffic is expected and review QoS or jitter-sensitive applications.'
        })

    if icmp_packets and icmp_packets > 0:
        issues.append({
            'severity': 'high',
            'title': 'ICMP packets detected',
            'detail': 'ICMP traffic suggests connectivity testing or path issues, possibly due to packet loss or unreachable hosts.',
            'recommendation': 'Check ping results, TTL values, and router reachability between the client and server.'
        })

    if arp_packets and arp_packets > 0:
        issues.append({
            'severity': 'high',
            'title': 'ARP traffic spike',
            'detail': 'A large amount of ARP traffic can point to address conflicts or broadcast storms.',
            'recommendation': 'Inspect the local network for duplicate IPs, bad NIC drivers, or loops on the LAN.'
        })

    if len(packet_list) > 200:
        issues.append({
            'severity': 'medium',
            'title': 'High traffic volume',
            'detail': f'{len(packet_list)} packets were captured in a short window. This may obscure legitimate issue signatures.',
            'recommendation': 'Filter the capture to the relevant IP ranges or protocols before deep diagnosis.'
        })

    if not issues:
        issues.append({
            'severity': 'low',
            'title': 'No obvious faults detected',
            'detail': 'The captured data does not show a clear network fault based on the default ruleset.',
            'recommendation': 'Use a longer capture, inspect application-level logs, and compare against known-good traffic.'
        })

    summary = {
        'total_packets': len(packet_list),
        'protocols': dict(protocols),
        'top_sources': dict(sources.most_common(5)),
        'top_destinations': dict(dests.most_common(5)),
        'dns_queries': dns_queries,
        'tcp_packets': tcp_packets,
        'udp_packets': udp_packets,
        'icmp_packets': icmp_packets,
        'arp_packets': arp_packets,
        'fault_count': len(issues),
    }

    return [
        {'summary': summary, 'issues': issues}
    ]


def export_report(packet_list: List[Dict[str, Any]]) -> str:
    results = analyze_packets(packet_list)
    if not results:
        return 'No packet data available.'

    summary = results[0]['summary']
    issues = results[0]['issues']
    lines = [
        'Network Diagnosis Report',
        '=======================',
        f'Total packets: {summary["total_packets"]}',
        f'DNS queries: {summary["dns_queries"]}',
        f'TCP packets: {summary["tcp_packets"]}',
        f'UDP packets: {summary["udp_packets"]}',
        f'ICMP packets: {summary["icmp_packets"]}',
        f'ARP packets: {summary["arp_packets"]}',
        '',
        'Findings:',
    ]

    for idx, issue in enumerate(issues, start=1):
        lines.append(f'{idx}. [{issue["severity"].upper()}] {issue["title"]}')
        lines.append(f'   Detail: {issue["detail"]}')
        lines.append(f'   Recommendation: {issue["recommendation"]}')
        lines.append('')

    return '\n'.join(lines)
