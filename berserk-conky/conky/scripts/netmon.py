#!/usr/bin/env python3

import subprocess
import datetime
import sys
from collections import defaultdict

def get_network_connections():
    """Get network connections using netstat command"""
    try:
        # Use netstat -tulp for comprehensive connection info with hostnames
        cmd = ["netstat", "-tulp"]
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        lines = result.stdout.strip().split('\n')
        # Skip headers (usually first 2 lines) and filter valid connection lines
        return [line for line in lines[2:] if line.strip() and ('tcp' in line.lower() or 'udp' in line.lower())]
    except subprocess.CalledProcessError:
        try:
            # Fallback to ss if netstat not available
            cmd = ["ss", "-tup"]
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            lines = result.stdout.strip().split('\n')[1:]  # Skip header
            return [line for line in lines if line.strip()]
        except subprocess.CalledProcessError:
            return []

def parse_connection(line):
    """Parse connection line from netstat -tulpn output"""
    try:
        parts = line.split()
        if len(parts) < 6:
            return None
            
        proto = parts[0].upper()  # tcp, udp, tcp6, udp6
        recv_q = parts[1]
        send_q = parts[2]  
        local_addr = parts[3]
        foreign_addr = parts[4]
        state_or_process = parts[5]
        
        # Determine state based on protocol and state field
        if proto.startswith('TCP'):
            # TCP has state in column 5
            state = state_or_process
            process = parts[6] if len(parts) > 6 else "unknown"
        else:
            # UDP doesn't have state, column 5 is process
            state = "UDP"
            process = state_or_process
        
        # Normalize state names
        if state == 'ESTABLISHED':
            state = "ESTAB"
        elif state == 'LISTEN':
            state = "LISTEN"  
        elif state == 'UDP':
            state = "UDP"
        else:
            state = "OTHER"
            
        # Extract process name from PID/process format
        if '/' in process:
            process = process.split('/')[-1]
        elif process == '-':
            process = "kernel"
        
        # Clean up addresses but keep hostnames
        if ':::' in local_addr:
            local_addr = local_addr.replace(':::', '*:')
        if '0.0.0.0:' in local_addr:
            local_addr = local_addr.replace('0.0.0.0:', '*:')
            
        return {
            'proto': proto,
            'state': state,
            'local': local_addr,
            'foreign': foreign_addr,
            'process': process[:12],  # Limit process name length
            'recv_q': recv_q,
            'send_q': send_q
        }
    except (IndexError, ValueError):
        return None

def prioritize_connections(connections):
    """Prioritize connections: ESTAB > LISTEN > UDP > OTHER, limit to 5 total"""
    established = [c for c in connections if c['state'] == 'ESTAB']
    listening = [c for c in connections if c['state'] == 'LISTEN'] 
    udp_conns = [c for c in connections if c['state'] == 'UDP']
    other = [c for c in connections if c['state'] == 'OTHER']
    
    result = []
    
    # Priority 1: Established TCP connections (active threats/communications)
    if established:
        result.extend(established[:3])  # Max 3 established
    
    # Priority 2: Listening services (attack surface)
    if len(result) < 5 and listening:
        needed = 5 - len(result)
        result.extend(listening[:needed])
    
    # Priority 3: UDP connections (DNS, etc.)
    if len(result) < 5 and udp_conns:
        needed = 5 - len(result)
        result.extend(udp_conns[:needed])
        
    # Priority 4: Other TCP states
    if len(result) < 5 and other:
        needed = 5 - len(result)  
        result.extend(other[:needed])
    
    return result[:5]

def get_connection_color(conn):
    """Get color code based on connection type"""
    if conn['state'] == 'ESTAB':
        return 'ff4444'  # Red for established (active connections)
    elif conn['state'] == 'LISTEN':
        return 'ffaa00'  # Orange for listening (services)
    elif conn['state'] == 'UDP':
        return '44aaff'  # Blue for UDP
    else:
        return 'aaaaaa'  # Gray for other states

def get_connection_flags(conn):
    """Get flags for connection analysis"""
    flags = []
    
    if conn['state'] == 'ESTAB':
        flags.append('ACT')  # Active connection
    elif conn['state'] == 'LISTEN':
        flags.append('LSN')  # Listening service
    
    # Check for common ports
    local_port = conn['local'].split(':')[-1]
    foreign_port = conn['foreign'].split(':')[-1] if ':' in conn['foreign'] else ''
    
    common_ports = {
        '22': 'SSH', '23': 'TEL', '25': 'SMTP', '53': 'DNS',
        '80': 'HTTP', '110': 'POP', '143': 'IMAP', '443': 'HTTPS',
        '993': 'IMAPS', '995': 'POPS', '21': 'FTP', '3389': 'RDP'
    }
    
    if local_port in common_ports:
        flags.append(common_ports[local_port])
    elif foreign_port in common_ports:
        flags.append(common_ports[foreign_port])
    
    # Check for external connections
    if conn['foreign'] != 'unknown' and not conn['foreign'].startswith('127.') and not conn['foreign'].startswith('*'):
        flags.append('EXT')
    
    return ','.join(flags) if flags else 'UNK'

def main():
    # Get connections
    raw_connections = get_network_connections()
    
    if not raw_connections:
        print("netcon: no connection data available")
        return
    
    # Parse connections
    connections = []
    for line in raw_connections:
        conn = parse_connection(line)
        if conn:
            connections.append(conn)
    
    if not connections:
        print("netcon: no valid connections found")
        return
    
    # Prioritize and limit to 5
    top_connections = prioritize_connections(connections)
    
    # Count by state for summary
    state_counts = defaultdict(int)
    for conn in connections:
        state_counts[conn['state']] += 1
    
    now = datetime.datetime.now()
    total_conns = len(connections)
    
    # Header
    print(f"┌─ < ── netmon --- TOP 5 CONNECTIONS ({total_conns} total)")
    print("│")
    print(f"└──┬─── priority : ESTAB > LISTEN > UDP > OTHER")
    print("   │")
    print(f"   ├─┬─ summary  : E:{state_counts['ESTAB']} L:{state_counts['LISTEN']} U:{state_counts['UDP']} O:{state_counts['OTHER']}")
    print("   │ │")
    
    # Connection entries
    for i, conn in enumerate(top_connections):
        is_last = i == len(top_connections) - 1
        pre = "├" if not is_last else "└"
        
        flags = get_connection_flags(conn)
        color = get_connection_color(conn)
        
        # Format addresses for display - truncate long hostnames but keep readability
        local_display = conn['local'][:20] + ".." if len(conn['local']) > 22 else conn['local']
        foreign_display = conn['foreign'][:20] + ".." if len(conn['foreign']) > 22 else conn['foreign']
        
        print(f"   │ {pre}─ {conn['proto']:<3} "
              f"{conn['state']:<5} "
              f"{local_display:<22} -> {foreign_display:<22} "
              f"{conn['process']:<12} "
              f"({flags}) ${{color {color}}}●${{color}}")
    
    print("   │")
    print(f"   └─── refreshed : {now.strftime('%H:%M:%S')}")

if __name__ == "__main__":
    main()