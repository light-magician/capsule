//! Network information parsing from socket syscalls

use crate::model::{NetworkInfo, ResourceType};

/// Parse network information from socket syscalls
pub fn parse_network_info(syscall_name: &str, line: &str, resource_type: &Option<ResourceType>) -> Option<NetworkInfo> {
    // Only parse network info for socket resources
    if !matches!(resource_type, Some(ResourceType::Socket)) {
        return None;
    }
    
    match syscall_name {
        "socket" => parse_socket_syscall(line),
        "bind" | "connect" => parse_bind_connect_syscall(line),
        "accept" | "accept4" => parse_accept_syscall(line),
        "send" | "sendto" | "recv" | "recvfrom" => parse_send_recv_syscall(line),
        _ => None,
    }
}

/// Parse socket() syscall to extract protocol family and type
fn parse_socket_syscall(line: &str) -> Option<NetworkInfo> {
    if let Some(args_start) = line.find("socket(") {
        if let Some(args_end) = line.find(") = ") {
            let args_section = &line[args_start + 7..args_end];
            let parts: Vec<&str> = args_section.split(',').map(|s| s.trim()).collect();
            
            if parts.len() >= 2 {
                let family = parse_address_family(parts[0]);
                let protocol = parse_socket_type_and_protocol(&parts[1..]);
                
                return Some(NetworkInfo {
                    family,
                    protocol,
                    local_addr: None,
                    local_port: None,
                    remote_addr: None,
                    remote_port: None,
                });
            }
        }
    }
    None
}

/// Parse bind() or connect() syscall to extract address information
fn parse_bind_connect_syscall(line: &str) -> Option<NetworkInfo> {
    if let Some(sock_start) = line.find('{') {
        if let Some(sock_end) = line.find('}') {
            let socket_info = &line[sock_start + 1..sock_end];
            
            let family = extract_sa_family(socket_info);
            let (addr, port) = extract_address_port(socket_info, &family);
            
            return Some(NetworkInfo {
                family: family.clone(),
                protocol: None,
                local_addr: if line.contains("bind(") { addr.clone() } else { None },
                local_port: if line.contains("bind(") { port } else { None },
                remote_addr: if line.contains("connect(") { addr } else { None },
                remote_port: if line.contains("connect(") { port } else { None },
            });
        }
    }
    None
}

/// Parse accept() syscall to extract peer address information
fn parse_accept_syscall(line: &str) -> Option<NetworkInfo> {
    if let Some(sock_start) = line.find('{') {
        if let Some(sock_end) = line.find('}') {
            let socket_info = &line[sock_start + 1..sock_end];
            
            let family = extract_sa_family(socket_info);
            let (addr, port) = extract_address_port(socket_info, &family);
            
            return Some(NetworkInfo {
                family,
                protocol: None,
                local_addr: None,
                local_port: None,
                remote_addr: addr,
                remote_port: port,
            });
        }
    }
    None
}

/// Parse send/recv syscalls (limited info available)
fn parse_send_recv_syscall(_line: &str) -> Option<NetworkInfo> {
    Some(NetworkInfo {
        family: "UNKNOWN".to_string(),
        protocol: None,
        local_addr: None,
        local_port: None,
        remote_addr: None,
        remote_port: None,
    })
}

/// Extract address family from strace output
fn parse_address_family(family_str: &str) -> String {
    match family_str.trim() {
        "AF_INET" | "PF_INET" => "AF_INET".to_string(),
        "AF_INET6" | "PF_INET6" => "AF_INET6".to_string(),
        "AF_UNIX" | "AF_LOCAL" | "PF_UNIX" | "PF_LOCAL" => "AF_UNIX".to_string(),
        "AF_NETLINK" | "PF_NETLINK" => "AF_NETLINK".to_string(),
        _ => family_str.trim().to_string(),
    }
}

/// Parse socket type and protocol into a protocol string
fn parse_socket_type_and_protocol(parts: &[&str]) -> Option<String> {
    if parts.is_empty() {
        return None;
    }
    
    let socket_type = parts[0].trim();
    let protocol = if parts.len() > 1 { parts[1].trim() } else { "" };
    
    match (socket_type, protocol) {
        ("SOCK_STREAM", "IPPROTO_TCP") | ("SOCK_STREAM", _) => Some("TCP".to_string()),
        ("SOCK_DGRAM", "IPPROTO_UDP") | ("SOCK_DGRAM", _) => Some("UDP".to_string()),
        ("SOCK_RAW", _) => Some("RAW".to_string()),
        _ => Some(socket_type.to_string()),
    }
}

/// Extract sa_family from socket address structure
fn extract_sa_family(socket_info: &str) -> String {
    for part in socket_info.split(',') {
        let part = part.trim();
        if part.starts_with("sa_family=") {
            return parse_address_family(&part[10..]);
        }
    }
    "UNKNOWN".to_string()
}

/// Extract IP address and port from socket address structure
fn extract_address_port(socket_info: &str, _family: &str) -> (Option<String>, Option<u16>) {
    let mut addr = None;
    let mut port = None;
    
    for part in socket_info.split(',') {
        let part = part.trim();
        
        // Extract port
        if part.starts_with("sin_port=htons(") {
            if let Some(port_end) = part.find(')') {
                let port_str = &part[15..port_end];
                port = port_str.parse::<u16>().ok();
            }
        }
        
        // Extract IPv4 address
        if part.starts_with("sin_addr=inet_addr(\"") {
            if let Some(addr_end) = part.find("\")") {
                addr = Some(part[20..addr_end].to_string());
            }
        }
        
        // Extract IPv6 address (simplified)
        if part.starts_with("sin6_addr=") {
            addr = Some("::1".to_string()); // Placeholder
        }
        
        // Extract Unix domain socket path
        if part.starts_with("sun_path=\"") {
            if let Some(path_end) = part[10..].find('"') {
                addr = Some(part[10..10 + path_end].to_string());
            }
        }
    }
    
    (addr, port)
}