use std::{
    collections::HashSet,
    net::IpAddr,
    time::{Duration, Instant},
};

use dns_lookup::lookup_addr;
use pnet::{
    datalink::{self, Channel::Ethernet},
    packet::{
        MutablePacket, Packet,
        arp::{ArpHardwareTypes, ArpOperations, ArpPacket, MutableArpPacket},
        ethernet::{EtherTypes, MutableEthernetPacket},
    },
};

fn main() {
    let interfaces = datalink::interfaces();
    let interface = interfaces
        .into_iter()
        .find(|iface| iface.is_up() && !iface.is_loopback() && iface.ips.iter().any(|ip| ip.is_ipv4()))
        .expect("No suitable network interface found");

    let source_ip = match interface.ips.iter().find(|ip| ip.is_ipv4()).unwrap().ip() {
        IpAddr::V4(ip) => ip,
        _ => panic!("No IPv4 found"),
    };

    let net = match interface.ips.iter().find(|ip| ip.is_ipv4()).unwrap() {
        pnet::ipnetwork::IpNetwork::V4(net) => net,
        _ => panic!("Not an IPv4 network"),
    };

    let source_mac = interface.mac.unwrap();
    println!("Using interface: {}", interface.name);
    println!("Source IP: {}, MAC: {}", source_ip, source_mac);
    println!("Scanning subnet: {}", net);

    let (mut tx, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        _ => panic!("Failed to open datalink channel"),
    };

    let mut found = HashSet::new();

    let mut ethernet_buffer = [0u8; 42];
    let mut ethernet_packet = MutableEthernetPacket::new(&mut ethernet_buffer).unwrap();
    ethernet_packet.set_source(source_mac);
    ethernet_packet.set_ethertype(EtherTypes::Arp);

    let mut arp_buffer = [0u8; 28];
    let mut arp_packet = MutableArpPacket::new(&mut arp_buffer).unwrap();
    arp_packet.set_hardware_type(ArpHardwareTypes::Ethernet);
    arp_packet.set_protocol_type(EtherTypes::Ipv4);
    arp_packet.set_hw_addr_len(6);
    arp_packet.set_proto_addr_len(4);
    arp_packet.set_operation(ArpOperations::Request);
    arp_packet.set_sender_hw_addr(source_mac);
    arp_packet.set_sender_proto_addr(source_ip);

    for target in net.iter().filter(|ip| *ip != IpAddr::V4(source_ip)) {
        arp_packet.set_target_hw_addr(datalink::MacAddr::zero());
        arp_packet.set_target_proto_addr(target);
        ethernet_packet.set_destination(datalink::MacAddr::broadcast());
        ethernet_packet.set_payload(arp_packet.packet_mut());
        tx.send_to(ethernet_packet.packet(), None).unwrap().unwrap();
    }

    let timeout = Instant::now() + Duration::from_secs(2);
    while Instant::now() < timeout {
        if let Ok(packet) = rx.next() {
            if packet.len() >= 42 {
                if let Some(arp) = ArpPacket::new(&packet[14..]) {
                    if arp.get_operation() == ArpOperations::Reply {
                        let ip = arp.get_sender_proto_addr();
                        let mac = arp.get_sender_hw_addr();

                        if found.insert(ip) {
                            let hostname = lookup_addr(&IpAddr::V4(ip)).unwrap_or_else(|_| "-".to_string());
                            println!("IP: {:<15} MAC: {} Hostname: {}", ip, mac, hostname);
                        }
                    }
                }
            }
        }
    }
}
