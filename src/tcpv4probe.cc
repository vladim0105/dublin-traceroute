/* SPDX-License-Identifier: BSD-2-Clause */

/**
 * \file   udpv4probe.cc
 * \Author Andrea Barberio <insomniac@slackware.it>
 * \date   2017
 * \brief  Definition of the UDPv4Probe class
 *
 * This file contains the definition of the UDPv4Probe class, which represents
 * an UDP probe that will be sent over IPv4.
 *
 * \sa tcpv4probe.h
 */

#include <memory>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <iostream>
#include <iomanip>

#include "dublintraceroute/tcpv4probe.h"
#include "dublintraceroute/common.h"
#include "dublintraceroute/exceptions.h"
#include "dublintraceroute/icmp_messages.h"


/** \brief method that sends the probe to the specified destination
 */
Tins::IP* TCPv4Probe::forge() {
	Tins::IP *packet = new Tins::IP(remote_addr_, Tins::NetworkInterface::default_interface().addresses().ip_addr) /
		Tins::TCP(remote_port_, local_port_);
	Tins::TCP *tcp = &packet->rfind_pdu<Tins::TCP>();
	tcp->set_flag(Tins::TCP::SYN, 1);
    tcp->seq(ttl_);
    //packet->ttl(ttl_*2);
	// serialize the packet so we can extract source IP and checksum
    //packet->serialize();

	//packet->id(local_port_);
	return packet;
}

Tins::IP &TCPv4Probe::send() {
	Tins::NetworkInterface iface = Tins::NetworkInterface::default_interface();
	Tins::PacketSender sender;
	if (packet == nullptr) {
		packet = forge();
	}
	sender.send(*packet, iface.name());
	return *packet;
}

TCPv4Probe::~TCPv4Probe() {
	if (packet != nullptr)
		delete packet;
}

