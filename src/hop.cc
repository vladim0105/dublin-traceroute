/* SPDX-License-Identifier: BSD-2-Clause */

/**
 * \file   hop.cc
 * \Author Andrea Barberio <insomniac@slackware.it>
 * \date   October 2015
 * \brief  Definition of the Hop class
 *
 * This file contains the definition of the Hop class, which represent every
 * single hop in a traceroute. A Hop includes the sent packet, the matching
 * received packet (if any), NAT information and last-hop information.
 *
 * This module currently offers the set-up of the logging facilities.
 *
 * \sa hop.h
 */

#include <memory>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <iostream>
#include <iomanip>

#include "dublintraceroute/hop.h"
#include "dublintraceroute/common.h"
#include "dublintraceroute/exceptions.h"
#include "dublintraceroute/icmp_messages.h"


/** \brief setter the sent packet
 */
void Hop::sent(Tins::IP &packet) {
	sent_ = std::make_shared<Tins::IP>(packet);
}

/** \brief setter for the timestamp of the sent packet
 */
void Hop::sent_timestamp(const Tins::Timestamp &timestamp) {
	sent_timestamp_ = std::make_shared<Tins::Timestamp>(timestamp);
}

/** \brief setter for the host name of the responding IP
 */
void Hop::name(std::string &name) {
	name_ = name;
}
void Hop::set_tcp(const Tins::Timestamp &sent_timestamp, const Tins::Timestamp &received_timestamp){
	has_tcp_ = true;
	tcp_sent_timestamp_ = std::make_shared<Tins::Timestamp>(sent_timestamp);
	tcp_received_timestamp_ = std::make_shared<Tins::Timestamp>(received_timestamp);
}
std::string Hop::resolve() {
	if (!received())
		return std::string();

	struct sockaddr_in sa;
	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_port = htons(0);
	if (inet_pton(AF_INET, received()->src_addr().to_string().c_str(), &sa.sin_addr) != 1)
		throw (std::runtime_error("inet_pton failed"));
	char host[NI_MAXHOST], service[NI_MAXSERV];

	std::string name;
	if (getnameinfo((struct sockaddr *)&sa, sizeof(sa), host, sizeof(host), service, sizeof(service), NI_NUMERICSERV) == 0)
		name = std::string(host);
	else
		name = received()->src_addr().to_string();
	name_ = name;

	return name;
}

/** \brief setter for the received packet and its timestamp
 */
void Hop::received(Tins::IP &packet, const Tins::Timestamp &timestamp) {
	received_ = std::make_shared<Tins::IP>(packet);
	received_timestamp_ = std::make_shared<Tins::Timestamp>(timestamp);
}

/** \brief return the NAT ID of the hop
 *
 * This method returns the NAT identifier for this hop. The NAT identifier is
 * calculated as the difference between the checksum of the inner UDP layer of
 * the received packet and the checksum of the sent UDP packet.
 */
uint16_t Hop::nat_id() {

	if (!received()) {
		throw DublinTracerouteException(
			"Cannot get NAT ID for unmatched packets"
		);
	}
	try {
        uint16_t chk1 = sent_->rfind_pdu<Tins::UDP>().checksum();
        Tins::IP inner_ip = received_->rfind_pdu<Tins::RawPDU>().to<Tins::IP>();
        uint16_t chk2 = inner_ip.rfind_pdu<Tins::UDP>().checksum();
        return chk2 - chk1;
    } catch(Tins::pdu_not_found) {
	    return 0;
	}

}


/** \brief return true if the hop suffers from the zero-ttl forwarding bug
 *
 * This method checks that the hop does not suffer of the zero-ttl forwarding
 * bug, and returns true or false accordingly. This is done by checking the TTL
 * of the IP-in-ICMP response, i.e. the IP header that was received by the
 * hop.
 */
const bool Hop::zerottl_forwarding_bug() {

	if (!received()) {
		throw DublinTracerouteException(
			"Cannot get zero-TTL forwarding information for unmatched packets"
		);
	}
	// FIXME catch pdu_not_found

	try {
        Tins::IP inner_ip = received_->rfind_pdu<Tins::RawPDU>().to<Tins::IP>();
        if (inner_ip.ttl() == 0) {
            // TODO handle the interesting case where TTL is neither 0 or 1
            return true;
        }
    } catch (Tins::pdu_not_found){
	    // Do nothing
	}
	return false;
}

/** \brief return the RTT in microseconds
 *
 * This method returns the Round-Trip Time in microseconds, if a matching packet
 * was received, 0 otherwise.
 */
unsigned int Hop::rtt() {
	if (received()) {
		unsigned long long ts1 = sent_timestamp()->seconds() * 1000000 + sent_timestamp()->microseconds();
		unsigned long long ts2 = received_timestamp()->seconds() * 1000000 + received_timestamp()->microseconds();
		return ts2 - ts1;
	} else {
		return 0;
	}
}
unsigned int Hop::rtt_tcp() {
	if (has_tcp()) {
		unsigned long long ts1 = tcp_sent_timestamp()->seconds() * 1000000 + tcp_sent_timestamp()->microseconds();
		unsigned long long ts2 = tcp_received_timestamp()->seconds() * 1000000 + tcp_received_timestamp()->microseconds();
		return ts2 - ts1;
	} else {
		return 0;
	}
}

/** \brief Method that computes the flow hash of a given packet
 *
 * This method computes the flow hash of a packet and returns it. Returns 0 if
 * no flow hash cannot be computed (e.g. it is not an IP/UDP packet).
 * This number is only useful for comparison purposes, and does not necessarily
 * match any network device's micro-flow hash implementation.
 *
 * Two packets with the same flow hash will traverse the same path, so you can
 * use this method to compare them.
 *
 * \sa Hop
 *
 * \return the packet's flow hash
 */
const uint16_t Hop::flowhash() {
	uint16_t flowhash = 0;
	Tins::IP ip;
	try {
		ip = (*sent()).rfind_pdu<Tins::IP>();
	} catch (Tins::pdu_not_found) {
		return 0;
	}
	flowhash += ip.tos() + ip.protocol();
	flowhash += (uint32_t)(ip.src_addr());
	flowhash += (uint32_t)(ip.dst_addr());
	Tins::UDP udp;
	try {
		udp = (*sent()).rfind_pdu<Tins::UDP>();
	} catch (Tins::pdu_not_found) {
		return 0;
	}
	flowhash += udp.sport() + udp.dport();
	if (flowhash == 0)
		flowhash = 0xffff;
	return flowhash;
}

/** \brief Convert the hop to JSON
 *
 * This method converts the hop data to a JSON representation. The
 * representation is lossy and cannot be used to rebuild the original packet.
 */
Json::Value Hop::to_json() {
	icmpmessages icmpm;
	Json::Value root;
	Json::Value nullvalue;

	// Serialize the sent packet
	root["is_last"] = is_last_hop();
	root["has_tcp"] = has_tcp();
	if (received())
		root["zerottl_forwarding_bug"] = zerottl_forwarding_bug();
	root["sent"]["timestamp"] = std::to_string(sent_timestamp()->seconds()) + "." + std::to_string(sent_timestamp()->microseconds());
	if(has_tcp()){
		root["sent"]["tcp_timestamp"] = std::to_string(tcp_sent_timestamp()->seconds()) + "." + std::to_string(tcp_sent_timestamp()->microseconds());
	}

	// flow hash
	root["flowhash"] = flowhash();

	// IP layer
	root["sent"]["ip"]["src"] = sent()->src_addr().to_string();
	root["sent"]["ip"]["dst"] = sent()->dst_addr().to_string();
	root["sent"]["ip"]["ttl"] = sent()->ttl();

	// UDP layer
	try {
		auto udp = sent()->rfind_pdu<Tins::UDP>();
		root["sent"]["udp"]["sport"] = udp.sport();
		root["sent"]["udp"]["dport"] = udp.dport();
	} catch (Tins::pdu_not_found) {
	}

	// If present, serialize the received packet
	if (received()) {
		root["rtt_usec"] = rtt();
		root["rtt_tcp_usec"] = rtt_tcp();
		if(has_tcp()){
			root["received"]["tcp_timestamp"] = std::to_string(tcp_received_timestamp()->seconds()) + "." + std::to_string(tcp_received_timestamp()->microseconds());
		}
		root["received"]["timestamp"] = std::to_string(received_timestamp()->seconds()) + "." + std::to_string(received_timestamp()->microseconds());

		// IP layer
		root["received"]["ip"]["src"] = received()->src_addr().to_string();
		root["received"]["ip"]["dst"] = received()->dst_addr().to_string();
		root["received"]["ip"]["ttl"] = received()->ttl();
		root["received"]["ip"]["id"] = received()->id();

		// ICMP layer
		try {
			auto icmp = received()->rfind_pdu<Tins::ICMP>();
			root["received"]["icmp"]["type"] = static_cast<int>(icmp.type());
			root["received"]["icmp"]["code"] = static_cast<int>(icmp.code());
			root["received"]["icmp"]["description"] = icmpm.get(icmp.type(), icmp.code());
			root["received"]["icmp"]["extensions"] = Json::Value(Json::arrayValue);
			root["received"]["icmp"]["mpls_labels"] = Json::Value(Json::arrayValue);
		} catch (Tins::pdu_not_found) {
		}
	} else {
		root["received"] = nullvalue;
		root["rtt_usec"] = nullvalue;
		root["rtt_tcp_usec"] = nullvalue;
	}
	// set the DNS name
	root["name"] = name();

	try {
		root["nat_id"] = nat_id();
	} catch (DublinTracerouteException) {
	}

	return root;
}


std::string Hop::summary() {
	std::stringstream stream;
	if (sent() == nullptr) {
		return std::string("<incomplete hop>");
	}
	Tins::IP ip;
	try {
		ip = sent()->rfind_pdu<Tins::IP>();
	} catch (Tins::pdu_not_found) {
		return std::string("<incomplete: No IP layer found>");
	}
	Tins::UDP udp;
	try {
		udp = sent()->rfind_pdu<Tins::UDP>();
	} catch (Tins::pdu_not_found) {
		return std::string("<incomplete: No UDP layer found>");
	}
	stream
		<< "UDP "
		<< ip.src_addr() << ":" << udp.sport()
		<< " -> "
		<< ip.dst_addr() << ":" << udp.dport()
		<< " TTL: " << static_cast<int>(ip.ttl())
		<< ", Flow hash: " << flowhash();
	return stream.str();
}

