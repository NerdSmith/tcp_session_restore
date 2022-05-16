#include <iostream>
#include <map>
#include <list>
#include <vector>
#include <utility>
#include <sstream>
#include "TcpLayer.h"
#include "IPv4Layer.h"
#include "PacketUtils.h"
#include "stdlib.h"
#include "PcapFileDevice.h"
#include "SystemUtils.h"

#define EXIT_WITH_ERROR(reason) do { \
	std::cout << std::endl << "ERROR: " << reason << std::endl << std::endl; \
	exit(1); \
	} while(0)

static enum Phase {
	SYNC, 
	CONN, 
	CLOSE 
};

struct Connection 
{
	pcpp::IPAddress srcIP;
	uint16_t srcPort;

	pcpp::IPAddress destIP;
	uint16_t destPort;

	std::string toString() {
		std::stringstream ss;
		ss << srcIP << "|" << srcPort << "|" << destIP << "|" << destPort;
		return ss.str();
	}
	// Phase phase;
};
//
//bool operator == (const Connection& conn1, const Connection& conn2) 
//{
//	return conn1.destPort == conn2.destPort;
//}

bool operator <(const Connection& conn1, const Connection& conn2)
{
	return (conn1.srcPort < conn2.srcPort) ||
		(conn1.destPort < conn2.destPort);
}

void printInfoByConns(
	std::map<Connection, std::list<pcpp::Packet>>& connPackets,
	std::list<pcpp::Packet>& lastPkgs
)
{
	std::cout << "Conns: " << connPackets.size() << std::endl;
	std::map<Connection, std::list<pcpp::Packet>>::iterator it;
	for (it = connPackets.begin(); it != connPackets.end(); it++) {
		Connection conn = it->first;
		std::list<pcpp::Packet> pkgs = it->second;
		std::cout << conn.toString() << " pkgs nb: " << pkgs.size() << std::endl;
	}
	std::cout << "Last: " << lastPkgs.size();
}

std::pair<Connection, bool> getConn(
	pcpp::IPAddress srcIP,
	uint16_t srcPort,
	pcpp::IPAddress destIP,
	uint16_t destPort,
	std::map<Connection, std::list<pcpp::Packet>>& connPackets
) {
	Connection conn = Connection{ srcIP, srcPort, destIP, destPort };
	
	if (connPackets.find(conn) != connPackets.end()) {
		return std::make_pair(conn, true);
	}
	else {
		std::cout << "double" << std::endl;
	}
	
	conn = Connection{ destIP, destPort, srcIP, srcPort };
	if (connPackets.find(conn) != connPackets.end()) {
		return std::make_pair(conn, true);
	}
	else {
		std::cout << "double" << std::endl;
	}

	return std::make_pair(conn, false);
}

bool check4SYN(pcpp::TcpLayer* tcpLayer) 
{
	return tcpLayer->getTcpHeader()->synFlag;
}

bool check4ACK(pcpp::TcpLayer* tcpLayer)
{
	return tcpLayer->getTcpHeader()->ackFlag;
}

void analyzePkg(
	pcpp::Packet& packet,
	std::map<Connection,
	std::list<pcpp::Packet>>&connPackets,
	std::list<pcpp::Packet>& lastPkgs
)	
{

	if (!packet.isPacketOfType(pcpp::TCP) && !packet.isPacketOfType(pcpp::SSL)) {
		return;
	}


	pcpp::IPv4Layer* ipv4Layer = packet.getLayerOfType<pcpp::IPv4Layer>();
	if (ipv4Layer == NULL)
	{
		EXIT_WITH_ERROR("Something went wrong, couldn't find IPv4 layer");
	}

	pcpp::TcpLayer* tcpLayer = packet.getLayerOfType<pcpp::TcpLayer>();
	if (tcpLayer == NULL)
	{
		EXIT_WITH_ERROR("Something went wrong, couldn't find TCP layer");
	}

	//if (tcpLayer->getDstPort() == 8888) {
	//	if (check4SYN(tcpLayer)) {
	//		std::cout << "syn" << std::endl;
	//	}
	//	if (check4ACK(tcpLayer)) {
	//		std::cout << "ack" << std::endl;
	//	}
	//	std::cout << "asd1" << std::endl;
	//}

	pcpp::IPAddress srcIP = ipv4Layer->getSrcIPAddress();
	uint16_t srcPort = tcpLayer->getSrcPort();
	pcpp::IPAddress destIP = ipv4Layer->getDstIPAddress();
	uint16_t destPort = tcpLayer->getDstPort();

	Connection conn = Connection{ srcIP, srcPort, destIP, destPort };
	if (check4SYN(tcpLayer) && !check4ACK(tcpLayer)) {
		std::list<pcpp::Packet> pkgs = {packet};
		connPackets.emplace(conn, pkgs);
	}
	else {
		lastPkgs.push_back(packet);
	}


	//Connection conn = getConn();
}

void parseFromFile(
	std::string &fileName, 
	std::map<Connection, 
	std::list<pcpp::Packet>> &connPackets, 
	std::list<pcpp::Packet> &lastPkgs
)
{
	pcpp::IFileReaderDevice* reader = pcpp::IFileReaderDevice::getReader(fileName);

	if (!reader->open()) {
		EXIT_WITH_ERROR("Could not open the device");
	}

	pcpp::RawPacket rawPacket;

	while (reader->getNextPacket(rawPacket)) {
		pcpp::Packet parsedPacket(&rawPacket);

		analyzePkg(parsedPacket, connPackets, lastPkgs);
	}

}

int main() {
	std::map<Connection, std::list<pcpp::Packet>> connPackets;
	std::list<pcpp::Packet> lastPkgs;

	std::string fileName = "tcp_tls_.pcap";

	parseFromFile(fileName, connPackets, lastPkgs);
	printInfoByConns(connPackets, lastPkgs);

	return 0;
}