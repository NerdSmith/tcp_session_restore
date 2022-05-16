#include <iostream>
#include <map>
#include <list>
#include <vector>
#include "TcpLayer.h"
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
	std::string srcIP;
	std::string srcPort;

	std::string destIP;
	std::string destPort;

	Phase phase;
};

void analyzePkg(pcpp::Packet& packet, std::map<Connection, std::list<pcpp::Packet>>& connPackets) 
{

	if (!packet.isPacketOfType(pcpp::TCP) || !packet.isPacketOfType(pcpp::SSL)) {
		return;
	}


	std::cout << "passed" << std::endl;
}

void parseFromFile(std::string &fileName, std::map<Connection, std::list<pcpp::Packet>> &connPackets)
{
	pcpp::IFileReaderDevice* reader = pcpp::IFileReaderDevice::getReader(fileName);

	if (!reader->open()) {
		EXIT_WITH_ERROR("Could not open the device");
	}

	pcpp::RawPacket rawPacket;

	while (reader->getNextPacket(rawPacket)) {
		pcpp::Packet parsedPacket(&rawPacket);

		analyzePkg(parsedPacket, connPackets);
	}
}

int main() {
	std::map<Connection, std::list<pcpp::Packet>> connPackets;

	std::string fileName = "tcp_tls_.pcap";

	parseFromFile(fileName, connPackets);


	return 0;
}