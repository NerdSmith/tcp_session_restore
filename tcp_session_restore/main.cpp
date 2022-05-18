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

#include "comUtils.h"
#include "strUtils.h"



enum Phase 
{
	SYNC = 0, 
	CONN = 1, 
	CLOSE1 = 2,
	CLOSE2 = 3
};

struct Connection 
{
	pcpp::IPAddress srcIP;
	uint16_t srcPort;

	pcpp::IPAddress destIP;
	uint16_t destPort;

	Phase phase = Phase::SYNC;

	std::string toString(std::string sep = "|") {
		std::stringstream ss;
		ss << srcIP << sep << srcPort << sep << destIP << sep << destPort << sep;
		switch (phase) {
			case SYNC:
				ss << "SYNC";
				break;
			case CONN:
				ss << "CONN";
				break;
			case CLOSE1:
				ss << "CLOSE1";
				break;
			case CLOSE2:
				ss << "CLOSE2";
				break;
			default:
				ss << "NONE";
				break;
		}

			
		return ss.str();
	}

	std::string toFilename() {
		return this->toString("%") + ".pcap";
	}
};

void setPhase(std::map<Connection, std::list<pcpp::Packet>>& connPackets, Connection& conn, Phase phase) 
{
	auto entry = connPackets.find(conn);
	if (entry != connPackets.end())
	{
		auto const value = std::move(entry->second);
		auto key = entry->first;
		Connection newConn = Connection{ key.srcIP, key.srcPort, key.destIP, key.destPort, phase};
		connPackets.erase(entry);
		connPackets.insert({ newConn, std::move(value) });
	}
}

bool operator == (const Connection& conn1, const Connection& conn2) 
{
	Connection c1 = const_cast<Connection&>(conn1);
	Connection c2 = const_cast<Connection&>(conn2);
	return 
		c1.srcIP == c2.srcIP || 
		c1.srcPort == c2.srcPort ||
		c1.destIP == c2.destIP ||
		c1.destPort == c2.destPort;
}

bool operator <(const Connection& conn1, const Connection& conn2)
{
	Connection c1 = const_cast<Connection&>(conn1);
	Connection c2 = const_cast<Connection&>(conn2);
	return c1.srcPort < c2.srcPort || 
(c1.srcPort == c2.srcPort && c1.srcIP < c2.srcIP);
}


void printInfoByConns(
	std::map<Connection, std::list<pcpp::Packet>>& connPackets,
	std::list<pcpp::Packet>& lastPkgs,
	std::map<Connection, std::list<pcpp::Packet>>& closedTcpSessions
)
{
	std::cout << "Conns: " << connPackets.size() << std::endl;
	std::map<Connection, std::list<pcpp::Packet>>::iterator it;
	for (it = connPackets.begin(); it != connPackets.end(); it++) {
		Connection conn = it->first;
		std::list<pcpp::Packet> pkgs = it->second;
		std::cout << conn.phase << "|" << conn.toString() << " pkgs nb: " << pkgs.size() << std::endl;
	}
	std::cout << "Closed: " << std::endl;
	for (it = closedTcpSessions.begin(); it != closedTcpSessions.end(); it++) {
		Connection conn = it->first;
		std::list<pcpp::Packet> pkgs = it->second;
		std::cout << conn.phase << "|" << conn.toString() << " pkgs nb: " << pkgs.size() << std::endl;
	}
	std::cout << "Last: " << lastPkgs.size() << std::endl;
}

std::pair<Connection, bool> getConn(
	pcpp::IPAddress srcIP,
	uint16_t srcPort,
	pcpp::IPAddress destIP,
	uint16_t destPort,
	std::map<Connection, std::list<pcpp::Packet>>& connPackets
) 
{
	Connection conn = Connection{ srcIP, srcPort, destIP, destPort };
	auto connFind = connPackets.find(conn);
	if (connFind != connPackets.end()) {
		return std::make_pair(connFind->first, true);
	}

	conn = Connection{ destIP, destPort, srcIP, srcPort };
	connFind = connPackets.find(conn);
	if (connFind != connPackets.end()) {
		return std::make_pair(connFind->first, true);
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

bool check4FIN(pcpp::TcpLayer* tcpLayer)
{
	return tcpLayer->getTcpHeader()->finFlag;
}

void analyzePkg(
	pcpp::Packet& packet,
	std::map<Connection, std::list<pcpp::Packet>>& connPackets,
	std::list<pcpp::Packet>& lastPkgs,
	std::map<Connection, std::list<pcpp::Packet>>& closedTcpSessions
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

	pcpp::IPAddress srcIP = ipv4Layer->getSrcIPAddress();
	uint16_t srcPort = tcpLayer->getSrcPort();
	pcpp::IPAddress destIP = ipv4Layer->getDstIPAddress();
	uint16_t destPort = tcpLayer->getDstPort();
	pcpp::Packet lastPkg;
	pcpp::TcpLayer* lastPkgTcpLayer;
	

	Connection conn = Connection{ srcIP, srcPort, destIP, destPort };
	if (check4SYN(tcpLayer) && !check4ACK(tcpLayer)) {
		std::list<pcpp::Packet> pkgs = { packet };
		connPackets.emplace(conn, pkgs);
		setPhase(connPackets, conn, Phase::SYNC);
	}
	else {
		std::pair<Connection, bool> conn_pair = getConn(srcIP, srcPort, destIP, destPort, connPackets);
		if (conn_pair.second) {
			if (check4ACK(tcpLayer) && !(check4SYN(tcpLayer) || check4FIN(tcpLayer))) {
				lastPkg = connPackets[conn_pair.first].back();
				lastPkgTcpLayer = lastPkg.getLayerOfType<pcpp::TcpLayer>();
				connPackets[conn_pair.first].push_back(packet);
				if (check4FIN(lastPkgTcpLayer) && check4ACK(lastPkgTcpLayer) && (conn_pair.first.phase == Phase::CLOSE2)) {
						closedTcpSessions.emplace(conn_pair.first, connPackets[conn_pair.first]);
						connPackets.erase(conn_pair.first);
				}
			}
			else if (check4ACK(tcpLayer) && check4FIN(tcpLayer)) {
				if (conn_pair.first.phase == Phase::CLOSE1) {
					setPhase(connPackets, conn_pair.first, Phase::CLOSE2);
				}
				else {
					setPhase(connPackets, conn_pair.first, Phase::CLOSE1);
				};
				connPackets[conn_pair.first].push_back(packet);
			}
			else {
				setPhase(connPackets, conn_pair.first, Phase::CONN);
				connPackets[conn_pair.first].push_back(packet);
			}


		}
		else {
			lastPkgs.push_back(packet);
		}
	}
}

void parseFromFile(
	std::string &fileName, 
	std::map<Connection, std::list<pcpp::Packet>>& connPackets, 
	std::list<pcpp::Packet> &lastPkgs,
	std::map<Connection, std::list<pcpp::Packet>>& closedTcpSessions
)
{
	pcpp::IFileReaderDevice* reader = pcpp::IFileReaderDevice::getReader(fileName);

	if (!reader->open()) {
		EXIT_WITH_ERROR("Could not open the device");
	}

	pcpp::RawPacket rawPacket;

	while (reader->getNextPacket(rawPacket)) {
		pcpp::Packet parsedPacket(&rawPacket);

		analyzePkg(parsedPacket, connPackets, lastPkgs, closedTcpSessions);
	}

}

void writeToFile(
	std::string dirName,
	Connection& conn,
	std::list<pcpp::Packet>& pkgs
)
{
	std::string filename = dirName + "/" + conn.toFilename();
	pcpp::PcapFileWriterDevice pcapWriter(filename);

	if (!pcapWriter.open())
	{
		EXIT_WITH_ERROR("Cannot open output.pcap for writing");
	}

	for (auto const& p : pkgs) {
		pcapWriter.writePacket(*p.getRawPacket());
	}
}

void writeToFiles(
	std::string dirName,
	std::map<Connection, std::list<pcpp::Packet>> connPkgs
)	
{
	createDirIfNotExist(dirName);
	std::map<Connection, std::list<pcpp::Packet>>::iterator it;
	for (it = connPkgs.begin(); it != connPkgs.end(); it++) {
		Connection conn = it->first;
		std::list<pcpp::Packet> pkgs = it->second;
		writeToFile(dirName, conn, pkgs);
	}
}

int main() 
{
	std::map<Connection, std::list<pcpp::Packet>> connPackets;
	std::map<Connection, std::list<pcpp::Packet>> closedTcpSessions;
	std::list<pcpp::Packet> lastPkgs;

	std::string fileName = "tcp_tls_.pcap";

	std::string sessionsDir = "sessions_" + getFileName(fileName);
	std::string activeSessionsDir = "active_sessions_" + getFileName(fileName);

	parseFromFile(fileName, connPackets, lastPkgs, closedTcpSessions);
	printInfoByConns(connPackets, lastPkgs, closedTcpSessions);

	writeToFiles(sessionsDir, closedTcpSessions);
	writeToFiles(activeSessionsDir, connPackets);

	return 0;
}