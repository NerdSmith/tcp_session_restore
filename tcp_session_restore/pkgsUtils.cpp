#include "pkgsUtils.h"


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

