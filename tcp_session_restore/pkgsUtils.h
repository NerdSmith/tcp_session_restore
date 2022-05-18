#pragma once
#include <list>
#include <map>
#include "TcpLayer.h"
#include "PcapFileDevice.h"
#include "comUtils.h"
#include "PacketUtils.h"

#include "connection.h"


bool check4SYN(pcpp::TcpLayer* tcpLayer);
bool check4ACK(pcpp::TcpLayer* tcpLayer);
bool check4FIN(pcpp::TcpLayer* tcpLayer);

void writeToFile(
	std::string dirName,
	Connection& conn,
	std::list<pcpp::Packet>& pkgs
);

void writeToFiles(
	std::string dirName,
	std::map<Connection, std::list<pcpp::Packet>> connPkgs
);

void printInfoByConns(
	std::map<Connection, std::list<pcpp::Packet>>& connPackets,
	std::list<pcpp::Packet>& lastPkgs,
	std::map<Connection, std::list<pcpp::Packet>>& closedTcpSessions
);