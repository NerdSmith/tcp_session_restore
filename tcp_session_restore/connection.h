#pragma once
#include <sstream>
#include "IPv4Layer.h"

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