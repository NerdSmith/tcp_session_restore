#include "strUtils.h"

std::string getFileName(std::string fullFilename)
{
	std::string slice = fullFilename.substr(0, fullFilename.size() - 5);
	return slice;
}