#include "comUtils.h"

int createDirIfNotExist(std::string dirName)
{
	if (CreateDirectoryA(dirName.c_str(), NULL) ||
		ERROR_ALREADY_EXISTS == GetLastError()) {
		printf("Dir is OK\n");
		return 0;
	}

	printf("Can't create dir\n");
	return 1;
}