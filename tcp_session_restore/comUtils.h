#pragma once
#include <iostream>
#include <string>
#include <windows.h>
#include "errhandlingapi.h"
#include "fileapi.h"


#define EXIT_WITH_ERROR(reason) do { \
	std::cout << std::endl << "ERROR: " << reason << std::endl << std::endl; \
	exit(1); \
	} while(0)

int createDirIfNotExist(std::string dirName);