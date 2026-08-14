#include <iostream>
#include <cmath>
#include <filesystem>
#include <stack>
#include <vector>
#include <new>
#include <cstring>
#include <random>
#include <chrono>
#include <iomanip>
#include "base.h"
#include "defs.h"
#include "encryption.h"

extern bool quiet;

void decryptLegacyVault(const std::string& d, const std::string& passwd) {
	FILE* fptr = fopen(d.c_str(), "rb");
	uint64_t initialBuffer[32];
	fread(initialBuffer, sizeof(uint64_t), 32, fptr);
	int method = (int)initialBuffer[3];
	std::string outputName = d;
	outputName.append(".out");
	FILE* outputFile = fopen(outputName.c_str(), "wb");
	uint64_t* nameTree = (uint64_t*)malloc(initialBuffer[1] - initialBuffer[0]);
	fseek(fptr, initialBuffer[0], SEEK_SET);
	fread(nameTree, 1, initialBuffer[1] - initialBuffer[0], fptr);

	switch (method) {
		case CRYPT256:
			encryptBinaryBlob256(nameTree, initialBuffer[1] - initialBuffer[0], passwd.c_str(), initialBuffer[2]);
			break;
		case CRYPT128:
			encryptBinaryBlob128(nameTree, initialBuffer[1] - initialBuffer[0], passwd.c_str(), initialBuffer[2]);
			break;
		default:
			encryptBinaryBlob(nameTree, initialBuffer[1] - initialBuffer[0], passwd.c_str(), initialBuffer[2], method);
			break;
	}

	fwrite(initialBuffer, sizeof(uint64_t), 32, outputFile);
	fwrite(nameTree, 1, initialBuffer[1] - initialBuffer[0], outputFile);

	fseek(fptr, 0L, SEEK_END);
	uint64_t dataTreeLength = ftell(fptr) - initialBuffer[1];
	fseek(fptr, initialBuffer[1], SEEK_SET);
	uint64_t chunkSize = 2<<26;
	int numChunks = (dataTreeLength / chunkSize);
	uint64_t* buffer = (uint64_t*)malloc(chunkSize);
	for (int i = 0;i < numChunks;i++) {
		fread(buffer, 1, chunkSize, fptr);
		switch (method) {
			case CRYPT256:
				encryptBinaryBlob256(buffer, chunkSize,  passwd.c_str(), initialBuffer[2], 1);
				break;
			case CRYPT128:
				encryptBinaryBlob128(buffer, chunkSize, passwd.c_str(), initialBuffer[2], 1);
				break;
			default:
				encryptBinaryBlob(buffer, chunkSize, passwd.c_str(), initialBuffer[2], method, 1);
				break;
		}
		fwrite(buffer, 1, chunkSize, outputFile);
	
	}
	uint64_t finalSize = dataTreeLength % chunkSize;
	fread(buffer, 1, finalSize, fptr);
	switch (method) {
		case CRYPT256:
			encryptBinaryBlob256(buffer, finalSize,  passwd.c_str(), initialBuffer[2], 1);
			break;
		case CRYPT128:
			encryptBinaryBlob128(buffer, finalSize, passwd.c_str(), initialBuffer[2], 1);
			break;
		default:
			encryptBinaryBlob(buffer, finalSize, passwd.c_str(), initialBuffer[2], method, 1);
			break;
	}
	fwrite(buffer, 1, finalSize, outputFile);

	free(nameTree);
	free(buffer);
	fclose(outputFile);
	fclose(fptr);
}



void createDirectoryFromArchiveLegacy14(const std::string& d, const std::string& passwd) {
	FILE* fptr = fopen(d.c_str(), "rb");
	if (fptr == NULL) {
		std::cerr << "No such file or directory" << std::endl;
		return;
	}	
	fseek(fptr, 0L, SEEK_END);

	size_t flength = ftell(fptr);
	rewind(fptr);
	uint64_t* buffer = (uint64_t*)malloc((flength >> 3) * sizeof(uint64_t));
	for (int i = 0;i < 8;i++) {
		if (!quiet) {std::cout << "Reading from \"" << d << "\" " << i << " / 8" << std::endl;};
		fread((unsigned char*)buffer + i * (flength >> 3), 1, flength >> 3, fptr);
	}
	fclose(fptr);
	uint64_t* nameTree = buffer + (buffer[0] >> 3);
	uint64_t* dataTree = buffer + (buffer[1] >> 3);
	int method = (int)buffer[3];
	if (method == CRYPT64 || method == CRYPT65) {
		if (!quiet) {std::cout << "Decrypting nameTree..." << std::endl;};
		encryptBinaryBlob(nameTree, buffer[1] - buffer[0], passwd.c_str(), buffer[2], method);
		if (!quiet) {std::cout << "Decrypting dataTree..." << std::endl;};
		encryptBinaryBlob(dataTree, flength - buffer[1], passwd.c_str(), buffer[2], method);
	} else if (method == CRYPT128) {
		if (!quiet) {std::cout << "Decrypting nameTree... (128-bit)" << std::endl;};
		encryptBinaryBlob128(nameTree, buffer[1] - buffer[0], passwd.c_str(), buffer[2]);
		if (!quiet) {std::cout << "Decrypting dataTree... (128-bit)" << std::endl;};
		encryptBinaryBlob128(dataTree, flength - buffer[1], passwd.c_str(), buffer[2]);
	
	} else if (method == CRYPT256) {
		if (!quiet) {std::cout << "Decrypting nameTree... (256-bit)" << std::endl;};
		encryptBinaryBlob256(nameTree, buffer[1] - buffer[0], passwd.c_str(), buffer[2]);
		if (!quiet) {std::cout << "Decrypting dataTree... (256-bit)" << std::endl;};
		encryptBinaryBlob256(dataTree, flength - buffer[1], passwd.c_str(), buffer[2]);
	}
	std::cout << "Loaded archive, nameTree -> " << buffer[0] << " dataTree -> " << buffer[1] << std::endl;
	std::stack<extractState> stack;
	
	stack.push(nameTree);
	//stack.top().offset+=2;
	int depth = 1;
	dynamicString fileName = "";
	dynamicString rootPath = d.c_str();
	rootPath.str[rootPath.length - 7] = '\0';
	rootPath.length-=6;
	rootPath.push("/");
    std::cout << "Creating directory at " << rootPath.str << ", length = " << rootPath.length << std::endl;	
	std::filesystem::create_directory(rootPath.str);
	while (depth > 0) {
		if (stack.top().progress < stack.top().numFiles) {
			fileName.clear();
			fileName.push(rootPath.str);
			fileName.push((char*)(stack.top().offset+4));
			if (!quiet) {std::cout << "name: " << fileName.str << " Directory: " << stack.top().offset[1] << std::endl;};
			if (stack.top().offset[1] == 0) {
				FILE* fptr = fopen(fileName.str, "wb");
				if (!quiet) {std::cout << "Writing \"" << fileName.str << "\", length -> " << stack.top().offset[3] << " Bytes" << std::endl;};
				fwrite((unsigned char*)dataTree + stack.top().offset[2], 1, stack.top().offset[3], fptr);
				fclose(fptr);
				stack.top().offset+=stack.top().offset[0]>>3;
				stack.top().progress++;
			} else if (stack.top().offset[1] == 1) {
				rootPath.push((char*)(stack.top().offset + 4));
				rootPath.push("/");

				stack.push(nameTree + (stack.top().offset[2] >> 3));
				
				if (!quiet) {std::cout << "Number of files: " << stack.top().offset[-2] << ", offset = " << (8 * (stack.top().offset - nameTree)) << std::endl;};
   				if (!quiet) {std::cout << "Creating directory at " << rootPath.str << ", length = " << rootPath.length << std::endl;};
				std::filesystem::create_directory(rootPath.str);
				depth++;
				if (stack.top().numFiles == 0) {
					stack.pop();
					rootPath.pop();
					if (!quiet) {std::cout << "Popping stack (no files in directory), rootPath = " << rootPath.str << std::endl;};
					depth--;
					stack.top().progress++;
					if (stack.top().progress < stack.top().numFiles) {stack.top().offset+=stack.top().offset[0]>>3;};
				}	
			} else {
				std::cout << "ERROR: Unknown file flag data" << std::endl;
				//stack.top().progress++;
				return;	
			}





		} else if (depth > 1) {

			stack.pop();
			rootPath.pop();
			if (!quiet) {std::cout << "Popping stack, rootPath = " << rootPath.str << std::endl;};
			depth--;
			stack.top().progress++;
			stack.top().offset+=stack.top().offset[0]>>3;
		} else if (depth == 1) {
			depth = 0;
			break;
		}
	}


	/*
	uint64_t* offset = nameTree + 2;
	for (int i = 0;i < nametree[0];i++) {
		std::cout << "name: " << (char*)(offset + 4) << " Directory: " << offset[1] << std::endl;
		offset+=(offset[0])>>3;
	}
	std::cout << buffer[0] << " files in directory" << std::endl;
	*/
	free(buffer);
}
