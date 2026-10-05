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
#include <unistd.h>
#include "encryption.h"

extern bool quiet;

//encryption.cpp v1.1.1

void encryptBinaryBlob256(void* b, size_t size, const char* pwd, uint64_t salt, bool persist) {
	static uint256_t pastKey;
	static uint64_t pastOffset;
	static bool pastPersist = 0;
	uint64_t offset = 0;

	uint256_t now;
	uint64_t* blob = (uint64_t*)b;
	size_t pwdLength = mymax(128 + strlen(pwd), strlen(pwd) * 2);
	size_t origLength = strlen(pwd);
	char* pwdString = (char*)calloc(pwdLength + 1,sizeof(char));
	for (int i = 0;(i + origLength) < pwdLength;i+=origLength) {
		//std::cout << "copy" << std::endl;
		std::memcpy(pwdString+i, pwd, origLength);
	}
	//std::cout << pwdString << std::endl;
	size_t numCycles = mymax(64, strlen(pwd));
	uint256_t* keylist = new uint256_t[numCycles];
	for (int i = 0;i < numCycles;i++) {
		std::memcpy(keylist[i].data.d64, pwdString + i, 4 * sizeof(uint64_t));
		//std::cout << std::hex << keylist[i].data[3] << ", " << keylist[i].data[2] << ", " << keylist[i].data[1] << ", " << keylist[i].data[0] << std::endl;
	}
	uint256_t buffer;

	if (pastPersist == 1 && persist == 1) {
		offset = pastOffset;
		now = pastKey;
		std::cout << "set offset to: " << offset << std::endl;
	} else {
		now.add(keylist[0]);
	
	}

	uint64_t i;
	for (i = offset;i < (size >> 5) + offset;i++) {
		//now = ((now + keylist[i%numCycles]) * now + i + salt) ^ keylist[i % numCycles];
		std::memcpy(buffer.data.d64, now.data.d64, sizeof(uint64_t)*4);
		now.add(keylist[i%numCycles]);
		//std::cout << "Step -> addKeylist     " << std::hex << std::setfill('0') << std::setw(16) << now.data.d64[3] << ", " << now.data.d64[2] << ", " << now.data.d64[1] << ", " << now.data.d64[0] << std::endl;
		now.multiply(buffer);
		//std::cout << "Step -> multiplyBuffer " << std::hex << std::setfill('0') << std::setw(16) << now.data.d64[3] << ", " << now.data.d64[2] << ", " << now.data.d64[1] << ", " << now.data.d64[0] << std::endl;
		now.add(i);
		//std::cout << "Step -> addI           " << std::hex << std::setfill('0') << std::setw(16) << now.data.d64[3] << ", " << now.data.d64[2] << ", " << now.data.d64[1] << ", " << now.data.d64[0] << std::endl;
		now.add(salt);
		//std::cout << "Step -> addSalt        " << std::hex << std::setfill('0') << std::setw(16) << now.data.d64[3] << ", " << now.data.d64[2] << ", " << now.data.d64[1] << ", " << now.data.d64[0] << std::endl;
		now.xorp(keylist[i%numCycles]);
		//std::cout << "Step -> XOR            " << std::hex << std::setfill('0') << std::setw(16) << now.data.d64[3] << ", " << now.data.d64[2] << ", " << now.data.d64[1] << ", " << now.data.d64[0] << std::endl;

		std::memcpy(buffer.data.d64, now.data.d64, sizeof(uint64_t)*4);
		for (int i = 0;i < 8;i++) {
	    	buffer.shiftRight32();
			now.add(buffer);
		}
		//std::cout << "Step -> shiftRight     " << std::hex << std::setfill('0') << std::setw(16) << now.data.d64[3] << ", " << now.data.d64[2] << ", " << now.data.d64[1] << ", " << now.data.d64[0] << std::endl;

		blob[(i << 2)]^=now.data.d64[0];
		blob[(i << 2) + 1]^=now.data.d64[1];
		blob[(i << 2) + 2]^=now.data.d64[2];
		blob[(i << 2) + 3]^=now.data.d64[3];
	
	}
	if (persist == 1) {
		pastKey = now;	
		pastOffset = i;
	}
	pastPersist = persist;
	delete keylist;
	free(pwdString);

}

void encryptBinaryBlob128(void* b, size_t size, const char* pwd, uint64_t salt, bool persist) {
	static uint128_t pastKey;
	static uint64_t pastOffset;
	static bool pastPersist = 0;
	uint64_t offset = 0;

	uint128_t now;
	
	uint64_t* blob = (uint64_t*)b;
	size_t pwdLength = mymax(64 + strlen(pwd), strlen(pwd) * 2);
	size_t origLength = strlen(pwd);
	char* pwdString = (char*)calloc(pwdLength + 1,sizeof(char));
	for (int i = 0;(i + origLength) < pwdLength;i+=origLength) {
		//std::cout << "copy" << std::endl;
		std::memcpy(pwdString+i, pwd, origLength);
	}
	//std::cout << pwdString << std::endl;
	size_t numCycles = mymax(32, strlen(pwd));
	uint128_t* keylist = new uint128_t[numCycles];
	for (int i = 0;i < numCycles;i++) {
		std::memcpy(keylist[i].data.d64, pwdString + i, 2 * sizeof(uint64_t));
		//std::cout << (uint64_t*)keylist[i] << std::endl;
	}
	uint128_t buffer;
	if (pastPersist == 1 && persist == 1) {
		offset = pastOffset;
		now = pastKey;
	} else {
		now.add(keylist[0]);
	}


	uint64_t i;
	for (i = offset;i < (size >> 4) + offset;i++) {
		//now = ((now + keylist[i%numCycles]) * now + i + salt) ^ keylist[i % numCycles];
		std::memcpy(buffer.data.d64, now.data.d64, sizeof(uint64_t)*2);
		now.add(keylist[i%numCycles]);
		now.multiply(buffer); 
		now.add(i);
		now.add(salt);
		now.xorp(keylist[i%numCycles]);
		std::memcpy(buffer.data.d64, now.data.d64, sizeof(uint64_t)*2);
		for (int i = 0;i < 8;i++) {
	    	buffer.shiftRight16();
			now.add(buffer);
		}		
		blob[(i << 1)]^=now.data.d64[0];
		blob[(i << 1) + 1]^=now.data.d64[1];

	}
	if (persist == 1) {
		pastKey = now;	
		pastOffset = i;
	}
	delete keylist;
	free(pwdString);

}

void encryptBinaryBlob(void* b, size_t size, const char* pwd, uint64_t salt, int method, bool persist) {
	uint64_t* blob = (uint64_t*)b;
	static uint64_t pastKey;
	static uint64_t pastOffset;
	static bool pastPersist = 0;
	uint64_t offset = 0;

	uint64_t now;

	size_t pwdLength = mymax(32 + strlen(pwd), strlen(pwd) * 2);
	size_t origLength = strlen(pwd);
	char* pwdString = (char*)calloc(pwdLength + 1,sizeof(char));
	for (int i = 0;(i + origLength) < pwdLength;i+=origLength) {
		//std::cout << "copy" << std::endl;
		std::memcpy(pwdString+i, pwd, origLength);
	}
	//std::cout << pwdString << std::endl;
	size_t numCycles = mymax(16, strlen(pwd));
	uint64_t* keylist = new uint64_t[numCycles];
	for (int i = 0;i < numCycles;i++) {
		std::memcpy(keylist + i, pwdString + i, sizeof(uint64_t));
		//std::cout << (uint64_t*)keylist[i] << std::endl;
	}
	if (pastPersist == 1 && persist == 1) {
		offset = pastOffset;
		now = pastKey;
	} else {
		now = keylist[0];
	}
	uint64_t i;
	if (method == CRYPT64) {
		for (i = offset;i < (size >> 3) + offset;i++) {
			now = ((now + keylist[i%numCycles]) * now + i + salt) ^ keylist[i % numCycles];
			//std::cout << (uint64_t*)now << std::endl;
			blob[i]^=now;
	
		}
	} else if (method == CRYPT65) {
		for (i = offset;i < (size >> 3) + offset;i++) {
			now = ((now + keylist[i%numCycles]) * now + i + salt) ^ keylist[i % numCycles];
			//std::cout << (uint64_t*)now << std::endl;
			now+= (now >> 8) + (now >> 16) + (now >> 24) + (now >> 32) + (now >> 40) + (now >> 48) + (now >> 56);
			blob[i]^=now;
	
		}
	
	} else {
		std::cerr << "Invalid encryption method!" << std::endl;
	}
	if (persist == 1) {
		pastKey = now;	
		pastOffset = i;
	}
	delete keylist;
	free(pwdString);

}

void obfuscateString(const char* src, char* dest, uint64_t salt) {
	const static char* hexChars = "0123456789ABCDEF";
	char temp[17];
	for (int i = 0;i < 16;i++) {
		temp[i] = rand() & 255;
	}
	if (strnlen(src, 17) > 16) {
		std::cerr << "[obfuscateString] (Warning) Input string is too long" << std::endl;
		return;
	}
	strcpy(temp, src);
	const char* username = getlogin();
	if (username == NULL) {
		std::cerr << "[obfuscateString] (Warning) Can't get username" << std::endl;
		return;
	}
	
	encryptBinaryBlob128(temp, 16, username, salt, 0);
	
	for (int i = 8;i < 24;i++) {
		dest[i*2 - 16] = hexChars[(temp[i & 15]>>4) & 15];
		dest[i*2 - 15] = hexChars[temp[i & 15] & 15];
	}
	dest[32] = '\0';

}

int deobfuscateString(const char* src, char* dest, uint64_t salt) {
	const static char hexChars[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9,
	0, 0, 0, 0, 0, 0, 0, 10, 11, 12, 13, 14, 15};
	
	for (int i = 0;i < 16;i++) {
		if (src[i*2] < 48 || src[i*2] > 70 || src[i*2 + 1] < 48 || src[i*2 + 1] > 70) {
			std::cerr << "[deobfuscateString] (ERROR) Invalid value in obfuscated string" << std::endl;
			return -1;
		}
		dest[(i + 8) & 15] = hexChars[src[i*2] - 48] << 4;
		dest[(i + 8) & 15] += hexChars[src[i*2 + 1] - 48];
	}
	const char* username = getlogin();
	if (username == NULL) {
		std::cerr << "[deobfuscateString] (Warning) Can't get username" << std::endl;
		return -1;
	}
	encryptBinaryBlob128(dest, 16, username, salt);
	return 0;
}

char* lastSlash(const char* src, int offset) {
	size_t len = strnlen(src, 1024);
	for (int i = len;i >= 0;i--) {
		if (src[i] == '/' || src[i] == '\\') {
			return (char*)src + i + offset;
		}
	}
	return (char*)src;
}

char* lastChar(const char* src, char c, int offset) {
	size_t len = strnlen(src, 1024);
	for (int i = len;i >= 0;i--) {
		if (src[i] == c) {
			return (char*)src + i + offset;
		}
	}
	return (char*)src;
}

