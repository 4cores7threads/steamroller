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

//defs.h v1.0.0

#define ENABLE_DEBUG
#define CRYPT64 0
#define CRYPT65 1
#define CRYPT128 2
#define CRYPT256 3
#define NOCRYPT 4
#define max(x, y) (((x) > (y)) ? ( x) : (y))
#define min(x, y) (((x) > (y)) ? ( x) : (y))

void encryptBinaryBlob256(void*, size_t, const char*, uint64_t, bool persist = 0);
void encryptBinaryBlob128(void*, size_t, const char*, uint64_t, bool persist = 0);
void encryptBinaryBlob(void*, size_t, const char*, uint64_t, int method = CRYPT65, bool persist = 0);

void createDirectoryFromArchiveLegacy14(const std::string&, const std::string&);

void decryptLegacyVault(const std::string& d, const std::string& passwd);

typedef union {
	uint64_t d64[4] = {0, 0, 0, 0};
	uint32_t d32[8];
} array256;

typedef union {
	uint64_t d64[2] = {0, 0};
	uint32_t d32[4];
} array128;

class uint128_t {
	public:
		array128 data;
		void add(uint64_t num) {
			if (data.d64[0] + num < data.d64[0]) {data.d64[1]++;};
			data.d64[0]+=num;
		}
		void add(const uint128_t& num) {
			if (data.d64[0] + num.data.d64[0] < data.d64[0]) {data.d64[1]++;};
			data.d64[0]+=num.data.d64[0];
			data.d64[1]+=num.data.d64[1];
		}
		void multiply(uint64_t num) {
			uint32_t dataOld[4];
			memcpy(dataOld, data.d32, 4 * sizeof(uint32_t));
			memset(data.d32, 0, 4 * sizeof(uint32_t));
			for (int y = 0;y < 4;y++) {
				for (int x = 0;x < 2;x++) {
					if (x + y < 4) {
						uint32_t temp;
						uint64_t result = ((uint64_t)dataOld[y]) * ((x == 0) ? (num & 0xffffffff) : (num >> 32));
						//std::cout << x << ", " << y << " " << result << std::endl;
						temp = data.d32[x+y];
						data.d32[x+y]+=result & 0xffffffff;
						if (data.d32[x+y] < temp && x + y < 3) {data.d32[x+y+1]++;};
						if (x + y != 3) {
							temp=data.d32[x+y+1];
							data.d32[x+y+1]+=(result >> 32);
							if (data.d32[x+y+1] < temp && x + y < 2) {data.d32[x+y+2]++;};
						};
					}
				}
			}
		}
		void multiply(const uint128_t& num) {
			uint32_t dataOld[4];
			memcpy(dataOld, data.d32, 4 * sizeof(uint32_t));
			memset(data.d32, 0, 4 * sizeof(uint32_t));
			for (int y = 0;y < 4;y++) {
				for (int x = 0;x < 4;x++) {
					if (x + y < 4) {
						uint32_t temp;
						uint64_t result = ((uint64_t)dataOld[y]) * (uint64_t)num.data.d32[x];
						//std::cout << x << ", " << y << " " << result << std::endl;
						temp = data.d32[x+y];
						data.d32[x+y]+=result & 0xffffffff;
						if (data.d32[x+y] < temp && x + y < 3) {data.d32[x+y+1]++;};
						if (x + y != 3) {
							temp=data.d32[x+y+1];
							data.d32[x+y+1]+=(result >> 32);
							if (data.d32[x+y+1] < temp && x + y < 2) {data.d32[x+y+2]++;};
						};
					}
				}
			}
		}
		void pow2() {
			uint32_t dataOld[4];
			memcpy(dataOld, data.d32, 4 * sizeof(uint32_t));
			memset(data.d32, 0, 4 * sizeof(uint32_t));
			for (int y = 0;y < 4;y++) {
				for (int x = 0;x < 4;x++) {
					if (x + y < 4) {
						uint32_t temp;
						uint64_t result = ((uint64_t)dataOld[y]) * ((uint64_t)dataOld[x]);
						//std::cout << x << ", " << y << " " << result << std::endl;
						temp = data.d32[x+y];
						data.d32[x+y]+=result & 0xffffffff;
						if (data.d32[x+y] < temp && x + y < 3) {data.d32[x+y+1]++;};
						if (x + y != 3) {
							temp=data.d32[x+y+1];
							data.d32[x+y+1]+=(result >> 32);
							if (data.d32[x+y+1] < temp && x + y < 2) {data.d32[x+y+2]++;};
						};
					}
				}
			}
		}		
		void xorp(const uint128_t& num) {
			data.d64[0]^=num.data.d64[0];
			data.d64[1]^=num.data.d64[1];
		}
		void shiftRight16() {
			data.d64[0]>>=16;
			data.d64[0]+=(data.d64[1] & 0xffff) << 48;
			data.d64[1]>>=16;
		}
};

class uint256_t {
	public:
		array256 data;
		
		void add(uint64_t num) {
			
			if (data.d64[0] + num < data.d64[0]) {
				data.d64[1]++;
				if (data.d64[1] == 0) {
					data.d64[2]++;
					if (data.d64[2] == 0) {
						data.d64[3]++;
					}
				}
			};
			data.d64[0]+=num;
		}
		void add(const uint256_t& num) {
			uint64_t temp;
			for (int i = 0;i < 3;i++) {
				temp = data.d64[i];
				data.d64[i]+=num.data.d64[i];
				if (data.d64[i] < temp && i != 3) {data.d64[i+1]++;};
			}
			data.d64[3]+=num.data.d64[3];
		}
		void multiply(uint64_t num) {
			
			uint32_t dataOld[8];
			memcpy(dataOld, data.d32, 8 * sizeof(uint32_t));
			memset(data.d32, 0, 8 * sizeof(uint32_t));
			for (int y = 0;y < 8;y++) {
				for (int x = 0;x < 2;x++) {
					if (x + y < 8) {
						uint32_t temp;
						uint64_t result = ((uint64_t)dataOld[y]) * ((x == 0) ? (num & 0xffffffff) : (num >> 32));
						//std::cout << x << ", " << y << " " << result << std::endl;
						temp = data.d32[x+y];
						data.d32[x+y]+=result & 0xffffffff;
						if (data.d32[x+y] < temp && x + y < 7) {data.d32[x+y+1]++;};
						if (x + y != 7) {
							temp=data.d32[x+y+1];
							data.d32[x+y+1]+=(result >> 32);
							if (data.d32[x+y+1] < temp && x + y < 6) {data.d32[x+y+2]++;};
						};
					}
				}
			}
		}
		void multiply(const uint256_t& num) {

			//using O3 in g++ breaks this function? WTF?

			
			//std::memcpy(&data32, &data, sizeof(void*));
			//std::cout << data32 << std::endl;
			uint32_t dataOld[8];
			memcpy(dataOld, data.d32, 8 * sizeof(uint32_t));
			memset(data.d32, 0, 8 * sizeof(uint32_t));
			for (int y = 0;y < 8;y++) {
				for (int x = 0;x < 8;x++) {
					if (x + y < 8) {
						uint32_t temp;
						uint64_t result = ((uint64_t)dataOld[y]) * num.data.d32[x];
						//std::cout << x << ", " << y << " " << result << std::endl;
						temp = data.d32[x+y];
						data.d32[x+y]+=(uint32_t)result;
						//std::cout << ", " << data[0] << std::endl;
						if (data.d32[x+y] < temp && x + y != 7) {data.d32[x+y+1]++;};
						if (x + y != 7) {
							temp=data.d32[x+y+1];
							data.d32[x+y+1]+=(result >> 32);
							if (data.d32[x+y+1] < temp && x + y != 6) {data.d32[x+y+2]++;};
						};
						//std::cout << std::hex << data[3] << ", " << data[2] << ", " << data[1] << ", " << data[0] << std::endl;
					}
				}
			}
		}
		void pow2() {
			//using O3 in g++ breaks this function? WTF?

			
			//std::memcpy(&data32, &data, sizeof(void*));
			//std::cout << data32 << std::endl;
			uint32_t dataOld[8];
			memcpy(dataOld, data.d32, 8 * sizeof(uint32_t));
			memset(data.d32, 0, 8 * sizeof(uint32_t));
			for (int y = 0;y < 8;y++) {
				for (int x = 0;x < 8;x++) {
					if (x + y < 8) {
						uint32_t temp;
						uint64_t result = ((uint64_t)dataOld[y]) * ((uint64_t)dataOld[x]);
						//std::cout << x << ", " << y << " " << result << std::endl;
						temp = data.d32[x+y];
						data.d32[x+y]+=(uint32_t)result;
						//std::cout << ", " << data[0] << std::endl;
						if (data.d32[x+y] < temp && x + y != 7) {data.d32[x+y+1]++;};
						if (x + y != 7) {
							temp=data.d32[x+y+1];
							data.d32[x+y+1]+=(result >> 32);
							if (data.d32[x+y+1] < temp && x + y != 6) {data.d32[x+y+2]++;};
						};
						//std::cout << std::hex << data[3] << ", " << data[2] << ", " << data[1] << ", " << data[0] << std::endl;
					}
				}
			}
		}

		void xorp(const uint256_t& num) {
			data.d64[0]^=num.data.d64[0];
			data.d64[1]^=num.data.d64[1];
			data.d64[2]^=num.data.d64[2];
			data.d64[3]^=num.data.d64[3];
		}
		void shiftRight32() {
			/*
			data[0]>>=32;
			data[0]+=(data[1] & 0xffffffff) << 32;
			data[1]>>=32;
			data[1]+=(data[2] & 0xffffffff) << 32;
			data[2]>>=32;
			data[2]+=(data[3] & 0xffffffff) << 32;
			data[3]>>=32;
			*/
			for (int i = 0;i < 7;i++) {
				data.d32[i] = data.d32[i + 1];
			}
			data.d32[7] = 0;
		}
};

class blob {
	private:
		size_t bufferLength;
	public:
		unsigned char* data;
		size_t length = 0;
		blob(size_t l = 1024) {
			data = (unsigned char*)malloc(l);
			#ifdef ENABLE_DEBUG
				//std::cout << "Initialized blob at -> " << data << "." << std::endl;

			#endif
			bufferLength = l;
		}
		~blob() {
			free(data);
		}
		void add(size_t l) {
			length+=l;
			if (length + 1 > bufferLength) {

				bufferLength = length * 2;
				data = (unsigned char*)realloc(data, bufferLength);
			}
		}
};

class vaultArchiveFile {
	public:
		char* name;
		uint64_t salt;
		size_t size;
		vaultArchiveFile() {
			std::random_device rd;
			std::mt19937_64 gen(rd());
			std::uniform_int_distribution<uint64_t> dist(0, 0xffffffffffffffff);
			salt = dist(gen);
		}
		~vaultArchiveFile() {
			free(name);
			std::cout << "vaultArchiveFile destructor called" << std::endl;
		}
};

class file {
	public:
		unsigned char* data;
		size_t length;
		FILE* fptr;
		file(const char* name) {
			fptr = fopen(name, "rb");
			if (fptr == NULL) {length = 0;return;};
			fseek(fptr, 0L, SEEK_END);
			length = ftell(fptr);
						
		}
		void load(const char* name) {
			rewind(fptr);
			data = (unsigned char*)malloc(length);
			fread(data, 1, length, fptr);
			#ifdef ENABLE_DEBUG
				std::cout << "Loaded \"" << name << "\", length = " << length << std::endl; 
			#endif
			fclose(fptr);

		}
		~file() {
			free(data);
			//free(fname);
		}

};

class directory {
	public:
		size_t fileLength = 0;
		size_t dirLength = 0;
		uint64_t headerLocation = 0;
		int progress = 0;
		size_t fileBufferLength;
		size_t dirBufferLength;
		std::string rootPath;
		std::vector<std::string> fileList;
		std::vector<std::string> dirList;
		std::vector<uint64_t> pointerList;
		directory(const std::string& p) {
			#ifdef ENABLE_DEBUG
				//std::cout << "Directory class constructor function was called, start size: " << startSize << std::endl;
			#endif
			rootPath = p;
			//fileList = (std::string*)std::malloc(startSize*sizeof(std::string));
			//dirList = (std::string*)std::malloc(startSize*sizeof(std::string));
			//fileBufferLength = startSize;
			//dirBufferLength = startSize;
		}
		~directory() {
			#ifdef ENABLE_DEBUG
				std::cout << "Directory class destructor function was called" << std::endl;
			#endif
			//free(fileList);
			//free(dirList);
		}
		inline void addFile(const std::string& name) {
			/*if (fileLength >= fileBufferLength) {
				#ifdef ENABLE_DEBUG
					std::cout << "Reallocating directory buffer from " << fileBufferLength << " -> " << fileBufferLength*2 << std::endl;
				#endif

				fileBufferLength*=2;
				fileList = (std::string*)std::realloc(fileList,fileBufferLength * sizeof(std::string));

				if (fileList == NULL) {
					std::cout << "fileList reallocation returned NULL" << std::endl;
				}

			}*/
			//fileList[fileLength] = name;
			fileList.push_back(name);
			fileLength++;	
		}
		inline void addDir(const std::string& name, uint64_t ptr) {
			/*if (dirLength >= dirBufferLength) {
				dirBufferLength*=2;
				dirList = (std::string*)std::realloc(dirList,dirBufferLength * sizeof(std::string));
				if (dirList == NULL) {
					std::cout << "dirList reallocation returned NULL" << std::endl;
				}
			}*/

			//dirList[dirLength] = name;
			dirList.push_back(name);
			pointerList.push_back(ptr);
			dirLength++;	
		}

};

class extractState {
	public:
		uint64_t* offset = 0;
		uint64_t numFiles = 0;
		size_t progress = 0;
		extractState(uint64_t* o) {
			offset = o + 2;
			numFiles = *o;
			std::cout << *o << " Files in directory" << std::endl;	
		}
};

class dynamicString {
	public:
		char* str;
		size_t length = 0;
		size_t bufferLength = 0;
		dynamicString(const char* s) {
			length = strlen(s) + 1;
			bufferLength = length*2;
			str = (char*)calloc(bufferLength, sizeof(char));
			strcpy(str, s);
			
		}
		void push(const char* s) {
			length+=strlen(s);
			if (length > bufferLength) {bufferLength=length*2;str = (char*)realloc(str, bufferLength + 1);};
			strcat(str, s);
		}
		void pop() {
			if (length > 0) {
				int i = length - 3;
				//if (str[i] == '/' || str[i] == '\\') {i--;};
				while (str[i] != '/' && str[i] != '\\' && i > 0) {
					i--;
				}
				if (i > 0) {str[i + 1] = '\0';length = i + 2;};
				
			}
		}
		void clear() {
			str[0] = '\0';
			length = 1;
		}
};

class dirStack {
	private:
		directory* data;
	public:
		directory* top;
		size_t length = 0;
		size_t bufferSize;
		dirStack(size_t startSize = 8) {
			data = (directory*)std::malloc(startSize*sizeof(directory));
			if (data == NULL) {printf("dirStack malloc failed!");};
			bufferSize = startSize;
		}
		~dirStack() {
			free(data);
		}
		inline void push(const std::string& p) {
			if (length >= bufferSize) {bufferSize*=2;data = (directory*)std::realloc(data, bufferSize*sizeof(directory));};
			//data[length] = directory(p);
			new (&data[length]) directory(p);
			top = &(data[length]);
			
			length++;
		}
		inline void pop() {
			
			if (length > 0) {
					length--;
					//top->~directory();
					//delete &data[length];
					top = &data[length-1];
			};
		}
};
