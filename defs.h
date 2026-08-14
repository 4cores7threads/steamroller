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

#define CRYPT64 0
#define CRYPT65 1
#define CRYPT128 2
#define CRYPT256 3
#define NOCRYPT 4
#define mymin(x, y) (((x) < (y)) ? ( x) : (y))
#define mymax(x, y) (((x) > (y)) ? ( x) : (y))

void createDirectoryFromArchiveLegacy14(const std::string&, const std::string&);

void decryptLegacyVault(const std::string& d, const std::string& passwd);

class vaultConfig {
	public:
		int method;
		bool headless;
		bool noSymlink;
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
