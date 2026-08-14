#include <iostream> 
#include <cmath>
#include <filesystem>
#include <stack>
#include <vector>
#include <new>
#include <cstring>

//base.h v1.0.0

#define CRYPT64 0
#define CRYPT65 1
#define CRYPT128 2
#define CRYPT256 3
#define NOCRYPT 4
#define mymin(x, y) (((x) < (y)) ? ( x) : (y))
#define mymax(x, y) (((x) > (y)) ? ( x) : (y))



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

