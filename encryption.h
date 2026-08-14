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

//encryption.h v1.0.0

#define CRYPT64 0
#define CRYPT65 1
#define CRYPT128 2
#define CRYPT256 3
#define NOCRYPT 4
#define mymin(x, y) (((x) < (y)) ? ( x) : (y))
#define mymax(x, y) (((x) > (y)) ? ( x) : (y))

void encryptBinaryBlob256(void*, size_t, const char*, uint64_t, bool persist = 0);
void encryptBinaryBlob128(void*, size_t, const char*, uint64_t, bool persist = 0);
void encryptBinaryBlob(void*, size_t, const char*, uint64_t, int method = CRYPT65, bool persist = 0);


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

