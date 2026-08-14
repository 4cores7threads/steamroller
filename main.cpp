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
#include "base.h"
#include "encryption.h"
#include "defs.h"

bool quiet = 0;





void createArchiveFromDirectory(const std::string& d, const std::string& passwd, const vaultConfig* cfg) {
	#ifdef ENABLE_DEBUG
		std::cout << "Creating archive from \"" << d << "\"" << std::endl;	
	#endif	
	blob nameTree;
	
	size_t dataTreeOffset = 0;
	size_t nameTreeOffset = 0;
	uint64_t totalSize = 0;
	dirStack stack;
	int depth = 0;
	//printf("stack has not been bushed\n");
	stack.push(d);
	nameTree.add(16);
	stack.top->headerLocation = 0;
	//printf("stack has JUST been pushed\n");
	std::string fname;
	std::vector<vaultArchiveFile*> fileTreeList;	

	while (depth >= 0) {
		//stack.top->fileLength = 0;
		//stack.top->dirLength = 0;
		if (stack.top->progress == 0) {
			stack.top->fileLength = 0;
			stack.top->dirLength = 0;
			for (const auto & entry : std::filesystem::directory_iterator(stack.top->rootPath)) {
				#ifdef ENABLE_DEBUG
					if (!quiet) {std::cout << "-> " << entry.path() << " Dir? " << std::filesystem::is_directory(entry.path()) << std::endl; };
				#endif
				fname = entry.path().filename();
				if (fname.c_str()[0] != '.' && ((!cfg->noSymlink && depth < 16) || !(std::filesystem::is_symlink(entry.path())))) {
						uint64_t is_dir = std::filesystem::is_directory(entry.path());
					if (is_dir) {
						nameTreeOffset=nameTree.length;	
						nameTree.add(48 + ((fname.size()+1)>>3)*8);
						((uint64_t*)nameTree.data)[nameTreeOffset>>3] = 48 + ((fname.size()+1)>>3)*8;
						((uint64_t*)nameTree.data)[(nameTreeOffset>>3) + 1] = 1;
						strcpy((char*)( nameTree.data + nameTreeOffset + 40), (char*)fname.c_str());
						stack.top->addDir(entry.path(), (uint64_t)((nameTreeOffset + 16)>>3));
						#ifdef ENABLE_DEBUG
							if (!quiet) {std::cout << "& Added " << (uint64_t)((nameTreeOffset + 16)>>3) << " to pointerList" << std::endl;};
						#endif
					} else {
						
					
						FILE* fptr = fopen(entry.path().c_str(), "rb");
						if (fptr == NULL) {
							std::cerr << "Failed to open file \"" << entry.path() << "\"" << std::endl;
						} else {
							nameTreeOffset=nameTree.length;	
							nameTree.add(48 + ((fname.size()+1)>>3)*8);
							((uint64_t*)nameTree.data)[nameTreeOffset>>3] = 48 + ((fname.size()+1)>>3)*8;
							((uint64_t*)nameTree.data)[(nameTreeOffset>>3) + 1] = 0;
							strcpy((char*)( nameTree.data + nameTreeOffset + 40), (char*)fname.c_str());

							stack.top->addFile(entry.path());

							fseek(fptr, 0L, SEEK_END);
							size_t flength = ftell(fptr);
							totalSize+=flength;
							rewind(fptr);
							fileTreeList.push_back(new vaultArchiveFile);
							vaultArchiveFile* currentFile = fileTreeList[fileTreeList.size() - 1];
							currentFile->name = (char*)malloc(strlen(entry.path().c_str()) + 1);
							strcpy(currentFile->name, entry.path().c_str());
							currentFile->size = flength;
							if (cfg->headless == true) {
								auto ftime = std::filesystem::last_write_time(entry.path());
								auto sctp = std::chrono::time_point_cast<std::chrono::system_clock::duration>(ftime - std::filesystem::file_time_type::clock::now() + std::chrono::system_clock::now());
								std::time_t cftime = std::chrono::system_clock::to_time_t(sctp);
								((int32_t*)nameTree.data)[(nameTreeOffset>>2) + 3] = (int32_t)cftime;
							}
							((uint64_t*)nameTree.data)[(nameTreeOffset>>3) + 2] = dataTreeOffset;
							((uint64_t*)nameTree.data)[(nameTreeOffset>>3) + 3] = flength;
							((uint64_t*)nameTree.data)[(nameTreeOffset>>3) + 4] = currentFile->salt;
							dataTreeOffset+=(flength >> 5) * 32 + 32;
							//dataTree.add((flength>>5) * 32 + 32);
							//fread(dataTree.data + dataTreeOffset,1,flength,fptr);
							fclose(fptr);
														
							if (!quiet && flength > 65536) {std::cout << "Added " << entry.path() << " to dataTree, size -> " << + dataTreeOffset << std::endl;};
						}

					
					}	
								
				} else {
					if (!quiet) {std::cout << ":: file is hidden or symlink, skipping..." << std::endl;};
				
				}
			
			}
			printf("%llu, %zu\n", stack.top->headerLocation, nameTree.length);
			((uint64_t*)nameTree.data)[stack.top->headerLocation] = (uint64_t)(stack.top->fileLength + stack.top->dirLength);
		}
		if (stack.top->progress < stack.top->dirLength) {
			nameTreeOffset = nameTree.length;
			((uint64_t*)nameTree.data)[stack.top->pointerList[(stack.top->progress)]] = nameTreeOffset;
			stack.top->progress++;
			depth++;
			if (!quiet) {std::cout << "Increasing depth from " << depth-1 << " -> " << depth << std::endl;};
			//std::cout << stack.top->progress << std::endl;
			stack.push(stack.top->dirList[stack.top->progress - 1]);
			
			nameTree.add(16);
			stack.top->headerLocation = (uint64_t)nameTreeOffset >> 3;

		} else {
			stack.pop();
			depth--;
			if (!quiet) {std::cout << "Popping stack from depth " << (depth+1) << " -> " << depth << std::endl;};
		}	
	}
	if (cfg->method == CRYPT256) {
		nameTree.add((32 - (nameTree.length % 32)) % 32);
	} else if (cfg->method == CRYPT128) {
		nameTree.add((16 - (nameTree.length % 16)) % 16);
	}



	uint64_t* frontBuffer = (uint64_t*)calloc(32, sizeof(uint64_t));
	frontBuffer[0] = 256;
	frontBuffer[1] = 256+nameTree.length;
	frontBuffer[3] = cfg->method;
	frontBuffer[4] = 0x00020100;
	if (cfg->headless) {
		frontBuffer[6] = totalSize;
	}
	sprintf((char*)(frontBuffer + 5), "VAULT\0\0\0");
	std::random_device rd;
	std::mt19937_64 gen(rd());
	std::uniform_int_distribution<uint64_t> dist(0, 0xffffffffffffffff);
	uint64_t salt = dist(gen);

	frontBuffer[2] = salt;
	if (cfg->method == CRYPT256) {

		if (!quiet) {std::cout << "Encrypting dataTree... (256-bit)" << std::endl;};
		encryptBinaryBlob256(nameTree.data, nameTree.length, passwd.c_str(), salt);
	} else if (cfg->method == CRYPT128) {

		if (!quiet) {std::cout << "Encrypting dataTree... (128-bit)" << std::endl;};
		encryptBinaryBlob128(nameTree.data, nameTree.length, passwd.c_str(), salt);
	} else if (cfg->method == CRYPT64 || cfg->method == CRYPT65) {

		if (!quiet) {std::cout << "Encrypting dataTree... (Legacy / 64-bit)" << std::endl;};
		encryptBinaryBlob(nameTree.data, nameTree.length, passwd.c_str(), salt, cfg->method);

	}
	FILE* fout = fopen((d + ".vault").c_str(), "wb");
	fwrite(frontBuffer, 8, 32, fout);
	fwrite(nameTree.data, 1, nameTree.length, fout);
	//fwrite(dataTree.data, 1, dataTree.length, fout);
	if (cfg->headless == false) {
		int numFiles = fileTreeList.size();
		
		
		blob currentFileBuffer;
		size_t fileLengthRounded;
		for (int i = 0;i < numFiles;i++) {
			FILE* currentFile = fopen(fileTreeList[i]->name, "rb");
			fileLengthRounded = (fileTreeList[i]->size >> 5) * 32 + 32;
			currentFileBuffer.length = 0;
			currentFileBuffer.add(fileLengthRounded);
			if (!quiet) {std::cout << "Adding -> \"" << fileTreeList[i]->name << "\" to dataTree" << std::endl;};
			fread(currentFileBuffer.data, 1, fileTreeList[i]->size, currentFile);
			if (cfg->method == CRYPT256) {
				encryptBinaryBlob256(currentFileBuffer.data, fileLengthRounded, passwd.c_str(), fileTreeList[i]->salt);
			} else if (cfg->method == CRYPT128) {
				encryptBinaryBlob128(currentFileBuffer.data, fileLengthRounded, passwd.c_str(), fileTreeList[i]->salt);
			} else if (cfg->method == CRYPT64 || cfg->method == CRYPT65) {
				encryptBinaryBlob(currentFileBuffer.data, fileLengthRounded, passwd.c_str(), fileTreeList[i]->salt, cfg->method);
			}
			delete fileTreeList[i];
			fclose(currentFile);
			fwrite(currentFileBuffer.data, 1, fileLengthRounded, fout);
		}
	}
	fclose(fout);
	free(frontBuffer);
}

void createDirectoryFromArchive(const std::string& d, const std::string& passwd) {
	FILE* fptr = fopen(d.c_str(), "rb");
	if (fptr == NULL) {
		std::cerr << "No such file or directory" << std::endl;
		return;
	}	
	//fseek(fptr, 0L, 256);
	uint64_t initialBuffer[32];
	fread(initialBuffer, sizeof(uint64_t), 32, fptr);
	if (initialBuffer[4] < 131072) {
		fclose(fptr);
		createDirectoryFromArchiveLegacy14(d, passwd);
		return;
		
	}
	//size_t flength = ftell(fptr);
	rewind(fptr);
	uint64_t* buffer = (uint64_t*)malloc(initialBuffer[1]);

	if (!quiet) {std::cout << "Reading from \"" << d << "\"" << std::endl;};
	fread(buffer, 1, initialBuffer[1], fptr);
	
	
	uint64_t* nameTree = buffer + (buffer[0] >> 3);
	int method = (int)buffer[3];
	if (method == CRYPT64 || method == CRYPT65) {
		if (!quiet) {std::cout << "Decrypting nameTree..." << std::endl;};
		encryptBinaryBlob(nameTree, buffer[1] - buffer[0], passwd.c_str(), buffer[2], method);
	} else if (method == CRYPT128) {
		if (!quiet) {std::cout << "Decrypting nameTree... (128-bit)" << std::endl;};
		encryptBinaryBlob128(nameTree, buffer[1] - buffer[0], passwd.c_str(), buffer[2]);
	
	} else if (method == CRYPT256) {
		if (!quiet) {std::cout << "Decrypting nameTree... (256-bit)" << std::endl;};
		encryptBinaryBlob256(nameTree, buffer[1] - buffer[0], passwd.c_str(), buffer[2]);
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
			fileName.push((char*)(stack.top().offset+5));
			if (!quiet) {std::cout << "name: " << fileName.str << " Directory: " << stack.top().offset[1] << std::endl;};
			if (stack.top().offset[1] % 2 == 0) {
				FILE* tempfptr = fopen(fileName.str, "wb");
				if (tempfptr == NULL) {std::cerr << "ERROR: Could not open file!\n";};
				uint64_t* tempFileBuffer = (uint64_t*)malloc(stack.top().offset[3] + 32);
				fseek(fptr, stack.top().offset[2] + buffer[1], SEEK_SET);
				fread(tempFileBuffer, 1, (stack.top().offset[3] >> 5) * 32 + 32, fptr);

				switch (method) {
					case CRYPT64:
						encryptBinaryBlob(tempFileBuffer, stack.top().offset[3] + 7, passwd.c_str(), stack.top().offset[4], CRYPT64, 0);
						break;
					case CRYPT65:
						encryptBinaryBlob(tempFileBuffer, stack.top().offset[3] + 7, passwd.c_str(),  stack.top().offset[4], CRYPT65, 0);
						break;
					case CRYPT128:
						encryptBinaryBlob128(tempFileBuffer, stack.top().offset[3] + 15, passwd.c_str(), stack.top().offset[4], 0);
						break;
					case CRYPT256:
						encryptBinaryBlob256(tempFileBuffer, stack.top().offset[3] + 31, passwd.c_str(), stack.top().offset[4], 0);
						break;
				}

				if (!quiet) {std::cout << "Writing \"" << fileName.str << "\", length -> " << stack.top().offset[3] << " Bytes" << std::endl;};
				fwrite(tempFileBuffer, 1, stack.top().offset[3], tempfptr);
				fclose(tempfptr);
				free(tempFileBuffer);
				stack.top().offset+=stack.top().offset[0]>>3;
				stack.top().progress++;
			} else if (stack.top().offset[1] % 2 == 1) {
				rootPath.push((char*)(stack.top().offset + 5));
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
	fclose(fptr);
	free(buffer);
}


int main(int argc, char* argv[]) {
	vaultConfig cfg;
	cfg.method = CRYPT128;
	cfg.headless = false;
	cfg.noSymlink = true;
	std::cout << "Steamroller v2.1.0" << std::endl;
	//uint128_t num0;
	//uint128_t num1;
	//num0.add(0x123456789abcdeff);
	//num1.add(0xffedcba987654321);
	//num0.add(0xffed
	//num0.pow2();
	//num0.multiply(num1);
	//num0.multiply(num1);
	//num0.shiftRight8();
	//std::cout << std::hex << num0.data.d64[1] << ", " << num0.data.d64[0] << std::endl;
	std::string passwd;
	if (argc > 3) {
		for (int i = 3;i < argc;i++) {
			if (strcmp(argv[i], "--quiet") == 0 || strcmp(argv[i], "quiet") == 0) {quiet = 1;};
			if (strcmp(argv[i], "--c256") == 0 || strcmp(argv[i], "c256") == 0) {cfg.method = CRYPT256;};
			if (strcmp(argv[i], "--c65") == 0 || strcmp(argv[i], "c65") == 0) {cfg.method = CRYPT65;};
			if (strcmp(argv[i], "--c64") == 0 || strcmp(argv[i], "c64") == 0) {cfg.method = CRYPT64;};
			if (strcmp(argv[i], "--nocrypt") == 0 || strcmp(argv[i], "nocrypt") == 0) {cfg.method = NOCRYPT;};
			if (strcmp(argv[i], "--enable-symlinks") == 0 || strcmp(argv[i], "--enable-symlink") == 0 || strcmp(argv[i], "symlink") == 0) {cfg.noSymlink = false;};
		}
	} else if (argc < 2) {
		std::cout << "No arguments!" << std::endl;
		return 0;
	}
	if (strcmp(argv[1], "create") == 0 || strcmp(argv[1], "index") == 0) {
		if (argc < 3) {std::cerr << "Not enough arguments!" << std::endl;return -1;};
		std::string passwdConfirm;
		if (cfg.method != NOCRYPT) {
			std::cout << "Enter a password: ";
			#ifndef _WIN32
				system("stty -echo");
			#endif
			std::cin >> passwd;
			#ifndef _WIN32
				system("stty echo");
			#endif
			std::cout << std::endl << "Confirm password: ";
			
			#ifndef _WIN32
				system("stty -echo");
			#endif
			std::cin >> passwdConfirm;
			#ifndef _WIN32
				system("stty echo");
		#endif
		}
		if (passwd == passwdConfirm || cfg.method == NOCRYPT) {
			std::cout << std::endl;
			if (strcmp(argv[1], "index") == 0) {
				cfg.headless = true;
			}
			createArchiveFromDirectory(argv[2], passwd, &cfg);
		} else {
			std::cout << std::endl << "Passwords don't match!" << std::endl;
		}
	} else if (strcmp(argv[1], "extract") == 0) {
		if (argc < 3) {std::cerr << "Not enough arguments!" << std::endl;return -1;};
		uint64_t initialBuffer[32];
		FILE* fptr = fopen(argv[2], "rb");
		if (fptr == NULL) {
			std::cerr << "No such file or directory!" << std::endl;
			return -1;
		}
		fread(initialBuffer, sizeof(uint64_t), 32, fptr);
		fclose(fptr);
		if (initialBuffer[3] != NOCRYPT) {
			std::cout << "Enter a password: ";
			#ifndef _WIN32
				system("stty -echo");
			#endif
			std::cin >> passwd;
			#ifndef _WIN32
				system("stty echo");
			#endif
			std::cout << std::endl;
		}
		createDirectoryFromArchive(argv[2], passwd);

	} else if (strcmp(argv[1], "strip") == 0) {
		if (argc < 3) {std::cerr << "Not enough arguments!" << std::endl;return -1;};
		std::cout << "note: decrypt command only works for VAULT version <2.0.0" << std::endl;
		std::cout << "Enter a password: ";
		#ifndef _WIN32
			system("stty -echo");
		#endif
		std::cin >> passwd;
		#ifndef _WIN32
			system("stty echo");
		#endif
		std::cout << std::endl;
		decryptLegacyVault(argv[2], passwd);

	} else if (strcmp(argv[1], "benchmark") == 0) {
		uint64_t* buffer = (uint64_t*)malloc(8388608*sizeof(uint64_t));
		encryptBinaryBlob256(buffer, 8388608 * sizeof(uint64_t), "DHCIsTheBestProgrammer", 0xdeadbeef04222008, 1);
		//iencryptBinaryBlob256(buffer, 128 * sizeof(uint64_t), "DHCIsTheBestProgrammer", 0xdeadbeef04222008, 1);
		std::cout << "i5-14400F Scores ~450,000 (Lower = better)" << std::endl;
		for (int i = 0;i < 64;i++) {
			std::cout << std::hex << buffer[(i<<2) + 3] << ", " << buffer[(i<<2) + 2] << ", " << buffer[(i<<2) + 1] << ", " << buffer[i<<2] << std::endl;
			//std::cout << std::hex << ", " << buffer[(i<<1) + 1] << ", " << buffer[i<<1] << std::endl;
		}
		free(buffer);
	} else {
		if (argc < 3) {std::cerr << "Not enough arguments!" << std::endl;return -1;};
	}

	std::cout << "Hello World!" << std::endl;
	usleep(5000000);
	return 0;
}
