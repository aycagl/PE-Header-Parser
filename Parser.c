#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <winhttp.h>
#include <sys/stat.h>
#include <time.h>
#include <wincrypt.h>
#include <ctype.h>
#include "cJSON.h" //for JSON parsing

#define MD5_DIGEST_LENGTH 16
#define SHA256_DIGEST_LENGTH 32
#define MIN_STRING_LENGTH 4  // minimum meaningful string length

#pragma comment(lib, "winhttp.lib")

void printError(const char* msg) {
	fprintf(stderr, "Error: %s\n", msg);
	exit(EXIT_FAILURE);
}

void calculateMD5(FILE* file, unsigned char* md5Digest) {
	HCRYPTPROV hProv = 0;
	HCRYPTPROV hHash = 0;
	BYTE buffer[1024];
	DWORD bytesRead = 0;

	if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
		printError("CryptAcquireContext failed.");
	}

	if (!CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash)) {
		printError("CryptCreateHash failed.");
	}

	while ((bytesRead = fread(buffer, 1, sizeof(buffer), file)) != 0) {
		if (!CryptHashData(hHash, buffer, bytesRead, 0)) {
			printError("CryptHashData failed.");
		}
	}

	DWORD md5Length = MD5_DIGEST_LENGTH;
	if (!CryptGetHashParam(hHash, HP_HASHVAL, md5Digest, &md5Length, 0)) {
		printError("CryptGetHashParam failed.");
	}

	CryptDestroyHash(hHash);
	CryptReleaseContext(hProv, 0);

}

void calculateSHA256(FILE* file, unsigned char* sha256Digest) {
	HCRYPTPROV hProv = 0;
	HCRYPTPROV hHash = 0;
	BYTE buffer[1024];
	DWORD bytesRead = 0;

	if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
		printError("CryptAcquireContext failed.");
	}

	if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
		printError("CryptCreateHash failed.");
	}

	while ((bytesRead = fread(buffer, 1, sizeof(buffer), file)) != 0) {
		if (!CryptHashData(hHash, buffer, bytesRead, 0)) {
			printError("CryptHashData failed.");
		}
	}

	DWORD sha256Length = SHA256_DIGEST_LENGTH;
	if (!CryptGetHashParam(hHash, HP_HASHVAL, sha256Digest, &sha256Length, 0)) {
		printError("CryptGetHashParam failed.");
	}

	CryptDestroyHash(hHash);
	CryptReleaseContext(hProv, 0);

}

void printFileInformation(const char* fileName, FILE* file, IMAGE_DOS_HEADER* dosHeader, IMAGE_OPTIONAL_HEADER* optionalHeader) {
	struct stat fileStat;
	char timeBuffer[26];

	if (stat(fileName, &fileStat) != 0) {
		printError("Could not retrieve file information.");
	}

	fseek(file, 0, SEEK_SET);
	unsigned char md5Digest[MD5_DIGEST_LENGTH];
	calculateMD5(file, md5Digest);

	fseek(file, 0, SEEK_SET);
	unsigned char sha256Digest[SHA256_DIGEST_LENGTH];
	calculateSHA256(file, sha256Digest);

	printf("----FILE INFORMATION----\n");
	printf("File name: %s\n", fileName);
	printf("File size: %1d bytes \n", fileStat.st_size);

	// Get the creation time
	if (ctime_s(timeBuffer, sizeof(timeBuffer), &fileStat.st_ctime) == 0) {
		printf("Creation time: %s", timeBuffer);
	}
	else {
		printf("Failed to retrieve creation time.\n");
	}

	// Get the last access time
	if (ctime_s(timeBuffer, sizeof(timeBuffer), &fileStat.st_atime) == 0) {
		printf("Last access time: %s", timeBuffer);
	}
	else {
		printf("Failed to retrieve last access time.\n");
	}

	// Get the last modification time
	if (ctime_s(timeBuffer, sizeof(timeBuffer), &fileStat.st_mtime) == 0) {
		printf("Last modification time: %s", timeBuffer);
	}
	else {
		printf("Failed to retrieve last modification time.\n");
	}

	printf("MD5 Hash: ");
	for (int i = 0; i < MD5_DIGEST_LENGTH; i++) {
		printf("%02x", md5Digest[i]);
	}
	printf("\n");

	printf("SHA256 Hash: ");
	for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
		printf("%02x", sha256Digest[i]);
	}
	printf("\n");

	printf("File type: ");
	switch (optionalHeader->Subsystem) {
	case IMAGE_SUBSYSTEM_WINDOWS_GUI: printf("Windows GUI\n"); break;
	case IMAGE_SUBSYSTEM_WINDOWS_CUI: printf("Windows Console\n"); break;
	default: printf("Unknown \n"); break;
	}
	printf("Timestamp: 0x%x\n\n", fileStat.st_mtime);
}

void printDosHeader(IMAGE_DOS_HEADER* dosHeader) {
	printf("----IMAGE_DOS_HEADER----\n");
	printf("Magic number: 0x%x\n", dosHeader->e_magic);
	printf("Count of bytes on last page: 0x%x\n", dosHeader->e_cblp);
	printf("Count of pages: 0x%x\n", dosHeader->e_cp);
	printf("Count of relocations: 0x%x\n", dosHeader->e_crlc);
	printf("Size of header in paragraphs: 0x%x\n", dosHeader->e_cparhdr);
	printf("Minimum extra paragraphs needed: 0x%x\n", dosHeader->e_minalloc);
	printf("Maximum extra paragraphs needed: 0x%x\n", dosHeader->e_maxalloc);
	printf("Initial SS value: 0x%x\n", dosHeader->e_ss);
	printf("Initial SP value: 0x%x\n", dosHeader->e_sp);
	printf("Checksum: 0x%x\n", dosHeader->e_csum);
	printf("Initial IP value: 0x%x\n", dosHeader->e_ip);
	printf("Initial CS value: 0x%x\n", dosHeader->e_cs);
	printf("File address of relocation table: 0x%x\n", dosHeader->e_lfarlc);
	printf("Overlay number: 0x%x\n", dosHeader->e_ovno);
	printf("Reserved: 0x%x\n", dosHeader->e_res[4]);
	printf("OEM identifier: 0x%x\n", dosHeader->e_oemid);
	printf("OEM information: 0x%x\n", dosHeader->e_oeminfo);
	printf("Second reserved: 0x%x\n", dosHeader->e_res2[10]);
	printf("Address of NT headers: 0x%x\n\n", dosHeader->e_lfanew);
}

void printFileHeader(IMAGE_FILE_HEADER* fileHeader) {
	printf("----IMAGE_FILE_HEADER----\n");
	printf("Machine: 0x%x\n", fileHeader->Machine);
	printf("Number of Sections: %d\n", fileHeader->NumberOfSections);
	printf("TimeDateStamp: 0x%x\n", fileHeader->TimeDateStamp);
	printf("Pointer to Symbol Table: 0x%x\n", fileHeader->PointerToSymbolTable);
	printf("Number of Symbols: %d\n", fileHeader->NumberOfSymbols);
	printf("Size of Optional Header: %d\n", fileHeader->SizeOfOptionalHeader);
	printf("Characteristics: 0x%x\n\n", fileHeader->Characteristics);
}

void printOptionalHeader(IMAGE_OPTIONAL_HEADER* optionalHeader) {
	printf("---- IMAGE_OPTIONAL_HEADER ----\n");
	printf("Magic: 0x%x\n", optionalHeader->Magic);
	printf("Major linker version: 0x%x\n", optionalHeader->MajorLinkerVersion);
	printf("Minor linker version: 0x%x\n", optionalHeader->MinorLinkerVersion);
	printf("Size of code: 0x%x\n", optionalHeader->SizeOfCode);
	printf("Size of initialized data: 0x%x\n", optionalHeader->SizeOfInitializedData);
	printf("Size of uninitialized data: 0x%x\n", optionalHeader->SizeOfUninitializedData);
	printf("Address of entry point: 0x%x\n", optionalHeader->AddressOfEntryPoint);
	printf("Base of code: 0x%x\n", optionalHeader->BaseOfCode);
	printf("Image Base: 0x%x\n", optionalHeader->ImageBase);
	printf("Section Alignment: 0x%x\n", optionalHeader->SectionAlignment);
	printf("File Alignment: 0x%x\n", optionalHeader->FileAlignment);
	printf("Major Operating System Version: 0x%x\n", optionalHeader->MajorOperatingSystemVersion);
	printf("Minor Operating System Version 0x%x\n", optionalHeader->MinorOperatingSystemVersion);
	printf("Major Image Version: 0x%x\n", optionalHeader->MajorImageVersion);
	printf("Minor Image Version: 0x%x\n", optionalHeader->MinorImageVersion);
	printf("Major Subsystem Version: 0x%x\n", optionalHeader->MajorSubsystemVersion);
	printf("Minor Subsystem Version: 0x%x\n", optionalHeader->MinorSubsystemVersion);
	printf("Win32 Version Value: 0x%x\n", optionalHeader->Win32VersionValue);
	printf("Size Of Image: 0x%x\n", optionalHeader->SizeOfImage);
	printf("Size Of Headers: 0x%x\n", optionalHeader->SizeOfHeaders);
	printf("CheckSum: 0x%x\n", optionalHeader->CheckSum);
	printf("Subsystem: 0x%x\n", optionalHeader->Subsystem);
	printf("Dll Characteristics: 0x%x\n", optionalHeader->DllCharacteristics);
	printf("Size Of Stack Reserve: 0x%x\n", optionalHeader->SizeOfStackReserve);
	printf("Size Of Stack Commit: 0x%x\n", optionalHeader->SizeOfStackCommit);
	printf("Size Of Heap Reserve: 0x%x\n", optionalHeader->SizeOfHeapReserve);
	printf("Size Of Heap Commit: 0x%x\n", optionalHeader->SizeOfHeapCommit);
	printf("Loader Flags: 0x%x\n", optionalHeader->LoaderFlags);
	printf("Number Of Rva And Sizes: 0x%x\n\n", optionalHeader->NumberOfRvaAndSizes);

	printf("----DATA DIRECTORIES----\n");
	const char* dataDirectoryNames[] = {
		"Export Table",
		"Import Table",
		"Resource Table",
		"Exception Table",
		"Certificate Table",
		"Base Relocation Table",
		"Debug Directory",
		"Architecture Data",
		"Global Pointer",
		"TLS Table",
		"Load Config Table",
		"Bound Import",
		"Import Address Table",
		"Delay Import Descriptor",
		"CLR Runtime Header",
		"Reserved"
	};
	for (int i = 0; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; i++) {
		printf("%s: \n", dataDirectoryNames[i]);
		printf(" Virtual Address: 0x%x\n", optionalHeader->DataDirectory[i].VirtualAddress);
		printf(" Size: 0x%x\n", optionalHeader->DataDirectory[i].Size);
	}
	printf("\n");
}

void printSectionHeaders(IMAGE_SECTION_HEADER* sectionHeaders, int numberOfSections) {
	printf("---- IMAGE_SECTION_HEADERS ----\n");
	for (int i = 0; i < numberOfSections; i++) {
		printf("Section %d:\n", i + 1);
		printf(" Name: %.8s\n", sectionHeaders[i].Name); // Name can be max 8 characters long 
		printf(" Virtual size: 0x%x\n", sectionHeaders[i].Misc.VirtualSize);
		printf(" Physical address: 0x%x\n", sectionHeaders[i].Misc.PhysicalAddress); 
		printf(" Virtual address: 0x%x\n", sectionHeaders[i].VirtualAddress);
		printf(" Size of raw data: 0x%x\n", sectionHeaders[i].SizeOfRawData);
		printf(" Pointer to raw data: 0x%x\n", sectionHeaders[i].PointerToRawData);
		printf(" Pointer to relocations: 0x%x\n", sectionHeaders[i].PointerToRelocations);
		printf(" Pointer to line numbers: 0x%x\n", sectionHeaders[i].PointerToLinenumbers);
		printf(" Number of relocations: 0x%x\n", sectionHeaders[i].NumberOfRelocations);
		printf(" Number of line numbers: 0x%x\n", sectionHeaders[i].NumberOfLinenumbers);
		printf(" Characteristics: 0x%x\n\n", sectionHeaders[i].Characteristics);
	}
}

void printImportTable(FILE* file, IMAGE_DATA_DIRECTORY* importDir, IMAGE_OPTIONAL_HEADER* optionalHeader, IMAGE_SECTION_HEADER* sectionHeaders, int numberOfSections) {
	// RVA to file offset translation for the Import Table
	DWORD importTableOffset = RvaToOffset(importDir->VirtualAddress, sectionHeaders, numberOfSections);

	// Check if the offset is valid
	if (importTableOffset == 0) {
		printf("Invalid Import Table RVA: 0x%X\n", importDir->VirtualAddress);
		return;
	}

	fseek(file, importTableOffset, SEEK_SET);
	printf("----IMPORT TABLE----\n");

	IMAGE_IMPORT_DESCRIPTOR importDesc;

	while (1) {
		fread(&importDesc, sizeof(IMAGE_IMPORT_DESCRIPTOR), 1, file);
		if (importDesc.Name == 0) {
			break;  // End of import descriptors
		}

		// Get DLL name from import descriptor
		DWORD nameRVA = importDesc.Name;
		DWORD nameOffset = RvaToOffset(nameRVA, sectionHeaders, numberOfSections);

		if (nameOffset == 0) {
			printf("Invalid DLL name offset for import descriptor.\n");
			printf("Import Descriptor Name RVA: 0x%X\n", importDesc.Name);
			continue;
		}

		// Save current file position and seek to the DLL name offset
		DWORD currentPos = ftell(file);
		fseek(file, nameOffset, SEEK_SET);

		char dllName[256] = { 0 };
		fread(dllName, sizeof(char), 255, file);  // Read up to 255 bytes for the DLL name
		dllName[255] = '\0';  // Null-terminate to avoid buffer overflow

		printf("DLL Name: %s\n", dllName);

		// Restore the file position after reading DLL name
		fseek(file, currentPos, SEEK_SET);

		// Process the functions in the DLL (thunks)
		DWORD thunkRVA = importDesc.OriginalFirstThunk ? importDesc.OriginalFirstThunk : importDesc.FirstThunk;
		DWORD thunkOffset = RvaToOffset(thunkRVA, sectionHeaders, numberOfSections);
		if (thunkOffset == 0) {
			printf("Invalid thunk offset.\n");
			continue;
		}

		fseek(file, thunkOffset, SEEK_SET);
		IMAGE_THUNK_DATA thunkData;

		while (1) {
			fread(&thunkData, sizeof(IMAGE_THUNK_DATA), 1, file);
			if (thunkData.u1.Function == 0) {
				break;  // No more functions
			}

			// Check if it's an ordinal or a function name
			if (thunkData.u1.Ordinal & IMAGE_ORDINAL_FLAG32) {
				printf("  Ordinal: %u\n", thunkData.u1.Ordinal & 0xFFFF);
			}
			else {
				// Fetch function names
				DWORD functionNameRVA = thunkData.u1.AddressOfData;
				DWORD functionNameOffset = RvaToOffset(functionNameRVA, sectionHeaders, numberOfSections);

				if (functionNameOffset == 0) {
					printf("Invalid function name offset.\n");
					continue;
				}

				// Skip the hint (first two bytes)
				functionNameOffset += 2;
				currentPos = ftell(file);
				fseek(file, functionNameOffset, SEEK_SET);

				char functionName[256] = { 0 };
				fread(functionName, sizeof(char), 255, file);  // Read up to 255 bytes
				functionName[255] = '\0';  // Null-terminate

				printf("  Function: %s\n", functionName);
				fseek(file, currentPos, SEEK_SET);
			}
		}

		// Move to the next IMAGE_IMPORT_DESCRIPTOR
		importTableOffset += sizeof(IMAGE_IMPORT_DESCRIPTOR);
		fseek(file, importTableOffset, SEEK_SET);
	}
}

DWORD RvaToOffset(DWORD rva, IMAGE_SECTION_HEADER* sectionHeaders, int numberOfSections) {
	for (int i = 0; i < numberOfSections; i++) {
		DWORD sectionStart = sectionHeaders[i].VirtualAddress;
		DWORD sectionSize = sectionHeaders[i].SizeOfRawData;
		DWORD sectionEnd = sectionStart + sectionSize;

		if (rva >= sectionStart && rva < sectionEnd) {
			return rva - sectionStart + sectionHeaders[i].PointerToRawData;
		}
	}
	return 0;
}

void hexDump(const char* fileName) {
	FILE* fp;
	int i, c, offset = 0;
	unsigned char buffer[16];  // 16 bytes per line
	size_t bytesRead;

	// 1. Open the file in binary mode
	errno_t err = fopen_s(&fp, fileName, "rb");
	if (err != 0 || fp == NULL) {
		printf("Error: Could not open file %s\n", fileName);
		return;
	}

	printf("Offset     Hexadecimal Data                                ASCII Representation\n");
	printf("---------------------------------------------------------------------------------\n");

	// 2. Read the file in 16-byte chunks and process
	while ((bytesRead = fread(buffer, 1, sizeof(buffer), fp)) > 0) {
		// 3. Print the offset
		printf("%08x  ", offset);

		// 4. Print the hex data with better alignment
		for (i = 0; i < 16; i++) {
			if (i < bytesRead) {
				printf("%02x ", buffer[i]);
			}
			else {
				printf("   ");  // If the line is short, fill with spaces
			}

			if (i == 7) {
				printf(" ");  // Add extra space between the first and second half of the hex output
			}
		}

		// 5. Print the ASCII representation with borders
		printf(" |");
		for (i = 0; i < bytesRead; i++) {
			c = buffer[i];
			printf("%c", (c >= 32 && c <= 126) ? c : '.');  // Print readable ASCII characters or dots for non-printables
		}
		printf("|\n");

		// 6. Update the offset
		offset += 16;
	}

	// 7. Close the file
	fclose(fp);
}

void printStrings(const char* fileName) {
	FILE* fp;
	unsigned char buffer[32];
	size_t bytesRead;
	int i, c;
	char tempString[256];  // Temporary buffer to store potential strings
	int tempIndex = 0;     // Index for tempString

	// Open file
	errno_t err = fopen_s(&fp, fileName, "rb");
	if (err != 0 || fp == NULL) {
		printf("Error: Could not open file %s\n", fileName);
		return;
	}

	// Reading file and finding strings
	while ((bytesRead = fread(buffer, 1, sizeof(buffer), fp)) > 0) {
		for (i = 0; i < bytesRead; i++) {
			c = buffer[i];
			// Check if the character is a printable ASCII letter
			if (isprint(c)) {
				// Add to temporary string buffer
				tempString[tempIndex++] = c;

				// Prevent buffer overflow
				if (tempIndex >= sizeof(tempString) - 1) {
					tempString[tempIndex] = '\0';  // Null-terminate
					if (strlen(tempString) >= MIN_STRING_LENGTH) {
						printf("%s\n", tempString);
					}
					tempIndex = 0;
				}
			}
			else {
				// If non-printable character encountered, check the length of the tempString
				if (tempIndex >= MIN_STRING_LENGTH) {
					tempString[tempIndex] = '\0';  // Null-terminate
					printf("%s\n", tempString);
				}
				tempIndex = 0;  // Reset tempString
			}
		}
	}

	// If there's any leftover string after the loop
	if (tempIndex >= MIN_STRING_LENGTH) {
		tempString[tempIndex] = '\0';
		printf("%s\n", tempString);
	}

	fclose(fp);
}

void parseJsonResponse(const char* response) {
	// JSON parsing for JSON response
	cJSON* json = cJSON_Parse(response);
	if (json == NULL) {
		printf("Error parsing JSON response.\n");
		return;
	}

	// Finding scans in Virustotal API response
	cJSON* scans = cJSON_GetObjectItemCaseSensitive(json, "scans");
	if (scans == NULL) {
		printf("No scans data found in the response.\n");
		cJSON_Delete(json);
		return;
	}

	printf("Antivirus detections:\n");
	printf("\n");

	// iterate over each antivirus detection within scans
	cJSON* scanItem = NULL;
	cJSON_ArrayForEach(scanItem, scans) {
		// Antivirus name
		const char* antivirusName = scanItem->string;

		// AV detection response
		cJSON* detected = cJSON_GetObjectItemCaseSensitive(scanItem, "detected");
		cJSON* result = cJSON_GetObjectItemCaseSensitive(scanItem, "result");

		// if detected
		if (cJSON_IsBool(detected) && cJSON_IsTrue(detected)) {
			if (result != NULL && result->valuestring != NULL) {
				printf("Antivirus: %20.40s,  Result: %40.40s\n", antivirusName, result->valuestring);
			}
			else {
				printf("Antivirus: %s,  Result: (unknown)", antivirusName);
			}
		}
	}
	printf("\n");
	printf("Antivirus detections (Undetected):\n");
	printf("\n");

	cJSON_ArrayForEach(scanItem, scans) {
		const char* antivirusName = scanItem->string;

		cJSON* detected = cJSON_GetObjectItemCaseSensitive(scanItem, "detected");

		// if not detected
		if (cJSON_IsBool(detected) && cJSON_IsFalse(detected)) {

			printf("Antivirus: %20.40s,  Result: Clean\n", antivirusName);

		}
	}

	// cleary memory
	cJSON_Delete(json);
}

void queryVirusTotal(const char* apiKey, const char* hash) {
	HINTERNET hSession = WinHttpOpen(L"VirusTotalHashQuery/1.0",
		WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
		WINHTTP_NO_PROXY_NAME,
		WINHTTP_NO_PROXY_BYPASS, 0);
	if (!hSession) {
		printf("WinHttpOpen failed with error: %ld\n", GetLastError());
		return;
	}

	HINTERNET hConnect = WinHttpConnect(hSession, L"www.virustotal.com",
		INTERNET_DEFAULT_HTTPS_PORT, 0);
	if (!hConnect) {
		printf("WinHttpConnect failed with error: %ld\n", GetLastError());
		WinHttpCloseHandle(hSession);
		return;
	}

	wchar_t urlPath[512];
	swprintf(urlPath, 512, L"/vtapi/v2/file/report?apikey=%hs&resource=%hs", apiKey, hash);

	HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", urlPath, NULL,
		WINHTTP_NO_REFERER,
		WINHTTP_DEFAULT_ACCEPT_TYPES,
		WINHTTP_FLAG_SECURE);
	if (!hRequest) {
		printf("WinHttpOpenRequest failed with error: %ld\n", GetLastError());
		WinHttpCloseHandle(hConnect);
		WinHttpCloseHandle(hSession);
		return;
	}

	if (!WinHttpSendRequest(hRequest,
		WINHTTP_NO_ADDITIONAL_HEADERS, 0,
		WINHTTP_NO_REQUEST_DATA, 0,
		0, 0)) {
		printf("WinHttpSendRequest failed with error: %ld\n", GetLastError());
		WinHttpCloseHandle(hRequest);
		WinHttpCloseHandle(hConnect);
		WinHttpCloseHandle(hSession);
		return;
	}

	if (!WinHttpReceiveResponse(hRequest, NULL)) {
		printf("WinHttpReceiveResponse failed with error: %ld\n", GetLastError());
		WinHttpCloseHandle(hRequest);
		WinHttpCloseHandle(hConnect);
		WinHttpCloseHandle(hSession);
		return;
	}

	DWORD dwSize = 0;
	DWORD dwDownloaded = 0;
	char* jsonResponse = NULL;  // Initialize to NULL
	size_t jsonResponseSize = 0;  // Track the size of the buffer

	do {
		dwSize = 0;
		if (!WinHttpQueryDataAvailable(hRequest, &dwSize)) {
			printf("WinHttpQueryDataAvailable failed with error: %ld\n", GetLastError());
			break;
		}

		/*if (dwSize == 0) {
			printf("No data available to read.\n");
			break;
		}*/

		char* pszOutBuffer = (char*)malloc(dwSize + 1);
		if (!pszOutBuffer) {
			printf("Out of memory\n");
			dwSize = 0;
		}
		else {
			ZeroMemory(pszOutBuffer, dwSize + 1);
			if (!WinHttpReadData(hRequest, (LPVOID)pszOutBuffer, dwSize, &dwDownloaded)) {
				printf("WinHttpReadData failed with error: %ld\n", GetLastError());
			}
			else {
				// Print the size of data read
				/*printf("Data read size: %lu\n", dwDownloaded);*/

				// If jsonResponse is NULL, allocate initial buffer
				if (jsonResponse == NULL) {
					jsonResponse = (char*)malloc(dwSize + 1);
					if (jsonResponse) {
						jsonResponseSize = dwSize + 1;
						strcpy_s(jsonResponse, jsonResponseSize, pszOutBuffer);
					}
				}
				else {
					// Reallocate buffer to accommodate new data
					char* temp = (char*)realloc(jsonResponse, jsonResponseSize + dwSize);
					if (temp) {
						jsonResponse = temp;
						jsonResponseSize += dwSize;
						strcat_s(jsonResponse, jsonResponseSize, pszOutBuffer);
					}
				}
			}
			free(pszOutBuffer);
		}
	} while (dwSize > 0);

	if (jsonResponse != NULL) {
		// Print the final JSON response for debugging
		/*printf("Final JSON Response: %s\n", jsonResponse);*/
		parseJsonResponse(jsonResponse);  // pass the full accumulated response
		free(jsonResponse);  // free the allocated memory
	}
	else {
		printf("No response received from VirusTotal.\n");
	}

	WinHttpCloseHandle(hRequest);
	WinHttpCloseHandle(hConnect);
	WinHttpCloseHandle(hSession);
}

// Function to convert binary hash to a hexadecimal string
void hashToHexString(unsigned char* hash, char* hexStr, size_t hexStrSize) {
	for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
		snprintf(hexStr + (i * 2), hexStrSize - (i * 2), "%02x", hash[i]);
	}
	hexStr[hexStrSize - 1] = '\0';  // Ensure null-termination
}

int main(int argc, char* argv[]) {
	if (argc != 2) {
		printError("Usage: parser.exe <path_to_pe_file>");
		return 1;
	}

	const char* apiKey = "cc0181eac3a5c2fc232a95deb529ebb78c74fe55e359fe41f0263e27892bfc1e";
	const char* filePath = argv[1];

	// Open the file to calculate the hash
	FILE* file = fopen(filePath, "rb");
	if (!file) {
		printf("Failed to open file: %s\n", filePath);
		return 1;
	}

	// Calculate the SHA256 hash
	unsigned char sha256Digest[SHA256_DIGEST_LENGTH];
	calculateSHA256(file, sha256Digest);

	// Convert the hash to a hexadecimal string
	char fileHash[SHA256_DIGEST_LENGTH * 2 + 1];
	hashToHexString(sha256Digest, fileHash, sizeof(fileHash));

	// Close the file
	fclose(file);

	//FILE* file;
	errno_t err = fopen_s(&file, argv[1], "rb");
	if (err != 0 || file == NULL) {
		printError("Could not open the specified file.");
	}

	IMAGE_DOS_HEADER dosHeader;
	fread(&dosHeader, sizeof(IMAGE_DOS_HEADER), 1, file);

	if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE) {
		fclose(file);
		printError("Not a valid PE file.");
	}


	fseek(file, dosHeader.e_lfanew, SEEK_SET);

	DWORD ntHeadersSignature;
	fread(&ntHeadersSignature, sizeof(DWORD), 1, file);

	if (ntHeadersSignature != IMAGE_NT_SIGNATURE) {
		fclose(file);
		printError("Invalid NT Headers signature.");
	}

	IMAGE_FILE_HEADER fileHeader;
	fread(&fileHeader, sizeof(IMAGE_FILE_HEADER), 1, file);


	IMAGE_OPTIONAL_HEADER optionalHeader;
	fread(&optionalHeader, sizeof(IMAGE_OPTIONAL_HEADER), 1, file);

	IMAGE_SECTION_HEADER* sectionHeaders = malloc(fileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER)); //dynamically memory allocation
	fread(sectionHeaders, sizeof(IMAGE_SECTION_HEADER), fileHeader.NumberOfSections, file);

	fseek(file, 0, SEEK_SET);  // Reset the file pointer to the beginning

	int choice;
	while (1) {
		printf("-----------------------------------------------------------------\n");
		printf("Please select an option.\n");
		printf("	1.  Print File Information\n");
		printf("	2.  Print DOS Header\n");
		printf("	3.  Print NT Header Signature\n");
		printf("	4.  Print File Header\n");
		printf("	5.  Print Optional Header\n");
		printf("	6.  Print Section Headers\n");
		printf("	7.  Print Import Table\n");
		printf("	8.  Hex Dump\n");
		printf("	9.  Strings\n");
		printf("	10. VirusTotal Hash Query\n");
		printf("	0.  Exit\n");
		printf("Enter your choice: ");
		scanf_s("%d", &choice);
		printf("-----------------------------------------------------------------\n");
		printf("\n");

		switch (choice) {
		case 1:
			printFileInformation(argv[1], file, &dosHeader, &optionalHeader);
			break;
		case 2:
			printDosHeader(&dosHeader);
			break;
		case 3:
			printf("NT Header Signature: 0x%x\n\n", ntHeadersSignature);
			break;
		case 4:
			printFileHeader(&fileHeader);
			break;
		case 5:
			printOptionalHeader(&optionalHeader);
			break;
		case 6:
			// Seek to the correct position with fseek before reading IMAGE_SECTION_HEADERS
			fseek(file, dosHeader.e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + fileHeader.SizeOfOptionalHeader, SEEK_SET);

			fread(sectionHeaders, sizeof(IMAGE_SECTION_HEADER), fileHeader.NumberOfSections, file);

			printSectionHeaders(sectionHeaders, fileHeader.NumberOfSections);
			break;
		case 7:
			printImportTable(file, &optionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT], &optionalHeader, sectionHeaders, fileHeader.NumberOfSections);
			break;
		case 8:
			hexDump(argv[1]);
			break;
		case 9:
			printStrings(argv[1]);
			break;
		case 10:
			queryVirusTotal(apiKey, fileHash);
			break;
		case 0:
			printf("Exiting...\n");
			free(sectionHeaders);
			fclose(file);
			return 0;
		default:
			printf("Invalid choice. Please try again.\n");
		}
		printf("\n");
	}
}
