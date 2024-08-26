#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <sys/stat.h>
#include <time.h>
#include <wincrypt.h>
#include <ctype.h>

#define MD5_DIGEST_LENGTH 16


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

	while ((bytesRead = fread(buffer, 1, 1024, file)) != 0) {
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

void printFileInformation(const char* fileName, FILE* file, IMAGE_DOS_HEADER* dosHeader, IMAGE_OPTIONAL_HEADER* optionalHeader) {
	struct stat fileStat;
	char timeBuffer[26];

	if (stat(fileName, &fileStat) != 0) {
		printError("Could not retrieve file information.");
	}

	fseek(file, 0, SEEK_SET);
	unsigned char md5Digest[MD5_DIGEST_LENGTH];
	calculateMD5(file, md5Digest);

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

//void printDosStub(FILE* file, LONG stubSize) {
//	BYTE* stubData = (BYTE*)malloc(stubSize);
//	if (stubData == NULL) {
//		printf("Memory allocation error.\n");
//		return;
//	}
//
//	fseek(file, sizeof(IMAGE_DOS_HEADER), SEEK_SET);
//	fread(stubData, 1, stubSize, file);
//
//	printf("----DOS STUB----\n");
//	for (LONG i = 0; i < stubSize; i++) {
//		printf("%02X", stubData[i]);
//		if ((i + 1) % 16 == 0) {
//			printf("\n");
//		}
//	}
//	printf("\n\n");
//	free(stubData);
//}

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
		printf(" Name: %.8s\n", sectionHeaders[i].Name);
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
	if (importDir->VirtualAddress == 0) {
		printf("No import table found.\n");
		return;
	}
	//To read the data from the file, RVA must be converted to a file offset 
	DWORD importTableOffset = RvaToOffset(importDir->VirtualAddress, sectionHeaders, numberOfSections);
	fseek(file, importTableOffset, SEEK_SET);

	printf("----IMPORT TABLE----\n");
	IMAGE_IMPORT_DESCRIPTOR importDesc;

	while (1) {
		fread(&importDesc, sizeof(IMAGE_IMPORT_DESCRIPTOR), 1, file);
		if (importDesc.Name == 0) {
			break;
		}

		DWORD nameRVA = importDesc.Name;  // Get the RVA of the DLL name
		DWORD nameOffset = RvaToOffset(nameRVA, sectionHeaders, numberOfSections);

		// Save the current file position before seeking to the DLL name
		DWORD currentPos = ftell(file);
		fseek(file, nameOffset, SEEK_SET);

		char dllName[256] = { 0 }; //clear dllName array 
		fread(dllName, sizeof(char), 256, file);
		printf("DLL Name: %s\n", dllName);

		// Restore the file position to continue reading the import descriptor
		fseek(file, currentPos, SEEK_SET);
	}
}


//function to translate RVA to file offset
DWORD RvaToOffset(DWORD rva, IMAGE_SECTION_HEADER* sectionHeaders, int numberOfSections) {
	for (int i = 0; i < numberOfSections; i++) {
		if (rva >= sectionHeaders[i].VirtualAddress &&
			rva < sectionHeaders[i].VirtualAddress + sectionHeaders[i].Misc.VirtualSize) //converts the RVA to file offset
		{
			return rva - sectionHeaders[i].VirtualAddress + sectionHeaders[i].PointerToRawData;
		}
	}
	return 0;  // If RVA dosen't match with any offset, return 0
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
			// Letter check (ASCII)
			if (c != '\0' && (c >= 65 && c <= 90) || (c >= 97 && c <= 122)) {
				printf("%c", c);
			}
		}
	}

	fclose(fp);
}

int main(int argc, char* argv[]) {
	if (argc != 2) {
		printError("Usage: parser.exe <path_to_pe_file>");
	}

	FILE* file;
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

	/*LONG dosStubSize = dosHeader.e_lfanew - sizeof(IMAGE_DOS_HEADER);
	printDosStub(file, dosStubSize);*/

	IMAGE_FILE_HEADER fileHeader;
	fread(&fileHeader, sizeof(IMAGE_FILE_HEADER), 1, file);


	IMAGE_OPTIONAL_HEADER optionalHeader;
	fread(&optionalHeader, sizeof(IMAGE_OPTIONAL_HEADER), 1, file);

	IMAGE_SECTION_HEADER* sectionHeaders = malloc(fileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER)); //dynamically memory allocation
	fread(sectionHeaders, sizeof(IMAGE_SECTION_HEADER), fileHeader.NumberOfSections, file);

	int choice;
	while (1) {
		printf("Please select an option.\n");
		printf("	1. Print File Information\n");
		printf("	2. Print DOS Header\n");
		printf("	3. Print NT Header Signature\n");
		printf("	4. Print File Header\n");
		printf("	5. Print Optional Header\n");
		printf("	6. Print Section Headers\n");
		printf("	7. Print Import Table\n");
		printf("	8. Hex Dump\n");
		printf("	9. Strings\n");
		printf("	0. Exit\n");

		printf("Enter your choice: ");
		scanf_s("%d", &choice);
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




