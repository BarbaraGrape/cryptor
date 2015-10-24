#include <iostream>
#include <string>
#include <fstream>
#include <stdexcept>
#include <vector>

#include <windows.h>
#include <stdint.h>

#include "crypt.h"

static const std::string cryptorFilename("C:/dev/test/mine.exe"); // till we don't get path from argv[]
static const std::string cryptorNewFilename("C:/dev/test/mineCrypted.exe");

static const uint8_t XOR_MASK = 242;

int file_size(std::ifstream& i_file)
{
	std::streampos fpos = i_file.tellg();
	i_file.seekg(0, std::ios::end);
	int fs = static_cast<int>(i_file.tellg());
	i_file.seekg(fpos);
	return fs;
}

int main()
try
{
	std::ifstream i_file(cryptorFilename, std::ifstream::binary);
	if (i_file.fail())
		throw std::runtime_error("Failed to open file");

	int fs = file_size(i_file);
	
	std::vector<uint8_t> buffer(fs); 
	i_file.read(reinterpret_cast<char*>(buffer.data()), fs);

	IMAGE_DOS_HEADER* dos_h = reinterpret_cast<IMAGE_DOS_HEADER*>(buffer.data());
	if (dos_h->e_magic != IMAGE_DOS_SIGNATURE) // first test is this file true PE?
		throw std::runtime_error("This file is not DOS");

	IMAGE_NT_HEADERS* nt_h = reinterpret_cast<IMAGE_NT_HEADERS*>(&buffer[dos_h->e_lfanew]);
	if (nt_h->Signature != IMAGE_NT_SIGNATURE)
		throw std::runtime_error("This file is not PE");

	if ((nt_h->FileHeader.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE) == 0)
		throw std::runtime_error("This isn't executable file"); // only for exe yet

	IMAGE_OPTIONAL_HEADER* opt_h = &nt_h->OptionalHeader;
	if (opt_h->Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC)
		throw std::runtime_error("This file isn't 32 bit"); 

	IMAGE_SECTION_HEADER* sec_h = reinterpret_cast<IMAGE_SECTION_HEADER*>(opt_h+1);
	for (int i = 0; i < nt_h->FileHeader.NumberOfSections; ++i)
		if (sec_h->Characteristics & IMAGE_SCN_CNT_CODE)
			break;
	// crypt code section
	crypt_chunk(buffer.data() + sec_h->PointerToRawData, sec_h->SizeOfRawData, XOR_MASK);

	//open file for output 
	std::ofstream o_file(cryptorNewFilename, std::ofstream::binary | std::ofstream::out | std::ofstream::trunc);
	o_file.write(reinterpret_cast<char*>(buffer.data()), fs);

	std::cout << "OK!\n";

	return 0;
}
catch (std::exception& e)
{
	std::cout << "Exception: " << e.what() << std::endl;

	return 1;
}