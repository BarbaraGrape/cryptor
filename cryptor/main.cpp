#pragma optimize("", off)

#include <iostream>
#include <string>
#include <fstream>
#include <stdexcept>
#include <vector>

#include <windows.h>
#include <stdint.h>

#include "crypt.h"

static const std::string cryptorFilename("C:/dev/test/notepad++.exe"); // till we don't get path from argv[]
static const std::string cryptorNewFilename("C:/dev/test/mineCrypted.exe");

static const uint32_t XOR_MASK = 242;

int file_size(std::ifstream& i_file)
{
	std::streampos fpos = i_file.tellg();
	i_file.seekg(0, std::ios::end);
	int fs = static_cast<int>(i_file.tellg());
	i_file.seekg(fpos);
	return fs;
}

int main(void)
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
		else
			sec_h++;

	//
#ifdef _DEBUG
#error Can't calcute correct difference of functions address
#endif
	uint32_t stub_size = reinterpret_cast<uint32_t>(end_point) - reinterpret_cast<uint32_t>(crypt_chunk);

	std::cout << stub_size << std::endl;

	crypt_chunk(buffer.data() + sec_h->PointerToRawData, sec_h->SizeOfRawData, XOR_MASK);

	int offset_free = sec_h->PointerToRawData + sec_h->Misc.VirtualSize; // where we can put our code

	uint32_t stub_rva = offset_free + 1;
	while (stub_rva % 16)
		stub_rva++;

	int gap = stub_rva - offset_free;
	//if (stub_size + gap > (sec_h->SizeOfRawData - sec_h->Misc.VirtualSize))
	//	throw std::runtime_error("No space to write stub");

	std::memset(buffer.data() + offset_free, 0, sec_h->SizeOfRawData - sec_h->Misc.VirtualSize);
	std::memcpy(buffer.data() + stub_rva, crypt_chunk, stub_size);

	//set stub correct params
	uint32_t new_entry_fn =  (stub_rva + reinterpret_cast<uint32_t>(new_entry_point) - reinterpret_cast<uint32_t>(crypt_chunk));
	int new_entry_point = new_entry_fn + sec_h->VirtualAddress - sec_h->PointerToRawData + opt_h->ImageBase + 8;
	std::memcpy(buffer.data() + new_entry_fn + 11, &new_entry_point, 4);
	int point_begin_chunk = opt_h->ImageBase + sec_h->VirtualAddress;
	std::memcpy(buffer.data() + new_entry_fn + 20, &point_begin_chunk, 4);
	std::memcpy(buffer.data() + new_entry_fn + 29, &XOR_MASK, 4);
	std::memcpy(buffer.data() + new_entry_fn + 34, &sec_h->Misc.VirtualSize, 4);

	
	int old_entry_point = opt_h->AddressOfEntryPoint + opt_h->ImageBase;
	std::memcpy(buffer.data() + new_entry_fn + 77, &old_entry_point, 4);
	
	//set new entry point
	opt_h->AddressOfEntryPoint	 = new_entry_fn + sec_h->VirtualAddress - sec_h->PointerToRawData;
	sec_h->Characteristics		|= 0xE0000060;
	sec_h->Misc.VirtualSize		+= gap + stub_size;

	// relocation
	IMAGE_DATA_DIRECTORY* data_reloc = &opt_h->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	data_reloc->Size = 0;
	data_reloc->VirtualAddress = NULL;
	// try to find relocation table
	bool found = false;
	IMAGE_SECTION_HEADER* reloc_h = reinterpret_cast<IMAGE_SECTION_HEADER*>(opt_h+1);
	for (int i = 0; i < nt_h->FileHeader.NumberOfSections; ++i)
		if (std::strcmp(reinterpret_cast<char*>(reloc_h->Name), ".reloc") == 0)
		{
			found = true;
			break;
		}
		else
		{
			reloc_h->Characteristics |= IMAGE_SCN_MEM_WRITE;
			reloc_h++;
		}
	if (!found)
		throw std::runtime_error("Can't find relocation table");

	int p_relocation = opt_h->ImageBase + reloc_h->VirtualAddress;
	std::memcpy(buffer.data() + new_entry_fn + 49, &p_relocation, 4);
	std::memcpy(buffer.data() + new_entry_fn + 62, &reloc_h->Misc.VirtualSize, 4);
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