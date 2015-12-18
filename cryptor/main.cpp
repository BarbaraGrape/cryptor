#pragma optimize("", off)

#include <iostream>
#include <string>
#include <fstream>
#include <stdexcept>
#include <vector>

#include <windows.h>
#include <stdint.h>

#include "crypt.h"

static const std::string cryptorFilename("C:/dev/test/minimal.exe"); // till we don't get path from argv[]
static const std::string cryptorNewFilename("C:/dev/test/crypted.exe");

static const uint32_t XOR_MASK = 242;

static void wait_for_input()
{
	system("PAUSE");
}
inline uint32_t get_fn_ptr(void* fn)
{
	return reinterpret_cast<uint32_t>(fn);
}

int file_size(std::ifstream& i_file)
{
	std::streampos fpos = i_file.tellg();
	i_file.seekg(0, std::ios::end);
	int fs = static_cast<int>(i_file.tellg());
	i_file.seekg(fpos);
	return fs;
}
int align(int begin, int alignment)
{
	int off = begin % alignment;
	if (!off)
		return begin;
	else
		return begin + alignment - off;
}
IMAGE_SECTION_HEADER* get_code_section(IMAGE_NT_HEADERS* nt_h) // find first code section
{ //return null if can't find code_section
	if (nt_h == NULL)
		return NULL;
	void *p = nt_h + 1;
	IMAGE_SECTION_HEADER* sec = static_cast<IMAGE_SECTION_HEADER*>(p);
	bool found = false;

	for (int i = 0; i < nt_h->FileHeader.NumberOfSections; ++i)
		if (sec->Characteristics & IMAGE_SCN_CNT_CODE)
		{
			found = true;
			break;
		}
		else
			sec++;
	return found ? sec : NULL;
}
IMAGE_SECTION_HEADER* get_reloc_section(IMAGE_NT_HEADERS* nt_h)
{
	if ((nt_h == NULL) || (nt_h->FileHeader.Characteristics & IMAGE_FILE_RELOCS_STRIPPED)) // second condtion for case, when .reloc section absent
		return NULL;
	
	IMAGE_DATA_DIRECTORY* entry_reloc = &nt_h->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	
	void* p = nt_h + 1;
	IMAGE_SECTION_HEADER* sec = static_cast<IMAGE_SECTION_HEADER*>(p);
	bool found = false;

	for (int i = 0; i < nt_h->FileHeader.NumberOfSections; ++i)
		if (sec->VirtualAddress == entry_reloc->VirtualAddress)
		{
			found = true;
			break;
		}
		else
			sec++;

	return found ? sec : NULL;
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

	IMAGE_SECTION_HEADER* code_sec = get_code_section(nt_h);
	if (code_sec == NULL)
		throw std::runtime_error("Code section is absent");

	IMAGE_SECTION_HEADER* reloc_sec = get_reloc_section(nt_h);

	//
#ifdef _DEBUG
#error Can't calcute correct difference of functions address
#endif
	int stub_size = get_fn_ptr(end_point) - get_fn_ptr(crypt_chunk);

	crypt_chunk(buffer.data() + code_sec->PointerToRawData, code_sec->SizeOfRawData, XOR_MASK);
	/* 
		rva - relative addres in mem
		pf - pointer in file
		pi - pointer in mem + ImageBase
	*/

	int end_code_pf = code_sec->PointerToRawData + code_sec->Misc.VirtualSize; // where we can put our code
	int free_space_size = code_sec->SizeOfRawData - code_sec->Misc.VirtualSize; // space that we can use
	int end_code_rva = code_sec->VirtualAddress + code_sec->Misc.VirtualSize;
	uint32_t stub_pf = align(end_code_pf, 16);

	int gap = stub_pf - end_code_pf;
	if (stub_size + gap > free_space_size)
		throw std::runtime_error("No space to write stub");
	int stub_rva = end_code_rva + gap;

	std::memset(&buffer[end_code_pf], 0, free_space_size);
	std::memcpy(&buffer[stub_pf], crypt_chunk, stub_size);

	//set stub correct params
	int nep_offset	= get_fn_ptr(new_entry_point) - get_fn_ptr(crypt_chunk);
	uint32_t nep_pf = stub_pf + nep_offset;
	int nep_rva		= stub_rva+ nep_offset;
	int nep_pi		= stub_rva+ nep_offset + opt_h->ImageBase + 8; // with offset.. sub, call and ect see asm code
	std::memcpy(&buffer[nep_pf + 11], &nep_pi, 4);

	int code_begin_pi = opt_h->ImageBase + code_sec->VirtualAddress;
	std::memcpy(&buffer[nep_pf + 20], &code_begin_pi, 4);
	std::memcpy(&buffer[nep_pf + 29], &XOR_MASK, 4);
	std::memcpy(&buffer[nep_pf + 34], &code_sec->Misc.VirtualSize, 4);

	int oep_pi = opt_h->AddressOfEntryPoint + opt_h->ImageBase;
	std::memcpy(&buffer[nep_pf + 77], &oep_pi, 4);
	
	//set new entry point
	opt_h->AddressOfEntryPoint		 = nep_rva;
	code_sec->Characteristics		|= IMAGE_SCN_MEM_WRITE;
	code_sec->Misc.VirtualSize		+= gap + stub_size;

	// relocation
	IMAGE_DATA_DIRECTORY* data_reloc = &opt_h->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	data_reloc->Size = 0;
	data_reloc->VirtualAddress = NULL;
	// try to find relocation table

	if (reloc_sec)
	{
		int reloc_begin_pi = opt_h->ImageBase + reloc_sec->VirtualAddress;
		std::memcpy(&buffer[nep_pf + 49], &reloc_begin_pi, 4);
		std::memcpy(&buffer[nep_pf + 62], &reloc_sec->Misc.VirtualSize, 4);

		reloc_sec->Characteristics &= ~(IMAGE_SCN_MEM_DISCARDABLE);
	} 
	else
	{
		int zero = 0;
		std::memcpy(&buffer[nep_pf + 62], &zero, 4);
	}

	//open file for output 
	std::ofstream o_file(cryptorNewFilename, std::ofstream::binary | std::ofstream::out | std::ofstream::trunc);
	o_file.write(reinterpret_cast<char*>(buffer.data()), fs);

	std::cout << "OK!\n";
	wait_for_input();

	return 0;
}
catch (std::exception& e)
{
	std::cout << "Exception: " << e.what() << std::endl;
	wait_for_input();

	return 1;
}