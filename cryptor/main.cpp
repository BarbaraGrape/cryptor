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

/*
	Берём .код секцию. В её конце пишем наш код, после него массив с важными данными и инфу из
	старой релок секции. Саму .релок секцию перезаполним на наш новый код а потом запихнём инфу,
	которая там была.
*/
int align(int begin, int alignment)
{
	int off = begin % alignment;
	if (!off)
		return begin;
	else
		return begin + alignment - off;
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
IMAGE_SECTION_HEADER* create_new_code_section(IMAGE_NT_HEADERS* nt_h, uint8_t* buffer)
{
	// todo: situation when not availabe enough space for new section	
	/* what we do:
		inc number of section in nt header
		acquire suitable pointer for IMAGE_SECTION_HEADER
		set for new section name and characteristic		
	*/
	void* p =  nt_h + 1;
	IMAGE_SECTION_HEADER* new_sec = static_cast<IMAGE_SECTION_HEADER*>(p) + nt_h->FileHeader.NumberOfSections;
	std::memset(new_sec, 0, sizeof(IMAGE_SECTION_HEADER));
	
	BYTE name[IMAGE_SIZEOF_SHORT_NAME] = ".code";
	name[IMAGE_SIZEOF_SHORT_NAME-1] = 0;
	memcpy(new_sec->Name, name, IMAGE_SIZEOF_SHORT_NAME); // Name
	
	new_sec->Characteristics = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE; 
	
	nt_h->FileHeader.NumberOfSections++; // new section added
	return new_sec;
}
// return section, that apear last in memory
IMAGE_SECTION_HEADER* get_last_section(IMAGE_NT_HEADERS* nt_h) 
{
	if (!nt_h)
		return NULL;

	void* p = nt_h + 1;
	IMAGE_SECTION_HEADER* last = static_cast<IMAGE_SECTION_HEADER*>(p);
	IMAGE_SECTION_HEADER* current = last+1;

	for (int i = 1; i < nt_h->FileHeader.NumberOfSections; ++i)
	{
		if (last->VirtualAddress < current->VirtualAddress)
			last = current;
		current++;
	}
	return last;
}
void set_flag_for_sections(IMAGE_NT_HEADERS* nt_h, uint32_t set_flags, uint32_t clear_flags)
{
	if (!nt_h)
		return;

	void* p = nt_h + 1;
	IMAGE_SECTION_HEADER* sec = static_cast<IMAGE_SECTION_HEADER*>(p);

	for (int i = 0; i < nt_h->FileHeader.NumberOfSections; ++i)
	{
		sec->Characteristics |= set_flags;
		sec->Characteristics &= ~(clear_flags);
		sec++;
	}
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

#ifdef _DEBUG
#error Can't calcute correct difference of functions address
#endif
	// crypt code section;
	crypt_chunk(&buffer[code_sec->PointerToRawData], code_sec->SizeOfRawData, XOR_MASK);
	/* 
		rva - relative addres in mem
		pf - pointer in file
		va - pointer in mem + ImageBase
	*/

	// allocate memory for stub+data
	int my_code_size = get_fn_ptr(end_point) - get_fn_ptr(crypt_chunk);
	int full_size = align(my_code_size + sizeof(Some_data), opt_h->FileAlignment);
	std::vector<uint8_t> stub(full_size, 0);
	std::memcpy(stub.data(), crypt_chunk, my_code_size);

	//calculate variable related to new section
	IMAGE_SECTION_HEADER* new_sec = create_new_code_section(nt_h, buffer.data());
	IMAGE_SECTION_HEADER* last_sec = get_last_section(nt_h);
	new_sec->VirtualAddress		= align(last_sec->VirtualAddress + last_sec->Misc.VirtualSize, opt_h->SectionAlignment);
	new_sec->Misc.VirtualSize	= full_size;
	new_sec->SizeOfRawData		= align(full_size, opt_h->FileAlignment);
	new_sec->PointerToRawData	= align(fs, opt_h->FileAlignment);
	
	int nep_offset	= get_fn_ptr(new_entry_point) - get_fn_ptr(crypt_chunk);
	int nep_rva		= new_sec->VirtualAddress + nep_offset;

	int image_base = opt_h->ImageBase;
	Some_data inf;
	inf.nep_va		= image_base + nep_rva;
	inf.cb_va		= image_base + code_sec->VirtualAddress;
	inf.xor_mask	= XOR_MASK;
	inf.code_vsize	= code_sec->Misc.VirtualSize;
	inf.oep_va		= image_base + opt_h->AddressOfEntryPoint;
	if (reloc_sec)
	{
		inf.br_va		= image_base + reloc_sec->VirtualAddress;
		inf.reloc_vsize = reloc_sec->Misc.VirtualSize;
	}
	else
		inf.reloc_vsize = 0;
	memcpy(&stub[my_code_size], &inf, sizeof(Some_data));


	//set new entry point
	//opt_h->AddressOfEntryPoint = nep_rva;
	opt_h->SizeOfCode += my_code_size;

	IMAGE_DATA_DIRECTORY* data_reloc = &opt_h->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	data_reloc->Size = 0;
	data_reloc->VirtualAddress = NULL;

	set_flag_for_sections(nt_h, IMAGE_SCN_MEM_WRITE, IMAGE_SCN_MEM_DISCARDABLE);
	//reloc_sec->Characteristics &= ~(IMAGE_SCN_MEM_DISCARDABLE);

	//open file for output 
	std::ofstream o_file(cryptorNewFilename, std::ofstream::binary | std::ofstream::out | std::ofstream::trunc);
	o_file.write(reinterpret_cast<char*>(buffer.data()), fs);
	o_file.write(reinterpret_cast<char*>(stub.data()), full_size);

	std::cout << "OK!\n";

	return 0;
}
catch (std::exception& e)
{
	std::cout << "Exception: " << e.what() << std::endl;

	return 1;
}