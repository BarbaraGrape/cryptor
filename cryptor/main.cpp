#include <iostream>
#include <string>
#include <fstream>
#include <stdexcept>

#include <windows.h>
#include <stdint.h>

static const std::string cryptorFilename("C:/cryptor.exe"); // till we don't get path from argv[]

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
		throw std::runtime_error("This file is not PE");

	std::cout << "OK!\n";
	std::cin.get();
}
catch (std::exception& e)
{
	std::cout << "Exception: " << e.what() << std::endl;
	std::cin.get();
	return 1;
}