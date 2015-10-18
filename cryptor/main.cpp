#include <iostream>
#include <string>
#include <fstream>
#include <stdexcept>

#include <windows.h>

typedef unsigned char uchar;

void open_file(std::ifstream& i_file)
{
	std::string s_file = "";
	s_file = "C:/cryptor.exe"; //s_file = "C:/cryptor.exe";//std::cin >> s_file;

	i_file.open(s_file, std::ios::binary);
	if (!i_file)
		throw std::runtime_error("File not exist");
}
int file_size(std::ifstream& i_file)
{
	i_file.seekg(0, std::ios::end);
	int fs = static_cast<int>(i_file.tellg());
	i_file.seekg(0);
	return fs;
}

int main()
try
{
	std::ifstream i_file;
	open_file(i_file);

	int fs = file_size(i_file);
	
	uchar* buffer = new uchar[fs]; 
	i_file.read(reinterpret_cast<char*>(buffer), fs);

	IMAGE_DOS_HEADER* dos_h = reinterpret_cast<IMAGE_DOS_HEADER*>(buffer);
	if (dos_h->e_magic != IMAGE_DOS_SIGNATURE) // first test is this file true PE?
		throw std::runtime_error("This file is not PE");

	std::cout << "OK!\n";
	std::cin.get();
	delete[] buffer;
}
catch (std::exception& e)
{
	std::cout << "Exception: " << e.what() << std::endl;
	std::cin.get();
	return 1;
}