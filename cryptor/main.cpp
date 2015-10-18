#include <iostream>
#include <string>
#include <fstream>
#include <stdexcept>

typedef unsigned char uchar;

void open_file(std::ifstream& i_file)
{
	std::string s_file = "";
	s_file = "C:/test.txt"; //s_file = "C:/cryptor.exe";//std::cin >> s_file;

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
{
	std::ifstream i_file;
	open_file(i_file);

	int fs = file_size(i_file);

	uchar* buffer = new uchar[fs];
	i_file.read(reinterpret_cast<char*>(buffer), fs);

	std::cout << reinterpret_cast<char*>(buffer) << std::endl;

	std::cin.get();

	delete[] buffer;
}