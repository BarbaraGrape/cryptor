#include <Windows.h>

void (* sub)(void);
void p_to_char(void* p, char* buff)
{
	unsigned int addr = reinterpret_cast<int>(p);

	buff[0]='0';
	buff[1]='x';

	for (int i = 7; i >= 0; i--)
	{
		unsigned int r = addr % 0x10;
		char w = 0;
		switch (r)
		{
		case 0xA:
			w = 'A';
			break;
		case 0xB:
			w = 'B';
			break;
		case 0xC:
			w = 'C';
			break;
		case 0xD:
			w = 'D';
			break;
		case 0xE:
			w = 'E';
			break;
		case 0xF:
			w = 'F';
			break;
		default:
			w = r - '0';
			break;
		}
		buff[i + 2] = w;
		addr /= 0x10;
	}
	buff[10] = NULL;
}
//0 1 2 3 4 5 6 7 8 9
//0 x 1 2 3 4 5 6 7 8
void print(void)
{
	MessageBoxA(0, "Hello, World", "Hello", MB_OK);
}
int main(int argc, char** argv)
{

	sub = print;
	sub();

	void* handle = GetCurrentProcess();
	char buff[255];

	p_to_char(handle, buff);

	MessageBoxA(0, buff, "Handle", MB_OK);

	return 42;
}
