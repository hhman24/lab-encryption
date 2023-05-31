#include<stdio.h>
#include<string>


unsigned char* pkcs7(unsigned char* p1, int p2, int p3)
{
	int pad = p2 - (p3 % p2);
	unsigned char* m = NULL;
	int m_len = p3 + pad;
	m = new unsigned char[m_len + 1];

	for (int i = 0; i < p3; i++) m[i] = p1[i];
	for (int i = p3; i < m_len; i++) m[i] = pad; // 16 - 1

	m[m_len] = '\0';

	return m;
}

int main()
{

	unsigned char* m[] = { (unsigned char*)"0", (unsigned char*)"01",
						  (unsigned char*)"012", (unsigned char*)"0123",
						  (unsigned char*)"0124", (unsigned char*)"01235",
						  (unsigned char*)"0123456", (unsigned char*)"01234567",
						  (unsigned char*)"012345678", (unsigned char*)"0123456789",
						  (unsigned char*)"0123456789a", (unsigned char*)"0123456789ab",
						  (unsigned char*)"0123456789abc", (unsigned char*)"0123456789abcd",
						  (unsigned char*)"0123456789abcde", (unsigned char*)"0123456789abcdef" };
	
	for (size_t i = 0; i < 16; i++)
	{
		unsigned char* res = pkcs7(m[15 - i], 8, strlen((const char*)m[15 - i]));
	
		printf("\n");
		for (size_t j = 0; j < strlen((const char*)res); j++) printf("%02x ", res[j]);
		printf("\n");
		delete[] res;
	}
	return 0;
}