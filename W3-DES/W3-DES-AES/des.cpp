#include"des.h"



void IP(unsigned char* plaintext)
{
	unsigned char* p = (unsigned char*)malloc(sizeof(plaintext));

	if (p == NULL) return;

	for (int i = 0; i < sizeof(plaintext); i++) p[i] = 0;

	for (int i = 0; i < 8; i++)
	{
		for (int j = 0; j < 8; j++)
		{
			int idx = (table_ip[i][j] - 1) / 8;
			int element = (table_ip[i][j] - 1) % 8;

			if (plaintext[idx] & (1 << 7 - element))
			{
				p[i] |= (1 << 7 - j);
			}
		}
	}

	for (int i = 0; i < sizeof(plaintext); i++)
	{
		plaintext[i] = p[i];
	}

	if(p != NULL) free(p);
}

void FP(unsigned char* plaintext)
{
	unsigned char* p = (unsigned char*)malloc(sizeof(plaintext));

	if (p == NULL) return;

	for (int i = 0; i < sizeof(plaintext); i++) p[i] = 0;

	for (int i = 0; i < 8; i++)
	{
		for (int j = 0; j < 8; j++)
		{
			int idx = (table_fp[i][j] - 1) / 8;
			int element = (table_fp[i][j] - 1) % 8;

			if (plaintext[idx] & (1 << 7 - element))
			{
				p[i] |= (1 << 7 - j);
			}
		}
	}

	for (int i = 0; i < sizeof(plaintext); i++)
	{
		plaintext[i] = p[i];
	}

	if (p != NULL) free(p);
}