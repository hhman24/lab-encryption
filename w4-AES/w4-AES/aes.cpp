#include"aes.h"
const uint8_t AES::SBOX[256] = {
	//0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
	0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76, // 0
	0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, // 1
	0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15, // 2
	0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, // 3
	0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, // 4
	0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, // 5
	0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, // 6
	0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, // 7 
	0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, // 8
	0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, // 9
	0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, // A
	0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, // B
	0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, // C
	0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, // D
	0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, // E
	0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 };// F

const uint8_t AES::INV_SBOX[256] = {
	0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
	0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
	0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
	0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
	0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
	0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
	0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
	0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
	0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
	0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
	0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
	0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
	0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
	0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
	0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
	0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d};

const uint8_t AES::MIXCOL[4][4] = {
	{0x02, 0x03, 0x01, 0x01},
	{0x01, 0x02, 0x03, 0x01},
	{0x01, 0x01, 0x02, 0x03},
	{0x03, 0x01, 0x01, 0x02}};

const uint8_t AES::INV_MIXCOL[4][4] ={
	{0x0E, 0x0B, 0x0D, 0x09},
	{0x09, 0x0E, 0x0B, 0x0D},
	{0x0D, 0x09, 0x0E, 0x0B},
	{0x0B, 0x0D, 0x09, 0x0E}};

AES::AES(uint8_t key[], int key_byte, int mode)
{
	this->_key_byte = key_byte;

	if (this->_key_byte == this->AES_128) this->_nr = this->AES_128_NR + 1;
	else if (this->_key_byte == this->AES_192) this->_nr = this->AES_192_NR + 1;
	else if (this->_key_byte == this->AES_256) this->_nr = this->AES_256_NR + 1;

	// deep copy
	this->_key = this->string2ArrayInt(key, key_byte);
	this->_keys_round = new int* [this->_nr + 1];
	this->_n_w = this->_key_byte / this->INT_SIDE;


	for (int i = 0; i < this->_nr + 1; i++) this->_keys_round[i] = new int[this->_n_w];
	for (int i = 0; i < this->_n_w; i++) this->_keys_round[0][i] = this->_key[i];
	 
	this->keySchedule(); 
}

void AES::addRoundKey(int r)
{
	for (int i = 0; i < this->_n_block; i++)
	{
		printf("%x ^ %x\n", this->_c[i], this->_keys_round[r][i]);
		this->_c[i] ^= this->_keys_round[r][i];
	}
}

void AES::subBytes()
{
	for (int i = 0; i < this->A_BLOCK_LEN; i++)
	{
		this->_c[i] = this->subWord(this->_m[i], true);
	}
}

void AES::invSubByte()
{
	for (int i = 0; i < this->A_BLOCK_LEN; i++)
	{
		this->_m[i] = this->subWord(this->_c[i], false);
	}
}

void AES::shiftRows()
{
	for (int i = 1; i < this->A_BLOCK_LEN; i++)
	{
		this->_c[i] = this->rorateLeft1Byte(this->_c[i], i);
	}
}

void AES::invShiftRows()
{
	for (int i = 1; i < this->A_BLOCK_LEN; i++)
	{
		this->_c[i] = this->rorateRight1Byte(this->_c[i], i);
	}
}

void AES::mixColumns()
{
	int* re = new int[this->A_BLOCK_LEN];

	for (int i = 0; i < this->A_BLOCK_LEN; i++)
	{
		re[i] = 0;
		for (int j = 0; j < this->A_BLOCK_LEN; j++)
		{
			uint8_t s_j = 0x00;
			for (int z = 0; z < this->A_BLOCK_LEN; z++)
			{
				 s_j = (this->_c[z] >> (this->INT_BITS - 8 - j)) && 0xFF;
				 s_j ^= this->GF(this->MIXCOL[i][z], s_j);
				 re[i] |= (s_j << this->INT_BITS - 8 - j);
			}
		}
	}
	
	if(this->_c != NULL) delete[] this->_c;
	this->_c = re;
}

void AES::invMixColumns()
{
	int* re = new int[this->A_BLOCK_LEN];

	for (int i = 0; i < this->A_BLOCK_LEN; i++)
	{
		re[i] = 0;
		for (int j = 0; j < this->A_BLOCK_LEN; j++)
		{
			uint8_t s_j = 0x00;
			for (int z = 0; z < this->A_BLOCK_LEN; z++)
			{
				s_j = (this->_c[z] >> (this->INT_BITS - 8 - j)) && 0xFF;
				s_j ^= this->GF(this->INV_MIXCOL[i][z], s_j);
				re[i] |= (s_j << this->INT_BITS - 8 - j);
			}
		}
	}

	if (this->_c != NULL) delete[] this->_c;
	this->_c = re;
}

void AES::keySchedule()
{
	uint8_t roundCoeff = 0x01;

	for (int i = 1; i < this->_nr; i++)
	{
		int w = subWord(rorateLeft1Byte(this->_keys_round[i - 1][this->_n_w - 1], 1), true); // rorate left 1 byte and sub word
		int rcon_2_int = 0;
		rcon_2_int |= roundCoeff;
		rcon_2_int <<= this->INT_BITS - 8;

		this->_keys_round[i][0] = this->_keys_round[i - 1][0] ^ w ^ rcon_2_int;

		for (int j = 1; j < this->_n_w; j++) 
			this->_keys_round[i][j] = this->_keys_round[i - 1][j] ^ this->_keys_round[i][j-1];

		roundCoeff = this->GF(roundCoeff, 0x02);
	}
}

uint8_t AES::GF(uint8_t x1, uint8_t x2)
{
	uint8_t re = 0;

	for (int i = 0; i < 8; i++)
	{
		if (x2 & 0x01)
		{
			re ^= x1; // re += x1 in GF(2^8)
		}

		bool hight_bit = x1 & 0x80; // re >= 128(1000 0000)
		x1 <<= 1;
		if (hight_bit)
		{
			// reduce
			x1 ^= 0x1b; // x1 ^ 0001 1011 = mod(x^8 + x^4 + x^3 + x + 1)
		}

		x2 >>= 1; // x2 / 2
	}

	return re;
}

int AES::subWord(int w, bool is_SBOX)
{
	int w_sub = 0;
	if (is_SBOX)
	{
		// sub each other byte
		for (int i = 0; i < 4; i++)
		{
			int c = (w >> 8 * i) & 0xFF; // get low byte by shift left 
			w_sub |= this->SBOX[c] << (8 * i); // shift right to back to original position byte
		}
	}
	else 
	{
		// sub each other byte
		for (int i = 0; i < 4; i++)
		{
			int c = (w >> 8 * i) & 0xFF; // get low byte by shift left 
			w_sub |= this->INV_SBOX[c] << (8 * i); // shift right to back to original position byte
		}
	}

	return w_sub;
}

int AES::rorateLeft1Byte(int w, int n_byte)
{
	int byte234 = 0;
	int byte1 = 0;
	int _w = w;
	for (int i = 0; i < n_byte; i++)
	{
		// shift left 1 byte example: 0xabcdef00
		byte234 = (_w << 8);

		// shift right to get hight byte example: 0x12
		byte1 = (_w >> (this->INT_BITS - 8)) & 0xFF;

		_w = byte234 | byte1; // or 2 byte
	}
	return _w; 
}

int AES::rorateRight1Byte(int w, int n_byte)
{
	int byte234 = 0;
	int byte1 = 0;
	int _w = w;

	for (int i = 0; i < n_byte; i++)
	{

		byte234 = (_w >> 8) & 0x00FFFFFF;

		byte1 = (_w & 0xFF);

		_w = byte234 | (byte1 << (this->INT_BITS - 8)); // or 2 byte
	}
	return _w;
}

int AES::byte2Int(unsigned char byte[5])
{
	int n = 0;
	for (int i = 0; i < 4; i++) n = (n << 8) | byte[i];

	// If byte is null ???
	return n;
}

int* AES::string2ArrayInt(uint8_t str[], int bytes)
{
	int* arr_int = new int[bytes / 4];
	short z = 0;
	for (int i = 0; i < bytes / 4; i++)
	{
		uint8_t t[5] = "ainz";
		for (short j = 0; j < 4; j++)  t[j] = str[z++]; // copy word 4 byte

		arr_int[i] = this->byte2Int(t);
	}

	return arr_int;
}

uint8_t* AES::int2str(int arr[], int buffers)
{
	uint8_t* str = new uint8_t[buffers * this->INT_SIDE + 1];
	short z = 0;
	for (int i = 0; i < buffers; i++)
	{
		str[z]	 = (arr[i] >> 24) & 0xFF;
		str[++z] = (arr[i] >> 16) & 0xFF;
		str[++z] = (arr[i] >> 8) & 0xFF;
		str[++z] = arr[i] & 0xFF;
		z++;
	}
	str[z] = '\0';
	return str;
}

//
// ------------ HELP FUNCTION ------------------------------------------------
//
void AES::printKeyHex()
{
	if (this->_key != NULL)
	{
		uint8_t* key = this->int2str(this->_key, this->_key_byte / this->INT_SIDE);
		for (int i = 0; i < this->_key_byte; i++)printf("%02x ", key[i]);
		printf("\n");
		delete[] key;
	}
}

void AES::printCipherTextHex()
{
	if (this->_c != NULL)
	{
		uint8_t* c = this->int2str(this->_c, this->_message_byte / this->INT_SIDE);
		for (int i = 0; i < this->_message_byte; i++) printf("%02x ", c[i]);
		printf("\n");
		delete[] c;
	}
}

void AES::printPlainTextHex()
{
	if (this->_m != NULL)
	{
		uint8_t* m = this->int2str(this->_m, this->_message_byte / this->INT_SIDE);
		for (int i = 0; i < this->_message_byte; i++) printf("%02x ", m[i]);
		printf("\n");
		delete[] m;
	}
}

void AES::printKeysRound()
{
	if (this->_keys_round != NULL)
	{
		printf("\n");
		for (int i = 0; i < this->_nr; i++)
		{
			printf("k[%i]: ", i);
			uint8_t* key = this->int2str(this->_keys_round[i], this->_n_w);
			for (int j = 0; j < this->_key_byte; j++)
			{
				printf("%x ", key[j]);
			}
			printf("\n");
			delete[] key;
		}
	}
}
//
// ------------ HELP FUNCTION ------------------------------------------------
//

void AES::encryptBlock(uint8_t* block)
{
	// if m_byte len khong phai lon hon 16 bao loi
	this->_message_byte = this->A_BLOCK_LEN * 4;
	this->_m = this->string2ArrayInt(block, this->_message_byte);
	this->_c = this->string2ArrayInt(block, this->_message_byte);

	// them phan pading vao
	printf("Plaint text:\t");
	this->printCipherTextHex();

	printf("key round:");
	this->printKeysRound();

	this->addRoundKey(0);
	printf("Cipher text[%i]:\t", 0);
	this->printPlainTextHex();

	//for (int i = 1; i < 2; i++)
	//{
	//	printf("Cipher text[%i]:\t\t\n", i);

	//	this->subBytes();
	//	printf("subytes: \t\t");
	//	this->printPlainTextHex();

	//	this->shiftRows();
	//	printf("shiftRows: \t\t");
	//	this->printPlainTextHex();

	//	if (i <= 9) this->mixColumns();
	//	printf("mixColumns: \t\t");
	//	this->printPlainTextHex();

	//	this->addRoundKey(i);
	//	printf("addRoundKey: \t\t");
	//	this->printPlainTextHex();
	//}
}
AES::~AES()
{
	if (this->_key != NULL) delete[] this->_key;
	
	if (this->_m != NULL) delete[] this->_m;

	if (this->_c != NULL) delete[] this->_c;

	if (this->_keys_round == NULL)
	{
		for (int i = 0; i < _nr; i++)
		{
			delete[] this->_keys_round;
		}
	}
}