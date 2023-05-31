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

/// <summary>
///		contructor
/// </summary>
/// <param name="key"> string byte key </param>
/// <param name="key_byte">length of string</param>
/// <param name="mode">mode AES: ECB, CBC, CTR</param>
AES::AES(uint8_t key[], int key_byte, int mode)
{
	this->_key_byte = key_byte; // length of key

	// set up number of rounds + 1
	if (this->_key_byte == this->AES_128)
	{
		this->_nr = this->AES_128_NR + 1;
		// ? fix
		// deep copy
		this->_key = this->string2ArrayInt(key, key_byte); // convert to array int
		this->_keys_round = new int* [this->_nr];
		this->_n_w = this->_key_byte / this->INT_SIDE; // number of word sub key

		// allocate for each round
		for (int i = 0; i < this->_nr + 1; i++) this->_keys_round[i] = new int[this->_n_w];
		// copy subkey [0]
		for (int i = 0; i < this->_n_w; i++) this->_keys_round[0][i] = this->_key[i];

		// generate subkey
		this->keySchedule128();
	}
	else if (this->_key_byte == this->AES_192)
	{
		this->_nr = this->AES_192_NR + 1;
		// ? generate key rounds ??
		// generate subkey
		this->keySchedule192();
	}
	else if (this->_key_byte == this->AES_256)
	{
		this->_nr = this->AES_256_NR + 1;
		// ? generate key rounds ??
		// generate subkey
		this->keySchedule256();
	}
	
	// mode
	this->_aes_mode = mode;

}


// -- Procedure Funciton ----
void AES::addRoundKey(int r)
{
	for (int i = 0; i < this->A_BLOCK_LEN; i++)
	{
		this->_block[i] ^= this->_keys_round[r][i];
	}
}

void AES::subBytes()
{
	for (int i = 0; i < this->A_BLOCK_LEN; i++)
	{
		this->_block[i] = this->subWord(this->_block[i], true);
	}
}

void AES::invSubByte()
{
	for (int i = 0; i < this->A_BLOCK_LEN; i++)
	{
		this->_block[i] = this->subWord(this->_block[i], false);
	}
}

void AES::shiftRows()
{
	uint8_t t = 0x00;
	uint8_t* state = int2str(this->_block, this->A_BLOCK_LEN); // each of byte

	t = state[1];
	state[1] = state[5];
	state[5] = state[9];
	state[9] = state[13];
	state[13] = t;

	// shift 2 byte in row 2th
	t = state[2];
	state[2] = state[10];
	state[10] = t;
	t = state[6];
	state[6] = state[14];
	state[14] = t;

	// shift 3 byte in row 3th
	t = state[15];
	state[15] = state[11];
	state[11] = state[7];
	state[7] = state[3];
	state[3] = t;

	// conver to array int
	if (this->_block != NULL) delete[] this->_block;
	this->_block = this->string2ArrayInt(state, this->A_BLOCK_LEN * 4);
}

void AES::invShiftRows()
{
	uint8_t t = 0x00;
	uint8_t* state = int2str(this->_block, this->A_BLOCK_LEN);

	t = state[13];
	state[13] = state[9];
	state[9] = state[5];
	state[5] = state[1];
	state[1] = t;
	
	t = state[14];
	state[14] = state[6];
	state[6] = t;
	
	t = state[10];
	state[10] = state[2];
	state[2] = t;
	
	t = state[3];
	state[3] = state[7];
	state[7] = state[11];
	state[11] = state[15];
	state[15] = t;

	// conver to array int
	if (this->_block != NULL) delete[] this->_block;
	this->_block = this->string2ArrayInt(state, this->A_BLOCK_LEN * 4);
}

void AES::mixColumns()
{
	int* re = new int[this->A_BLOCK_LEN];

	for (int i = 0; i < this->A_BLOCK_LEN; i++)
	{
		re[i] = 0;
		for (int j = 0; j < this->INT_SIDE; j++)
		{
			uint8_t s_j = 0x00;
			uint8_t out = 0x00;
			for (int z = 0; z < this->A_BLOCK_LEN; z++) // mat row x col
			{
				 s_j = (this->_block[i] >> (this->INT_BITS - 8*(z + 1))) & 0xFF;
				 out ^= this->GF(this->MIXCOL[j][z], s_j); // mat GF(2^8)
			}
			re[i] |= (out << this->INT_BITS - 8 * (j + 1));
		}
	}
	
	if(this->_block != NULL) delete[] this->_block;
	this->_block = re;
}

void AES::invMixColumns()
{
	int* re = new int[this->A_BLOCK_LEN];

	for (int i = 0; i < this->A_BLOCK_LEN; i++)
	{
		re[i] = 0;
		for (int j = 0; j < this->INT_SIDE; j++)
		{
			uint8_t s_j = 0x00;
			uint8_t out = 0x00;
			for (int z = 0; z < this->A_BLOCK_LEN; z++) // mat row x col
			{
				s_j = (this->_block[i] >> (this->INT_BITS - 8 * (z + 1))) & 0xFF;
				out ^= this->GF(this->INV_MIXCOL[j][z], s_j); // mat GF(2^8)
			}
			re[i] |= (out << this->INT_BITS - 8 * (j + 1));
		}
	}

	if (this->_block != NULL) delete[] this->_block;
	this->_block = re;
}

void AES::keySchedule128()
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

// -- not implement
void AES::keySchedule192()
{}
void AES::keySchedule256()
{}
// -- not implement

// -- Procedure Funciton ----

// ------------------------------- Help function ------

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

// convert 4 byte to int
int AES::byte2Int(uint8_t byte[5])
{
	int n = 0;
	for (int i = 0; i < 4; i++) n = (n << 8) | byte[i];

	// If byte is null ???
	return n;
}

// array uint8_t to array int ? neu no khong phai la boi cua 4 -> co the them padding
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

// array int to array uint8_t
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

void AES::printKeysRound()
{
	if (this->_keys_round != NULL)
	{
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

void AES::printBlockHex()
{
	if (this->_block != NULL)
	{
		uint8_t* b = this->int2str(this->_block, this->A_BLOCK_LEN);
		for (int i = 0; i < this->_key_byte; i++)printf("%02x ", b[i]);
		printf("\n");
		delete[] b;
	}
}

void AES::printCipherTextHex()
{
	if (this->_c_block != NULL)
	{
		uint8_t* c = this->int2str(this->_c_block, this->_n_byte_in_m / this->INT_SIDE);
		for (int i = 0; i < this->_n_byte_in_m; i++) printf("%02x ", c[i]);
		printf("\n");
	}
}

void AES::printPlainTextHex()
{
	if (this->_m != NULL)
	{
		for (int i = 0; i < this->_n_byte_in_m; i++) printf("%02x ", this->_m[i]);
		printf("\n");
	}
}

// function random byte to array int
int* AES::randomFill(int size)
{
	uint8_t* r = new uint8_t[size + 1];
	for (int i = 0; i < size; i++)
	{
	    r[i] = rand() % 256;
	}
	r[size] = '\0';

	int* a = this->string2ArrayInt(r, size);
	if (r != NULL) delete[] r;
	return a;
}

// ------------------------------- Help function ------

void AES::encryptBlock()
{
	this->addRoundKey(0);
	printf("Cipher text[%i]:\t\t", 0);
	this->printBlockHex();
	for (int i = 1; i < this->_nr; i++)
	{
		

		this->subBytes();

		this->shiftRows();

		if (i <= 9) this->mixColumns();

		this->addRoundKey(i);
		printf("Cipher text[%i]:\t\t", i);
		this->printBlockHex();
	}
}

void AES::decryptBlock()
{
	this->addRoundKey(this->_nr - 1);
	printf("Plaint text[%i]:\t\t", this->_nr - 1);
	this->printBlockHex();

	for (int i = this->_nr - 2; i >= 0; i--)
	{
		this->invShiftRows();
		this->invSubByte();
		this->addRoundKey(i);
		if (i > 0) this->invMixColumns();

		printf("Plaint text[%i]:\t\t", i);
		this->printBlockHex();
	}

}

void AES::encryptCBC(uint8_t* m, int byte_len)
{
	// if m_byte len khong phai lon hon 16 bao loi
	this->_m = new uint8_t[byte_len + 1]; // ? should deep copy ??
	this->_n_byte_in_m = byte_len;

	for (int i = 0; i < byte_len; i++) this->_m[i] = m[i];
	this->_m[byte_len] = '\0';

	this->_c_block = this->string2ArrayInt(this->_m, this->_n_byte_in_m); // co the them phan padding o day

	int IV[this->A_BLOCK_LEN] = { 0,0,0,0 }; // init random vector IV
	this->_n_blocks = byte_len / (this->A_BLOCK_LEN * this->INT_SIDE); // get n block

	int prev_block [this->A_BLOCK_LEN] = { 0,0,0,0 }; //  prev block

	this->_block = new int[this->A_BLOCK_LEN]; //  prev block

	for (int i = 0; i < this->_n_blocks; i++)
	{
		for (int j = 0; j < this->A_BLOCK_LEN; j++) this->_block[j] = this->_c_block[i * this->A_BLOCK_LEN + j];

		// xor IV with first round
		if (i == 0) for (int j = 0; j < this->A_BLOCK_LEN; j++) this->_block[j] ^= IV[j];
		else for (int j = 0; j < this->A_BLOCK_LEN; j++) this->_block[j] ^= prev_block[j];
	
		this->encryptBlock();

		for (int j = 0; j < this->A_BLOCK_LEN; j++) prev_block[j] ^= this->_block[j];

		// update cipher
		for (int j = 0; j < this->A_BLOCK_LEN; j++) this->_c_block[i * this->A_BLOCK_LEN + j] = this->_block[j];
	}
}

void AES::decryptCBC()
{

	int IV[this->A_BLOCK_LEN] = { 0,0,0,0 }; // init random vector IV

	int prev_block[this->A_BLOCK_LEN] = { 0,0,0,0 }; //  prev block

	this->_block = new int[this->A_BLOCK_LEN]; //  prev block

	for (int i = 0; i < this->_n_blocks; i++)
	{
		for (int j = 0; j < this->A_BLOCK_LEN; j++) this->_block[j] = this->_c_block[i * this->A_BLOCK_LEN + j];

		this->decryptBlock();

		// xor IV with first round
		if (i == 0) for (int j = 0; j < this->A_BLOCK_LEN; j++)
		{
			prev_block[j] = this->_block[j];
			this->_block[j] ^= IV[j];
		}
		else for (int j = 0; j < this->A_BLOCK_LEN; j++)
		{
			this->_block[j] ^= prev_block[j];
			prev_block[j] = this->_block[j];
		}

		// update cipher
		for (int j = 0; j < this->A_BLOCK_LEN; j++) this->_c_block[i * this->A_BLOCK_LEN + j] = this->_block[j];
	}
}

void AES::encrypt(uint8_t* m, int byte_len)
{
	switch (this->_aes_mode)
	{
	case 0:
		printf("Not implement ECB - comming soon :v\n");
		break;
	case 1:
		printf("\t\t**********************\n");
		printf("\t\t*Encrypt AES mode CBC*\n");
		printf("\t\t**********************\n");
		this->encryptCBC(m, byte_len);
		break;
	case 2:
		printf("Not implement CTR - comming soon :v\n");
		break;
	default:
		printf("\t\t**********************\n");
		printf("\t\t*Encrypt AES mode CBC*\n");
		printf("\t\t**********************\n");
		this->encryptCBC(m, byte_len);
		break;
	}
}

void AES::decrypt()
{
	switch (this->_aes_mode)
	{
	case 0:
		printf("Not implement ECB - comming soon :v\n");
		break;
	case 1:
		printf("\t\t**********************\n");
		printf("\t\t*Decrypt AES mode CBC*\n");
		printf("\t\t**********************\n");
		this->decryptCBC();
		break;
	case 2:
		printf("Not implement CTR - comming soon :v\n");
		break;
	default:
		printf("\t\t**********************\n");
		printf("\t\t*Decrypt AES mode CBC*\n");
		printf("\t\t**********************\n");
		this->decryptCBC();
		break;
	}
}

AES::~AES()
{
	if (this->_key != NULL) delete[] this->_key;
	
	if (this->_m != NULL) delete[] this->_m;

	if (this->_c_block != NULL) delete[] this->_c_block;

	if (this->_block != NULL) delete[] this->_block;

	if (this->_keys_round == NULL)
	{
		for (int i = 0; i < _nr; i++)
		{
			delete[] this->_keys_round;
		}
	}
}