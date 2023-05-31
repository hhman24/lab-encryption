#pragma once

#ifndef _AES_H_
#define _AES_H_

#include<stdio.h>
#include<stdlib.h>
#include <iomanip>
#include <chrono>

class AES
{
private:
	// plaint text
	int* _m = NULL;

	// cipher text
	int* _c = NULL;

	int _message_byte = 0;

	// array to store key
	int* _key = NULL;

	// round key
	int** _keys_round = NULL;

	// s-box and inverse s-box
	static const uint8_t SBOX[256];
	static const uint8_t INV_SBOX[256];

	// rcon
	static const uint8_t MIXCOL[4][4];
	static const uint8_t INV_MIXCOL[4][4];
	uint8_t GF(uint8_t x1, uint8_t x2);

	// AES key length
	static const int AES_128 = 16;
	static const int AES_192 = 24;
	static const int AES_256 = 32;
	int _key_byte = 0;

	// AES block len
	static const int A_BLOCK_LEN = 4;
	static const int INT_SIDE = 4;
	static const int INT_BITS = sizeof(int) * 8;
	int _n_block = 0;

	// AES mode
	static const int AES_ECB = 0;
	static const int AES_CBC = 1;
	static const int AES_CTR = 2;
	int _aes_mode = 0;

	// number of rounds base on the key length
	static const int AES_128_NR = 10;
	static const int AES_192_NR = 12;
	static const int AES_256_NR = 14;
	int _nr = 0;
	int _n_w = 0;

	// function for process

	void subBytes();
	void invSubByte();

	void shiftRows();
	void invShiftRows();

	void mixColumns();
	void invMixColumns();

	void addRoundKey(int r);

	void keySchedule(); //block size
	

	// help function

	int subWord(int w, bool is_SBOX);
	int rorateLeft1Byte(int w, int n_byte);
	int rorateRight1Byte(int w, int n_byte);

	int byte2Int(uint8_t byte[5]);
	int* string2ArrayInt(uint8_t str[], int bytes);

	uint8_t* int2str(int arr[], int buffers);

public:
	// constructor
	AES(uint8_t key[], int key_byte, int mode);


	// help function
	void printKeyHex();
	void printKeysRound();
	void printCipherTextHex();
	void printPlainTextHex();

	// encryption
	void encryptBlock(uint8_t* block);
	// destructor
	~AES();

};

#endif