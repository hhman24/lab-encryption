#include<iostream>
using namespace std;


/**
* Group 06:
* Hoàng Hữu Minh An - 20127102
* Nguyễn Nhật Quân  - 20127066
* Trần Anh Huy		- 20127192
* Trương Gia Thịnh	- 20127338
*/


// Bài 1: Tính l(f) và entropy
// 
//	 ---------------
//	| a1 | 10010    |
//	| a2 | 1001100  |
//	| a3 | 11       |
//	| a4 | 0        |
//	| a5 | 1000     |
//	| a6 | 101      |
//	| a7 | 1001101  |
//	| a8 | 100111   |
//	'---------------'

// l(f) = 0.4 * 5 + 0.01 * 7 + 0.3 * 2 + 0.4 * 1 + 0.06 * 4 + 0.15 * 3 + 0.01 * 7 + 0.03 * 6 = 4.01
// Entropy: H(x) =	0.01*log2(0.01) * 2 + 0.03*log2(0.03) + 0.04*log2(0.04)
//					+ 0.06*log2(0.06) + 0.15*log2(0.15) + 0.3*log2(0.3) + 0.4*log2(0.4)
//				 = 2.174




// Bài 2: Vernam Cipher -----------------------------------------------------
/**
* input:
*	@size: length of key
* 
* output:
*	a string key has length = length plaintext
* 
*/
string keyGenerate(size_t size)
{
	string p = "";

	for (int i = 0; i < size; i++) p += rand() % 26 + 'a'; // randdom 26 alphabet 
	return p;
}


/**
* input:
*	@plaintext: a string plaint text
*	@key: a string key
*
* output:
*	a string ciphertext after encrypt
*
*/
string vernamEncrypt(string plaintext, string key)
{
	string ciphertext = "";
	for (int i = 0; i < key.length(); i++)
	{
		char c = (plaintext[i] -  'a') ^ (key[i] - 'a'); // xor operator within two character string
		ciphertext += c + 'a';
	}

	return ciphertext;
}

/**
* input:
*	@ciphertext: a string cipher text
*	@key: a string key
*
* output:
*	a string plain text after encrypt
*
*/
string vernamDecrypt(string ciphertext, string key)
{
	string plaintext = "";
	for (int i = 0; i < key.length(); i++)
	{	
		char c = (ciphertext[i] - 'a') ^ (key[i] - 'a'); // xor operator within two character string
		plaintext += c + 'a';
	}

	return plaintext;
}

int main()
{
	srand(time(NULL));
	string p = "anhuyquanthinh", c = "", k = "";
	for (int i = 0; i < 20; i++)
	{
		k = keyGenerate(p.length());
		c = vernamEncrypt(p, k);
		cout << "Ciphertext[" << i << "]:\t" << c << endl;

		cout << "-------------------------" << endl;

		p = vernamDecrypt(c, k);
		cout << "plaintext[" << i << "]:\t" << p << endl << endl;
	}

	return 0;
}