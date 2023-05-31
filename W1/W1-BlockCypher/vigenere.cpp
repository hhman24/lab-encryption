#include<iostream>
#include<string>

using namespace std;


string vigenere_cipher_enc(string key, string message)
{
    string enc;

    for (int i = 0, j = 0; i < message.length(); ++i)

    {

        char c = message[i];

        if (c >= 'A' && c <= 'Z')
        {
            c += 'a' - 'A';
        }
        else if (c < 'a' || c > 'z') continue;

        enc += (c + key[j] - 2 * 'a') % 26 + 'a';

        j = (j + 1) % key.length();

    }

    return enc;
}

string vigenere_cipher_dec(string key, string encrypted_message)
{
    string dec;

    for (int i = 0, j = 0; i < encrypted_message.length(); ++i)

    {

        char c = encrypted_message[i];

        if (c >= 'A' && c <= 'Z')
        {
            c += 'a' - 'A';
        }
        else if (c < 'a' || c > 'z') continue;

        dec += (c - key[j] + 26) % 26 + 'a';

        j = (j + 1) % key.length();

    }

    return dec;
}


int main()
{

	string m = "anhuyquan", k = "cba", c = "";
	cout << "original message: " << m << endl;

	c = vigenere_cipher_enc(k, m);
	cout << "encrypted message: " << c << endl;

	m = vigenere_cipher_dec(k, c);
	cout << "decrypted message: " << m << endl;

	return 0;
}
