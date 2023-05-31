#include"aes.h"

/// <summary>
/// Group 06
/// AES for 128
/// Not implement for aes 192 - 256
/// length of plaint text is multiple of 16
/// Vector IV = 0
/// </summary>

int main() {

    uint8_t m[] = "ahnuythinhquan31anhuythinhquan31";
    uint8_t k[] = "Thats my Kung Fu";
    int len_m = 32;
    printf("Plaint text: ");
    for (int i = 0; i < len_m; i++) printf("%02x ", m[i]);
    printf("\n");

    AES aes(k, 16, 1); // bit->byte

    aes.encrypt(m, 32);
    printf("==> Cipher text: ");
    aes.printCipherTextHex();

    aes.decrypt();
    printf("Plaint text: ");
    aes.printPlainTextHex();

    return 0;
}

