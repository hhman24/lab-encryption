#include <iostream>
#include "des.h"
using namespace std;
//// Initial Permutation
//const short IP_Table[64] = { 58, 50, 42, 34, 26, 18, 10, 2,
//                            60, 52, 44, 36, 28, 20, 12, 4,
//                            62, 54, 46, 38, 30, 22, 14, 6,
//                            64, 56, 48, 40, 32, 24, 16, 8,
//                            57, 49, 41, 33, 25, 17, 9, 1,
//                            59, 51, 43, 35, 27, 19, 11, 3,
//                            61, 53, 45, 37, 29, 21, 13, 5,
//                            63, 55, 47, 39, 31, 23, 15, 7 };
////Final Permutation
//const short FP_Table[64] = { 40, 8, 48, 16, 56, 24, 64, 32,
//                            39, 7, 47, 15, 55, 23, 63, 31,
//                            38, 6, 46, 14, 54, 22, 62, 30,
//                            37, 5, 45, 13, 53, 21, 61, 29,
//                            36, 4, 44, 12, 52, 20, 60, 28,
//                            35, 3, 43, 11, 51, 19, 59, 27,
//                            34, 2, 42, 10, 50, 18, 58, 26,
//                            33, 1, 41, 9, 49, 17, 57, 25 };
//
//void IP(unsigned char* input) {
//    unsigned char output[sizeof(input)] = { 0 };
//    for (int i = 0; i < 64; i++) {
//        int index = IP_Table[i] - 1;
//
//        int bit = (input[index / 8] >> (7 - (index % 8))) & 1;
//        output[i / 8] |= (bit << (7 - (i % 8)));
//    }
//    for (int i = 0; i < sizeof(input); i++) {
//        input[i] = output[i];
//    }
//}
//void FP(unsigned char* input) {
//    unsigned char output[sizeof(input)] = { 0 };
//    for (int i = 0; i < 64; i++) {
//        int index = FP_Table[i] - 1;
//        int bit = (input[index / 8] >> (7 - (index % 8))) & 1;
//        output[i / 8] |= (bit << (7 - (i % 8)));
//    }
//    for (int i = 0; i < sizeof(input); i++) {
//        input[i] = output[i];
//    }
//}

int main()
{

    unsigned char p[] = "anhuythi";

    cout << "Plaintext: ";
    for (size_t i = 0; i < sizeof(p) - 1; i++) printf("%02x ", p[i]);
    cout << endl;

    IP(p);

    cout << "IP output: ";
    for (size_t i = 0; i < sizeof(p) - 1; i++) printf("%02x ", p[i]);

    cout << endl;

    FP(p);

    cout << "FP output: ";
    for (size_t i = 0; i < sizeof(p) - 1; i++) printf("%02x ", p[i]);
    cout << endl;

    return 0;
}