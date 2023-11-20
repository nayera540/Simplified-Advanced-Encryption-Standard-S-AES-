#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#define AES_BLOCK_SIZE 4
#define AES_ROUNDs 2

void saes_encrypt(uint8_t *text, uint8_t *key, uint8_t *rounded_key ,uint8_t *result);
/* Round Constants used in key expansion algorithm */
const uint8_t RC[] = {0x80, 0x30};

static const uint8_t S_BOX[16] = {
    0x9, 0x4, 0xA, 0xB,
    0xD, 0x1, 0x8, 0x5,
    0x6, 0x2, 0x0, 0x3,
    0xC, 0xE, 0xF, 0x7
};

static const uint8_t INVERSE_S_BOX[16] = {
    0xA, 0x5, 0x9, 0xB,
    0x1, 0x7, 0x8, 0xF,
    0x6, 0x0, 0x2, 0x3,
    0xC, 0x4, 0xD, 0xE
};

const uint8_t MIXCOLUMN_MATRIX[] =
{
    1, 4,
    4, 1
};

const uint8_t INVERSE_MIXCOLUMN_MATRIX[] =
{
    9, 2,
    2, 9
};

const uint8_t MULTIPLY_TABLE[16][16] =
{
    {0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0},
    {0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF},
    {0x0, 0x2, 0x4, 0x6, 0x8, 0xA, 0xC, 0xE, 0x3, 0x1, 0x7, 0x5, 0xB, 0x9, 0xF, 0xD},
    {0x0, 0x3, 0x6, 0x5, 0xC, 0xF, 0xA, 0x9, 0xB, 0x8, 0xD, 0xE, 0x7, 0x4, 0x1, 0x2},
    {0x0, 0x4, 0x8, 0xC, 0x3, 0x7, 0xB, 0xF, 0x6, 0x2, 0xE, 0xA, 0x5, 0x1, 0xD, 0x9},
    {0x0, 0x5, 0xA, 0xF, 0x7, 0x2, 0xD, 0x8, 0xE, 0xB, 0x4, 0x1, 0x9, 0xC, 0x3, 0x6},
    {0x0, 0x6, 0xC, 0xA, 0xB, 0xD, 0x7, 0x1, 0x5, 0x3, 0x9, 0xF, 0xE, 0x8, 0x2, 0x4},
    {0x0, 0x7, 0xE, 0x9, 0xF, 0x8, 0x1, 0x6, 0xD, 0xA, 0x3, 0x4, 0x2, 0x5, 0xC, 0xB},
    {0x0, 0x8, 0x3, 0xB, 0x6, 0xE, 0x5, 0xD, 0xC, 0x4, 0xF, 0x7, 0xA, 0x2, 0x9, 0x1},
    {0x0, 0x9, 0x1, 0x8, 0x2, 0xB, 0x3, 0xA, 0x4, 0xD, 0x5, 0xC, 0x6, 0xF, 0x7, 0xE},
    {0x0, 0xA, 0x7, 0xD, 0xE, 0x4, 0x9, 0x3, 0xF, 0x5, 0x8, 0x2, 0x1, 0xB, 0x6, 0xC},
    {0x0, 0xB, 0x5, 0xE, 0xA, 0x1, 0xF, 0x4, 0x7, 0xC, 0x2, 0x9, 0xD, 0x6, 0x8, 0x3},
    {0x0, 0xC, 0xB, 0x7, 0x5, 0x9, 0xE, 0x2, 0xA, 0x6, 0x1, 0xD, 0xF, 0x3, 0x4, 0x8},
    {0x0, 0xD, 0x9, 0x4, 0x1, 0xC, 0x8, 0x5, 0x2, 0xF, 0xB, 0x6, 0x3, 0xE, 0xA, 0x7},
    {0x0, 0xE, 0xF, 0x1, 0xD, 0x3, 0x2, 0xC, 0x9, 0x7, 0x6, 0x8, 0x4, 0xA, 0xB, 0x5},
    {0x0, 0xF, 0xD, 0x2, 0x9, 0x6, 0x4, 0xB, 0x1, 0xE, 0xC, 0x3, 0x8, 0x7, 0x5, 0xA}
};



int main(int argc, char *argv[]) {
    const char *type = argv[1];
    const char *key = argv[2];
    const char *plain_text = argv[3];
    uint8_t key_bytes[AES_BLOCK_SIZE];
    uint8_t plain_text_bytes[AES_BLOCK_SIZE];
    uint8_t rounded_keys[AES_ROUNDs + AES_BLOCK_SIZE];
    uint8_t cipher_text[AES_BLOCK_SIZE];

    for (int i = 0; i < AES_BLOCK_SIZE; i++) {
        key_bytes[i] = (uint8_t)(key[i] >= 'A' ? key[i] - 'A' + 10 : key[i] - '0');
        plain_text_bytes[i] = (uint8_t)(plain_text[i] >= 'A' ? plain_text[i] - 'A' + 10 : plain_text[i] - '0');
    }

    // Now key_bytes and plain_text_bytes contain the desired values
    if(strcmp(type,"ENC") == 0){
        saes_encrypt(plain_text_bytes, key_bytes, rounded_keys, cipher_text);
        for (int i = 0; i < AES_BLOCK_SIZE; i++) {
            printf("%X", cipher_text[i]);
        }
        printf("\n");
    }
    else{
        printf("Invalid type\n");
    }
    return 0;
}
uint8_t SubNib(uint8_t nibble) {
    // Extract the high-order 4 bits and low-order 4 bits
    uint8_t highNibble = (nibble >> 4) & 0x0F;
    uint8_t lowNibble = nibble & 0x0F;

    // Perform S-Box substitution using the S_BOX array for both nibbles
    uint8_t substitutedHighNibble = S_BOX[highNibble];
    uint8_t substitutedLowNibble = S_BOX[lowNibble];

    // Combine the substituted high and low nibbles into a byte
    return (substitutedHighNibble << 4) | substitutedLowNibble;
}


// Function to perform RotNib operation (rotate the nibbles)
uint8_t RotNib(uint8_t w) {
    return ((w & 0x0f) << 4) | ((w & 0xf0) >> 4);
}
void KEY_EXPANSION(uint8_t *key, uint8_t *rounded_keys) {
    for (int i = 0, j = 0; i < AES_BLOCK_SIZE; i += 2, j++) {
        rounded_keys[j] = (key[i] << 4) | key[i + 1];
    }
    rounded_keys[2] = rounded_keys[0] ^ RC[0] ^ SubNib(RotNib(rounded_keys[1]));
    rounded_keys[3] = rounded_keys[2] ^ rounded_keys[1];
    rounded_keys[4] = rounded_keys[2] ^ RC[1] ^ SubNib(RotNib(rounded_keys[3]));
    rounded_keys[5] = rounded_keys[4] ^ rounded_keys[3];

}
void AddRoundKey(uint8_t *plain_text, uint8_t w1, uint8_t w2) {
    uint16_t concatenated_value = 0;
    for (int i = 0; i < 4; i++) {
        concatenated_value = (concatenated_value << 4) | plain_text[i];
    }

    uint16_t concatenatedKey = ((uint16_t)w1 << 8) | w2;
    uint16_t result = concatenatedKey ^ concatenated_value;
    // XOR operation and update the plain_text array
    for (int i = 0; i < 4; i++) {
        // Extract each hexadecimal digit (half a byte)
        plain_text[i] = (result >> ((3 - i) * 4)) & 0xF;
    }
}
void NibbleSub(uint8_t *plaintext)
{
    int i;

    for (i = 0; i < 4; i++)
    {
        plaintext[i] = S_BOX[plaintext[i]];
    }
}
// Swap plaintext[1] and plaintext[3]
void ShiftRow(uint8_t *plaintext)
{
    plaintext[1] ^= plaintext[3];
    plaintext[3] ^= plaintext[1];
    plaintext[1] ^= plaintext[3];
}
uint8_t Multiply(uint8_t a, uint8_t b)
{
    return MULTIPLY_TABLE[a][b];
}
void MixColumns(uint8_t *state)
{
    uint8_t result[4];

    result[0] = Multiply(MIXCOLUMN_MATRIX[0], state[0]) ^ Multiply(MIXCOLUMN_MATRIX[1], state[1]);
    result[1] = Multiply(MIXCOLUMN_MATRIX[2], state[0]) ^ Multiply(MIXCOLUMN_MATRIX[3], state[1]);
    result[2] = Multiply(MIXCOLUMN_MATRIX[0], state[2]) ^ Multiply(MIXCOLUMN_MATRIX[1], state[3]);
    result[3] = Multiply(MIXCOLUMN_MATRIX[2], state[2]) ^ Multiply(MIXCOLUMN_MATRIX[3], state[3]);

    for (int i = 0; i < 4; ++i)
    {
        state[i] = result[i];
    }
}
void saes_encrypt(uint8_t *text, uint8_t *key, uint8_t *rounded_key ,uint8_t *result) {
    // Round 0
    // Key Expansion
    KEY_EXPANSION(key, rounded_key);
    // AddRoundKey
    AddRoundKey(text, rounded_key[0], rounded_key[1]);


    // Round 1

    // Nibble Substitution
    NibbleSub(text);

    // Shift Row
    ShiftRow(text);

    // Mix Column
    MixColumns(text);

    // AddRoundKey
    AddRoundKey(text, rounded_key[2], rounded_key[3]);

    // Round 2

    // Nibble Substitution
    NibbleSub(text);


    // Shift Row
    ShiftRow(text);

    // AddRoundKey
    AddRoundKey(text, rounded_key[4], rounded_key[5]);
    memcpy(result, text, AES_BLOCK_SIZE);


}