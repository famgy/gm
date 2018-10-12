#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <malloc.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <ctype.h>
#include "sm4.h"
#include "sm3.h"

/**
 * converting Java string to c string
 * appending byte to plain text
 * do sm4 encryption
 * If hexadecimal is true, you will get hexadecimal type cipher text. It is good for displaying on screen.
 * If hexadecimal is false, you will get non-hexadecimal type cipher text.
 */
 void sm4EncryptText(const unsigned char * plaintext, size_t plaintextSize, unsigned char *ciphertext, bool hexadecimal);

 /**
  * Convert cipher text Java string to c string.
  * Convert cipher text ascii encoding byte to hexadecimal encoding byte.
  * Convert cipher text hexadecimal encoding byte to char.
  * Decrypt cipher text.
  * return plain text.
  */
 void  sm4DecryptText(const unsigned char * ciphertext, size_t ciphertextSize ,unsigned char *plaintext);

 /**
  * Encrypt the file which is indicated by plaintextFilePath
  * Write cipher text into another file which is indicated by ciphertestFilePath
  */
 void sm4EncryptFile(const unsigned char *plaintextFilePath, const unsigned char *ciphertextFilePath);

 /**
  * Decrypt the cipher text file which is indicated by ciphertextFilePath.
  * Write plain text into another file which is indicated by plaintextFilePath.
  */
 void sm4DecryptFile(const unsigned char *ciphertextFilePath, const unsigned char *plaintextFilePath);

/**
 * Convert arbitrary length text to a fixed 256 bits length text.
 * Convert hash text to hexadecimal hash text.
 */
void sm3HashString(const unsigned char *text, size_t textSize, unsigned char *hexHashValue);

/**
 * Convert the file which is indicated by filePath to a fixed 256 bits length text.
 * Convert hash text to hexadecimal hash text.
 */
void sm3HashFile(const unsigned char *filePath, unsigned char *hexHashValue);

/**
 * calculate the size of appended plain text corresponding to plain text
 */
unsigned int calculatePlaintextSizeAfterAppending(const unsigned char* origin, size_t originalSize);

/**
* Calculating how many bytes should be appended to origin.
* The goal is result of size of origin Mod 16 is 0.
*/
unsigned int calculateAppendingBytes(const unsigned char *origin, size_t originalSize);

/**
 * If hexadecimal is false, calculate the size of cipher text corresponding to plain text.
 * If hexadecimal is true, calculate the size of hex cipher text corresponding to plain text.
 */
unsigned int calculateCiphertextSize(const unsigned char *origin, size_t originalSize, bool hexadecimal);

/**
 * calculate the size of plain text corresponding to cipher text
 * If cipher text is hexadecimal,then the size of plain text is half size of cipher text.
 * If cipher text is non hexadecimal, the the size of plain text is the same as cipher text.
 */
unsigned int calculatePlaintextSize(const unsigned char *origin, size_t originalSize);

/**
 * Appending origin text.
 * Make sure that the length of origin text Mod 16 is 0
 */
void  appendByteToText(const unsigned char *origin, size_t originalSize, unsigned char *destination, int appendingSize);

/**
 * Check whether input has been added appendingByte already or not.
 */
bool isAppendedText(unsigned char *input, size_t inputSize);

/**
 * remove appending bytes from text
 */
void removeByteFromText(unsigned char* input);

/**
 * Execute sm4 encryption
 * input[] is plain text
 * output[] is cipher text
 */
void sm4Encrypt(unsigned char input[], size_t inputSize, unsigned char output[]);

/**
 * Execute sm4 decrypt
 * input[] is cipher text.
 * output[] is plain text.
 */

 void sm4Decrypt(unsigned char *input, size_t inputSize, unsigned char *output);

/**
 * Convert char to hexadecimal string
 */
void char2HexString(unsigned char input[], size_t inputSize, unsigned char output[]);

/**
 * Convert hexadecimal to char string
 */
void hexString2Char(unsigned char input[], unsigned int inputSize,unsigned char output[]);

/**
 * Convert every ascii encoding char in input
 * to hexadecimal encoding.
 *
 * The size of input is unchanged,
 * but every byte's high four bits will be 0000
 */
void ascii2Hex( const unsigned char *input, unsigned char *output);

/**
 * Get the byte size of the file which is indicated by filePath.
 */
unsigned long getFileSize(const char *filePath);

/**
 * Check whether source is a hexadecimal string or not.
 */
bool isHexString(const unsigned char* source, size_t sourceSize);
