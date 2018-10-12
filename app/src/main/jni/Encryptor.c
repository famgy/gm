#include "Encryptor.h"
#include <jni.h>
#include <android/log.h>

#define TAG    "SM"
#define LOGV(...) __android_log_print(ANDROID_LOG_VERBOSE, TAG, __VA_ARGS__)
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG  , TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN   , TAG, __VA_ARGS__)
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO   , TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR   , TAG, __VA_ARGS__)


#define JNI_API_DEF(f) Java_com_famgy_gm_sm_SM4_##f


/*
 * sm4 security key is used to encrypt plain text and decrypt cipher text
 * the length of key is 128 bits = 16 bytes
 */
//static unsigned char key[16] = { 0x26, 0x67, 0x3b, 0x31, 0x3f, 0x66, 0x30, 0x57,
//		0x2f, 0x3d, 0x52, 0x38, 0x36, 0x66, 0x40, 0x2a };
//the content to append to plain text
static unsigned char appendingByte = '`';
static unsigned char stringEndingMark = '\0';

/*
 * Using this variable to allocate a 32 bytes(256 bits)
 * size memory to store sm3 hash value.
 */
static unsigned int hashValueSize = 32;

/*
 * Using this variable to allocate a 64 bytes
 * memory to store hexadecimal sm3 hash value.
 */
static unsigned int hexHashValueSize = 64;

/*
 * the size of memory buffer for encrypting or decrypting file.
 * the default size is one megabyte.
 */
static unsigned int bufferSize = 1024 * 1024;

static unsigned char key[16];

//Encrypt zq

JNIEXPORT jbyteArray JNI_API_DEF(jniSM4EncryptTest)(JNIEnv *env, jclass class,
                                                    jbyteArray keyArray, jbyteArray plaintext,
                                                    jint length) {
    char *key = (char *) (*env)->GetByteArrayElements(env, keyArray, NULL);
    unsigned char *cPlaintext = (char *) (*env)->GetByteArrayElements(env,
                                                                      plaintext, NULL);
    //The size of hexadecimal type cipher text
    unsigned int hexCiphertextSize = calculateCiphertextSize(cPlaintext, length,
                                                             true);
    /*
     * Allocate a block of memory for cipher text.
     * The size of allocating memory is hexCiphertextSize + 1 because of putting '\0' at the
     * end of ciphertext to indicate ending.
     */
    unsigned char *hexCiphertext = (unsigned char *) malloc(
            hexCiphertextSize + 1);

    printf("sm4Encrypt is called... \n");

    //allocate sm4 context struct
    sm4_context sm4Context;

    //initialize sm4 security key
    printf("set sm4 security key... \n");
    sm4_setkey_enc(&sm4Context, key);

    //execute encrypt operation
    printf("execute sm4 encrypt operation \n");
    sm4_crypt_ecb(&sm4Context, SM4_ENCRYPT, (int) length, cPlaintext,
                  hexCiphertext);

    //append '\0' to indicate the end of string
    hexCiphertext[length] = stringEndingMark;
    jbyteArray rtnbytes2 = (*env)->NewByteArray(env,
                                                (jsize) strlen(hexCiphertext));
    (*env)->SetByteArrayRegion(env, rtnbytes2, 0, (jsize) strlen(hexCiphertext),
                               (jbyte *) hexCiphertext);

    (*env)->ReleaseByteArrayElements(env, keyArray, key, 0);
    (*env)->ReleaseByteArrayElements(env, plaintext, cPlaintext, 0);
    return rtnbytes2;
}

//Decrypt zq
JNIEXPORT jbyteArray JNI_API_DEF(jniSM4DecryptTest)(JNIEnv *env, jclass class,
                                                    jbyteArray keyArray, jbyteArray ciphertext,
                                                    jint length) {
    char *key = (char *) (*env)->GetByteArrayElements(env, keyArray, NULL);
    unsigned char *cCiphertext = (char *) (*env)->GetByteArrayElements(env,
                                                                       ciphertext, NULL);
    /*
     * Plain text's size will be half of cipher text.
     * So allocate a block of memory for plain text.
     * The size of allocating memory is cCiphertextSize/2 + 1 because of putting '\0' at the
     * end of plain text to indicate ending.
     *
     */
    size_t plaintextSize = calculatePlaintextSize(cCiphertext, length);
    unsigned char *plaintext = (unsigned char *) malloc(plaintextSize + 1);

    printf("sm4Decrypt is called...\n");

    //allocate sm4 context struct
    sm4_context ctx;

    //initialize sm4 security key
    printf("set sm4 security key... \n");
    sm4_setkey_dec(&ctx, key);

    //execute encrypt operation
    printf("execute sm4 decrypt operation \n");
    sm4_crypt_ecb(&ctx, SM4_DECRYPT, length, cCiphertext, plaintext);

    //append '\0' to indicate the end of string
    plaintext[length] = stringEndingMark;

    jbyteArray rtnbytes2 = (*env)->NewByteArray(env, (jsize) strlen(plaintext));
    (*env)->SetByteArrayRegion(env, rtnbytes2, 0, (jsize) strlen(plaintext),
                               (jbyte *) plaintext);

    (*env)->ReleaseByteArrayElements(env, keyArray, key, 0);
    (*env)->ReleaseByteArrayElements(env, ciphertext, cCiphertext, 0);
    return rtnbytes2;
}


/**
 * Encrypt byte string by using sm4 algorithm
 * java code call this function
 */
JNIEXPORT jstring JNI_API_DEF(jniEncryptText)(JNIEnv *env, jclass class,
                                               jstring plaintext) {

    //Convert java string to c UTF-8 string
    const unsigned char *cPlaintext = (*env)->GetStringUTFChars(env, plaintext,
                                                                NULL);

    size_t cPlaintextSize = strlen((const char *) cPlaintext);

    //The size of hexadecimal type cipher text
    unsigned int hexCiphertextSize = calculateCiphertextSize(cPlaintext,
                                                             cPlaintextSize, true);

    /*
     * Allocate a block of memory for cipher text.
     * The size of allocating memory is hexCiphertextSize + 1 because of putting '\0' at the
     * end of ciphertext to indicate ending.
     */
    unsigned char *hexCiphertext = (unsigned char *) malloc(
            hexCiphertextSize + 1);

    sm4EncryptText(cPlaintext, cPlaintextSize, hexCiphertext, true);

    //free unused memory blocks
    (*env)->ReleaseStringUTFChars(env, plaintext, cPlaintext);

    //return ciphertext to java code
    return (*env)->NewStringUTF(env, hexCiphertext);
}

/**
 * Decrypt byte string by using sm4 algorithm
 * java code call this function
 */
JNIEXPORT jstring JNI_API_DEF(jniDecryptText)(JNIEnv *env, jclass class,
                                               jstring ciphertext) {

    //Convert java string to c UTF-8 string
    const unsigned char *cCiphertext = (*env)->GetStringUTFChars(env,
                                                                 ciphertext, NULL);

    /*
     * Plain text's size will be half of cipher text.
     * So allocate a block of memory for plain text.
     * The size of allocating memory is cCiphertextSize/2 + 1 because of putting '\0' at the
     * end of plain text to indicate ending.
     *
     */
    size_t cCiphertextSize = strlen((const char *) cCiphertext);
    size_t plaintextSize = calculatePlaintextSize(cCiphertext, cCiphertextSize);
    unsigned char *plaintext = (unsigned char *) malloc(plaintextSize + 1);

    sm4DecryptText(cCiphertext, cCiphertextSize, plaintext);

    //free unused memory blocks
    (*env)->ReleaseStringUTFChars(env, ciphertext, cCiphertext);

    //return plain text to java code
    return (*env)->NewStringUTF(env, plaintext);
}

/**
 * Encrypt file by using sm4 algorithm
 * java code call this function
 */
JNIEXPORT jstring JNI_API_DEF(jniEncryptFile)(JNIEnv *env, jclass class,
                                               jstring plaintextFilePath,
                                               jstring ciphertextFilePath) {
    //Convert java string to c UTF-8 string
    const unsigned char *cPlaintextFilePath = (*env)->GetStringUTFChars(env,
                                                                        plaintextFilePath, NULL);
    const unsigned char *cCiphertextFilePath = (*env)->GetStringUTFChars(env,
                                                                         ciphertextFilePath, NULL);

    if (cPlaintextFilePath == NULL) {
        LOGE("cPlaintextFilePath is null...");
        return NULL;
    }

    if (cCiphertextFilePath == NULL) {
        LOGE("cCiphertextFilePath is null...");
        return NULL;
    }

    sm4EncryptFile(cPlaintextFilePath, cCiphertextFilePath);

    //return cipher text file path to java code
    return (*env)->NewStringUTF(env, cCiphertextFilePath);
}

/**
 * Decrypt cipher text by using sm4 algorithm
 * this function will be called by java code
 */
JNIEXPORT jstring JNI_API_DEF(jniDecryptFile)(JNIEnv *env, jclass class,
                                               jstring ciphertextFilePath,
                                               jstring plaintextFilePath) {
    //Convert java string to c UTF-8 string
    const unsigned char *cPlaintextFilePath = (*env)->GetStringUTFChars(env,
                                                                        plaintextFilePath, NULL);
    const unsigned char *cCiphertextFilePath = (*env)->GetStringUTFChars(env,
                                                                         ciphertextFilePath, NULL);

    if (cPlaintextFilePath == NULL) {
        LOGE("cPlaintextFilePath is null...");
        return NULL;
    }

    if (cCiphertextFilePath == NULL) {
        LOGE("cCiphertextFilePath is null...");
        return NULL;
    }

    sm4DecryptFile(cCiphertextFilePath, cPlaintextFilePath);

    //return plain text file path to java code
    return (*env)->NewStringUTF(env, cPlaintextFilePath);
}


/**
 * converting Java string to c string
 * appending byte to plain text
 * do sm4 encryption
 * If hexadecimal is true, you will get hexadecimal type cipher text. It is good for displaying on screen.
 * If hexadecimal is false, you will get non-hexadecimal type cipher text.
 */
void sm4EncryptText(const unsigned char *plaintext, size_t plaintextSize,
                    unsigned char *ciphertext, bool hexadecimal) {

    //check parameters
    if (plaintext == NULL) {
        perror("plain text is null...");
        return;
    }

    if (ciphertext == NULL) {
        perror("cipher text is null...");
        return;
    }

    /*
     * preprocessing plain text before sm4 encryption
     */
    unsigned int appendingSize = calculateAppendingBytes(plaintext,
                                                         plaintextSize);
    unsigned int plaintextAfterAppendingSize =
            calculatePlaintextSizeAfterAppending(plaintext, plaintextSize);
    unsigned char *plaintextAfterAppending = (unsigned char *) malloc(
            plaintextAfterAppendingSize + 1);

    //check malloc operation result
    if (NULL == plaintextAfterAppending) {
        perror("plaintextAfterAppending malloc unsuccessfully...");
        return;
    }

    appendByteToText(plaintext, plaintextSize, plaintextAfterAppending,
                     appendingSize);
    printf("sm4 plain text finishes appending...\n");
    printf("plaintextAfterAppending is %d \n", plaintextAfterAppendingSize);

    /*
     * allocate a block of memory to store cipher text,
     * the length is the same as plain text after appending
     */
    unsigned char *nonHexCiphertext = (unsigned char *) malloc(
            plaintextAfterAppendingSize + 1);

    //check malloc operation result
    if (NULL == nonHexCiphertext) {
        perror("nonHexCiphertext malloc unsuccessfully...");
        return;
    }

    //execute sm4 encrypt operation on plain text which is already appended
    sm4Encrypt(plaintextAfterAppending, plaintextAfterAppendingSize,
               nonHexCiphertext);

    //free plaintextAfterAppending unused memory
    free((void *) plaintextAfterAppending);

    /*
     * convert cipher text to hexadecimal type string
     * the size of hex string become twice of original cipher text
     * the end of string is '\0' character
     * the size of nonHexCiphertext and plaintextAfterAppending are the same.
     */
    unsigned int nonHexCiphertextSize = plaintextAfterAppendingSize;
    printf("sm4 finish encryption and then convert to hex... \n");
    printf("nonHexCiphertext size is %d \n", nonHexCiphertextSize);
    if (hexadecimal) {
        char2HexString(nonHexCiphertext, nonHexCiphertextSize, ciphertext);
    } else {
        //Copying size is nonHexCiphertextSize + 1 because of '\0' at the end index of nonHexCiphertext.
        memcpy((void *) ciphertext, (const void *) nonHexCiphertext,
               nonHexCiphertextSize + 1);
    }

    //free nonHexCiphertext unused memory
    free((void *) nonHexCiphertext);

    return;
}

/**
 * Convert cipher text Java string to c string.
 * Convert cipher text ascii encoding byte to hexadecimal encoding byte.
 * Convert cipher text hexadecimal encoding byte to char.
 * Decrypt cipher text.
 * return plain text.
 */
void sm4DecryptText(const unsigned char *ciphertext, size_t ciphertextSize,
                    unsigned char *plaintext) {

    //check parameters
    if (ciphertext == NULL) {
        perror("cipher text is null...");
        return;
    }

    if (plaintext == NULL) {
        perror("plain text is null...");
        return;
    }

    if (ciphertextSize <= 0) {
        perror("invalid ciphertextSize argument is <= 0...");
        return;
    }

    /*
     * If cipher text is hexadecimal string , it must be converted to char string first.
     * If cipher text is not hexadecimal string, just decrypt it.
     */
    if (isHexString(ciphertext, ciphertextSize)) {

        /*
         * Allocate a block of memory which size is half of cipher text.
         * Store char type cipher text.
         * Appending '\0' char at charCiphertext[ciphertextSize/2] to
         * indicates the end of string.
         */
        size_t charCiphertextSize = ciphertextSize / 2;
        unsigned char *charCiphertext = (unsigned char *) malloc(
                charCiphertextSize + 1);
        if (charCiphertext == NULL) {
            perror("allocating charCiphertext is unsuccessful...");
            return;
        }

        /*
         * Allocate a block of memory which size is the same as cipher text.
         * Store hexadecimal cipher text.
         * Appending '\0' char at hexCiphertext[ciphertextSize] to indicates
         * the end of string
         */
        unsigned char *hexCiphertext = (unsigned char *) malloc(
                ciphertextSize + 1);
        if (hexCiphertext == NULL) {
            perror("allocating hexCiphertext is unsuccessful...");
            return;
        }

        ascii2Hex(ciphertext, hexCiphertext);

        hexString2Char(hexCiphertext, ciphertextSize, charCiphertext);

        //free unused memory blocks of hexCiphertext.
        free((void *) hexCiphertext);

        //starting sm4 decryption
        sm4Decrypt(charCiphertext, charCiphertextSize, plaintext);

        //free unused memory blocks of charCiphertext.
        free((void *) charCiphertext);
    } else {
        sm4Decrypt((unsigned char *) ciphertext, ciphertextSize, plaintext);
    }

    //remove appending byte from plaintext.
    removeByteFromText(plaintext);

    return;
}

/**
 * Encrypt the file which is indicated by plaintextFilePath
 * Write cipher text into another file which is indicated by ciphertestFilePath
 */
void sm4EncryptFile(const unsigned char *plaintextFilePath,
                    const unsigned char *ciphertextFilePath) {
    //Check parameters
    if (plaintextFilePath == NULL) {
        perror("plaintextFilePath argument is null...\n");
        return;
    }

    if (ciphertextFilePath == NULL) {
        perror("ciphertextFilePath argument is null...\n");
        return;
    }

    //check for file existence
    if ((access((const char *) plaintextFilePath, F_OK)) != 0) {
        perror("plaintextFilePath does not exist...\n");
        return;
    }

    //check for file read permission
    if ((access((const char *) plaintextFilePath, R_OK)) != 0) {
        perror("plaintextFilePath does not have read permission...\n");
        return;
    }

    //if ciphertextFilePath exists,then remove it.
    if ((access((const char *) ciphertextFilePath, F_OK)) == 0) {
        if (remove((const char *) ciphertextFilePath) != 0) {
            perror("Error deleting ciphertextFilePath... \n");
            return;
        } else {
            printf("ciphertextFilePath is successfully deleted...\n");
        }
    }

    /*
     * Allocating two blocks of memory.
     * One is for storing plain text which is extracted from file.
     * Another is for storing cipher text which is converted from above plain text by using sm4 algorithm.
     * The size is bufferSize + 1 because of appending '\0' at the last index to
     * indicate ending of char string.
     */
    unsigned char *plaintextBuffer = (unsigned char *) malloc(bufferSize + 1);
    unsigned char *ciphertextBuffer = (unsigned char *) malloc(bufferSize + 1);

    /*
     * Open plaintextFilePath for input operations. The file must exist.
     * 'r' character indicates read operation.
     * 'a' character indicates appending data at the end of file.
     * In order to open a file as a binary file, a "b" character has to be included
     */
    FILE *plaintextFile = fopen((const char *) plaintextFilePath, "rb");
    FILE *ciphertextFile = fopen((const char *) ciphertextFilePath, "ab");
    if (NULL == plaintextFile) {
        perror("open plain text file fail...\n");
        return;
    }

    if (NULL == ciphertextFile) {
        perror("open cipher text file fail...\n");
        return;
    }

    /*
     * Cyclic Polling from plain text file, the size is bufferSize each loop.
     * Each one with a bufferSize of 1 byte.
     * Do sm4 encryption upon above buffered plain text bytes.
     */
    size_t readingBytesCounter = 0;
    while ((readingBytesCounter = fread(plaintextBuffer, 1, bufferSize,
                                        plaintextFile)) > 0) {
        /*
         * If readingBytesCounter differs from the bufferSize parameter, either a reading error occurred or
         * the end-of-file was reached while reading. In both cases,
         * the proper indicator is set, which can be checked with ferror and feof, respectively.
         */
        if (ferror(plaintextFile)) {
            perror("reading error of plain text file occurred...\n");
            break;
        }
        /*
         * Putting '\0' at readingBytesCounter index of plaintextBuffer indicates the ending.
         * Using readingBytesCounter indicates ending can help us do the same operation when we
         * hint the end of file in while loop.
         */
        plaintextBuffer[readingBytesCounter] = stringEndingMark;
        size_t plaintextBufferSize = readingBytesCounter;

        sm4EncryptText(plaintextBuffer, plaintextBufferSize, ciphertextBuffer,
                       false);

        /*
         * Write all of the bytes in ciphertestBuffer into ciphertextFile.
         * Appending byte to plaintextBuffer happens in sm4 encryption, so the
         * final cipher text size if different plaintextBufferSize(readingBytesCounter).
         */
        unsigned int cipherTextBufferSize = calculateCiphertextSize(
                plaintextBuffer, plaintextBufferSize, false);
        fwrite(ciphertextBuffer, 1, cipherTextBufferSize, ciphertextFile);

        //clear counter of bytes read from plain text file.
        readingBytesCounter = 0;
    }

    //close file stream.
    fclose(plaintextFile);
    fclose(ciphertextFile);

    //Free unused memory
    free((void *) plaintextBuffer);
    free((void *) ciphertextBuffer);
    return;
}

/**
 * Decrypt the cipher text file which is indicated by ciphertextFilePath.
 * Write plain text into another file which is indicated by plaintextFilePath.
 */
void sm4DecryptFile(const unsigned char *ciphertextFilePath,
                    const unsigned char *plaintextFilePath) {
    //Check parameters
    if (plaintextFilePath == NULL) {
        perror("plaintextFilePath argument is null...\n");
        return;
    }

    if (ciphertextFilePath == NULL) {
        perror("ciphertextFilePath argument is null...\n");
        return;
    }

    //check for file existence
    if ((access((const char *) ciphertextFilePath, F_OK)) != 0) {
        perror("ciphertextFilePath does not exist...\n");
        return;
    }

    //check for file read permission
    if ((access((const char *) ciphertextFilePath, R_OK)) != 0) {
        perror("ciphertextFilePath does not have read permission...\n");
        return;
    }

    //if ciphertextFilePath exists,then remove it.
    if ((access((const char *) plaintextFilePath, F_OK)) == 0) {
        if (remove((const char *) plaintextFilePath) != 0) {
            perror("Error deleting plaintextFilePath... \n");
            return;
        } else {
            printf("plaintextFilePath is successfully deleted...\n");
        }
    }

    /*
     * Allocating two blocks of memory.
     * One is for storing cipher text which is extracted from file.
     * Another is for storing plain text which is converted from above cipher text by using sm4 algorithm.
     * The size is bufferSize + 1 because of appending '\0' at the last index to
     * indicate ending of char string.
     */
    unsigned char *ciphertextBuffer = (unsigned char *) malloc(bufferSize + 1);
    unsigned char *plaintextBuffer = (unsigned char *) malloc(bufferSize + 1);

    /*
     * Open ciphertextFilePath for input operations. The file must exist.
     * 'r' character indicates read operation.
     * 'a' character indicates appending data at the end of file.
     * In order to open a file as a binary file, a "b" character has to be included
     */
    FILE *ciphertextFile = fopen((const char *) ciphertextFilePath, "rb");
    FILE *plaintextFile = fopen((const char *) plaintextFilePath, "ab");
    if (NULL == plaintextFile) {
        perror("open plain text file fail...\n");
        return;
    }

    if (NULL == ciphertextFile) {
        perror("open cipher text file fail...\n");
        return;
    }

    /*
     * Cyclic Polling from cipher text file, the size is bufferSize each loop.
     * Each one with a bufferSize of 1 byte.
     * Do sm4 decryption upon above buffered cipher text bytes.
     */
    size_t readingBytesCounter = 0;
    while ((readingBytesCounter = fread(ciphertextBuffer, 1, bufferSize,
                                        ciphertextFile)) > 0) {
        /*
         * If readingBytesCounter differs from the bufferSize parameter, either a reading error occurred or
         * the end-of-file was reached while reading. In both cases,
         * the proper indicator is set, which can be checked with ferror and feof, respectively.
         */
        if (ferror(plaintextFile)) {
            perror("reading error of plain text file occurred...\n");
            break;
        }
        /*
         * Putting '\0' at readingBytesCounter index of ciphertextBuffer indicates the ending.
         * Using readingBytesCounter indicates ending can help us do the same operation when we
         * hint the end of file in while loop.
         */
        ciphertextBuffer[readingBytesCounter] = stringEndingMark;
        size_t ciphertextBufferSize = readingBytesCounter;

        sm4DecryptText(ciphertextBuffer, ciphertextBufferSize, plaintextBuffer);

        /*
         * Write all of the bytes in plaintextBuffer into plaintextFile.
         * plaintextBuffer contains appending byte and '\0' byte, so you should remove them first.
         * We'll write plaintextBufferSize - appendingSize - 1 bytes into plaintextFile.
         */
        unsigned int plaintextBufferSize = calculatePlaintextSize(
                ciphertextBuffer, ciphertextBufferSize);
        unsigned int appendingSize = calculateAppendingBytes(plaintextBuffer,
                                                             plaintextBufferSize);
        fwrite(plaintextBuffer, 1, plaintextBufferSize - appendingSize - 1,
               plaintextFile);

        //clear counter of bytes read from plain text file.
        readingBytesCounter = 0;
    }

    //close file stream.
    fclose(plaintextFile);
    fclose(ciphertextFile);

    //Free unused memory
    free((void *) plaintextBuffer);
    free((void *) ciphertextBuffer);
    return;

}

/**
 * Convert arbitrary length text to a fixed 256 bits length text.
 * Convert hash text to hexadecimal hash text.
 */
void sm3HashString(const unsigned char *text, size_t textSize,
                   unsigned char *hexHashValue) {
    //check parameters
    if (text == NULL) {
        perror("text argument is null...");
        return;
    }

    if (hexHashValue == NULL) {
        perror("hexHashValue argument is null...");
        return;
    }

    //allocating a 32 bytes(256 bits)size memory to store sm3 hash value.
    unsigned char *hashValue = (unsigned char *) malloc(hashValueSize + 1);

    sm3((unsigned char *) text, textSize, hashValue);

    //appending '\0' to indicates the end.
    hashValue[hashValueSize] = stringEndingMark;

    //convert hash value to hexadecimal type.
    char2HexString(hashValue, hashValueSize, hexHashValue);

    //free unused memory
    free((void *) hashValue);

    return;
}

/**
 * Convert the file which is indicated by filePath to a fixed 256 bits length text.
 * Convert hash text to hexadecimal hash text.
 */
void sm3HashFile(const unsigned char *filePath, unsigned char *hexHashValue) {
    //check parameters
    if (filePath == NULL) {
        perror("invalid filePath argument is null...\n");
        return;
    }

    //check for file existence
    if ((access((const char *) filePath, F_OK)) != 0) {
        perror("filePath does not exist...\n");
        return;
    }

    //check file read permission
    if ((access((const char *) filePath, R_OK)) != 0) {
        perror("current process does not have read permission...\n");
        return;
    }

    if (hexHashValue == NULL) {
        perror("invalid hexHashValue argument is null...\n");
        return;
    }

    //allocating a 32 bytes(256 bits)size memory to store sm3 hash value.
    unsigned char *hashValue = (unsigned char *) malloc(hashValueSize + 1);

    sm3_file((char *) filePath, hashValue);

    //appending '\0' to indicates the end.
    hashValue[hashValueSize] = stringEndingMark;

    //convert hash value to hexadecimal type.
    char2HexString(hashValue, hashValueSize, hexHashValue);

    //free unused memory
    free((void *) hashValue);

    return;
}

/**
 * calculate the size of appended plain text corresponding to plain text
 */
unsigned int calculatePlaintextSizeAfterAppending(const unsigned char *origin,
                                                  size_t originalSize) {
    //check parameters
    if (origin == NULL) {
        perror("original plain text is null...");
        return 0;
    }

    if (originalSize <= 0) {
        perror("invalid originalSize argument is <= 0...");
        return 0;
    }

    unsigned int sizeAfterAppending = originalSize
                                      + calculateAppendingBytes(origin, originalSize);

    return sizeAfterAppending;
}

/**
 * calculate the size of cipher text corresponding to plain text
 */
unsigned int calculateCiphertextSize(const unsigned char *origin,
                                     size_t originalSize, bool hexadecimal) {

    //check parameters
    if (origin == NULL) {
        perror("invalid origin argument is null...");
        return 0;
    }

    if (originalSize <= 0) {
        perror("invalid originalSize argument is <= 0...");
        return 0;
    }

    if (hexadecimal) {
        return calculatePlaintextSizeAfterAppending(origin, originalSize) * 2;
    } else {
        return calculatePlaintextSizeAfterAppending(origin, originalSize);
    }
}

/**
 * calculate the size of plain text corresponding to cipher text
 * If cipher text is hexadecimal,then the size of plain text is half size of cipher text.
 * If cipher text is non hexadecimal, the the size of plain text is the same as cipher text.
 */
unsigned int calculatePlaintextSize(const unsigned char *origin,
                                    size_t originalSize) {
    //check parameters
    if (origin == NULL) {
        perror("invalid origin argument is null...");
        return 0;
    }

    if (originalSize <= 0) {
        perror("invalid originalSize argument is <= 0...");
        return 0;
    }

    if (isHexString(origin, originalSize)) {
        return originalSize / 2;
    } else {
        return originalSize;
    }
}

/**
 * Calculating how many bytes should be appended to origin.
 * The goal is result of size of origin Mod 16 is 0.
 */
unsigned int calculateAppendingBytes(const unsigned char *origin,
                                     size_t originalSize) {

    //check parameters
    if (origin == NULL) {
        perror("invalid origin argument is null...");
        return 0;
    }

    if (originalSize <= 0) {
        perror("invalid originalSize argument is <= 0...");
        return 0;
    }

    if (originalSize % 16 == 0) {
        //origin has been appended already
        if (isAppendedText((unsigned char *) origin, originalSize)) {

            //calculate the number of appending byte.
            int i = 1;
            int appendingByteCount = 0;
            while (origin[originalSize - i] == appendingByte) {
                i++;
                appendingByteCount++;
            }

            return appendingByteCount;
        } else {
            return 0;
        }

    } else {
        if (isAppendedText((unsigned char *) origin, originalSize)) {
            perror(
                    "origin is invalid text, it has been appended already, but mod 16 is not 0...");
        } else {
            return 16 - (originalSize % 16);
        }
    }

    return 0;
}

/**
 * Appending origin text.
 * Make sure that the length of origin text Mod 16 is 0
 */
void appendByteToText(const unsigned char *origin, size_t originalSize,
                      unsigned char *destination, int appendingSize) {
    //check parameters
    if (origin == NULL) {
        perror("parameter origin is null...");
        return;
    }

    if (destination == NULL) {
        perror("parameter destination is null...");
        return;
    }

    if (originalSize <= 0) {
        perror("invalid originalSize argument is <= 0...");
        return;
    }

    memcpy(destination, origin, originalSize);

    //appending destination at index of originalSize
    int i;
    for (i = 0; i < appendingSize; i++) {
        destination[originalSize + i] = appendingByte;
    }

    //appending '\0' to indicate the end of text
    destination[originalSize + appendingSize] = stringEndingMark;

    return;
}

/**
 * Check whether input has been added appendingByte already or not.
 */
bool isAppendedText(unsigned char *input, size_t inputSize) {
    //check parameters
    if (input == NULL) {
        perror("remove byte from an null input...");
        return false;
    }

    if (inputSize <= 0) {
        perror("invalid inputSize argument is <= 0...");
        return false;
    }

    if (input[inputSize - 1] == appendingByte) {
        return true;
    } else {
        return false;
    }
}

/**
 * remove appending bytes from text
 */
void removeByteFromText(unsigned char *input) {

    //check parameters
    if (input == NULL) {
        perror("remove byte from an null input...");
        return;
    }

    unsigned int inputSize = strlen((const char *) input);

    if (!isAppendedText(input, inputSize)) {
        perror("remove byte from input which has not been appended...");
        return;
    }

    unsigned int appendingByteSize = calculateAppendingBytes(
            (const unsigned char *) input, (size_t) inputSize);

    /*
     * add '\0' at the last index of non-appending byte
     * to indicate the end of string.
     */
    input[inputSize - appendingByteSize] = stringEndingMark;

}

/*
 * Execute sm4 encryption
 * input[] is plain text
 * output[] is cipher text
 */
void sm4Encrypt(unsigned char input[], size_t inputSize, unsigned char output[]) {
    printf("sm4Encrypt is called... \n");

    //allocate sm4 context struct
    sm4_context sm4Context;

    //initialize sm4 security key
    printf("set sm4 security key... \n");
    sm4_setkey_enc(&sm4Context, key);

    //execute encrypt operation
    printf("execute sm4 encrypt operation \n");
    sm4_crypt_ecb(&sm4Context, SM4_ENCRYPT, (int) inputSize, input, output);

    //append '\0' to indicate the end of string
    output[inputSize] = stringEndingMark;
}

/**
 * Execute sm4 decrypt
 * input[] is cipher text.
 * output[] is plain text.
 */
void sm4Decrypt(unsigned char *input, size_t inputSize, unsigned char *output) {
    printf("sm4Decrypt is called...\n");

    //allocate sm4 context struct
    sm4_context ctx;

    //initialize sm4 security key
    printf("set sm4 security key... \n");
    sm4_setkey_dec(&ctx, key);

    //execute encrypt operation
    printf("execute sm4 decrypt operation \n");
    sm4_crypt_ecb(&ctx, SM4_DECRYPT, inputSize, input, output);

    //append '\0' to indicate the end of string
    output[inputSize] = stringEndingMark;

    //the size of cipher text and plain text is the same.
    if (strlen((const char *) input) != strlen((const char *) output)) {
        perror(
                "sm4 encrypt fail, cipher text's length not equals to plain text's length... \n");
        printf("sm4 plain text's length is %zd \n", inputSize);
        printf("sm4 cipher text's length is %d \n",
               (int) strlen((const char *) output));
        return;
    }
}

/*
 * convert char to hexadecimal string
 */
void char2HexString(unsigned char input[], size_t inputSize,
                    unsigned char output[]) {
    int i;
    unsigned char str[] = "0123456789abcdef"; //hexadecimal byte
//	unsigned char str[] = "abc"; //hexadecimal byte

//	unsigned char str[] = "2F917420E702DBA970C071AE4971AD08DE3D7D0D90DC1E"
//			"334ED20444E54F109BA80DD22F25C24FAA83D5AD58687F1AA68F1B749D0AD999DB9A1AC8E4DC";
    for (i = 0; i < inputSize; i++) {
        output[i * 2] = str[(input[i] >> 4) & 0x0f]; //将一个byte的高四位转成十六进制字符
        output[i * 2 + 1] = str[input[i] & 0x0f]; //将一个byte的低四位转成十六进制字符
    }

    //appending '\0' indicate the end of string
    output[inputSize * 2] = stringEndingMark;
}

/*
 * Convert hexadecimal to char string
 * This function does not use sterlen(input) to get inputSize.
 * Reason:
 * Even though hexadecimal string contains 00000000 byte which is not the end of string,
 * strlen() will consider it to be. So the inputSize will be less than the right value.
 */
void hexString2Char(unsigned char input[], unsigned int inputSize,
                    unsigned char output[]) {
    int i;

    for (i = 0; i < inputSize / 2; i++) {
        output[i] = (input[i * 2] << 4) | input[i * 2 + 1];
    }

    //appending '\0' indicates the end of string.
    output[inputSize / 2] = stringEndingMark;
}

/*
 * convert every ascii encoding char in input
 * to hexadecimal encoding
 * the size of input is unchanged.
 */
void ascii2Hex(const unsigned char *input, unsigned char *output) {
    int i;
    int number;
    int inputSize = strlen((const char *) input);

    for (i = 0; i < inputSize; i++) {

        //cast char to ascii decimal number
        number = (int) input[i];
        switch (number) {
            case 97:
                output[i] = 0x0a;
                break;
            case 98:
                output[i] = 0x0b;
                break;
            case 99:
                output[i] = 0x0c;
                break;
            case 100:
                output[i] = 0x0d;
                break;
            case 101:
                output[i] = 0x0e;
                break;
            case 102:
                output[i] = 0x0f;
                break;
            case 48:
                output[i] = 0x00;
                break;
            case 49:
                output[i] = 0x01;
                break;
            case 50:
                output[i] = 0x02;
                break;
            case 51:
                output[i] = 0x03;
                break;
            case 52:
                output[i] = 0x04;
                break;
            case 53:
                output[i] = 0x05;
                break;
            case 54:
                output[i] = 0x06;
                break;
            case 55:
                output[i] = 0x07;
                break;
            case 56:
                output[i] = 0x08;
                break;
            case 57:
                output[i] = 0x09;
                break;
            default:
                break;
        }
    }

    //appending '\0' indicates the end of string
    output[inputSize] = stringEndingMark;
}

/**
 * Get the byte size of the file which is indicated by filePath.
 */
unsigned long getFileSize(const char *filePath) {
    unsigned long filesize = -1;
    struct stat statbuff;
    if (stat(filePath, &statbuff) < 0) {
        return filesize;
    } else {
        filesize = statbuff.st_size;
    }
    return filesize;
}

/**
 * Check whether source is a hexadecimal string or not.
 */
bool isHexString(const unsigned char *source, size_t sourceSize) {
    //check parameters
    if (source == NULL) {
        perror("source argument is null ...");
        return false;
    }

    if (sourceSize <= 0) {
        perror("invalid sourceSize argument is <= 0...");
        return false;
    }

    //loop for each char in source to check.
    int i;
    for (i = 0; i < sourceSize; i++) {

        // if one char in source is not hexadecimal,then return false.
        if (!isxdigit((int) source[i])) {
            return false;
        }
    }

    // if all char in source are hexadecimal,then return true;
    return true;
}
