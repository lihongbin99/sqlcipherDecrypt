#pragma once

#include "base.h"

#define AES_MODE_ECB 1
#define AES_MODE_CBC 2
#define AES_MODE_CFB 3
#define AES_MODE_OFB 4
#define AES_MODE_CTR 5

#define AES_KEY_LEN_128 128
#define AES_KEY_LEN_192 192
#define AES_KEY_LEN_256 256

#define AES_PADDING_MODE_NONE        0
#define AES_PADDING_MODE_PKCS7       1
#define AES_PADDING_MODE_ISO7816_4   2
#define AES_PADDING_MODE_ANSI923     3
#define AES_PADDING_MODE_ISO10126    4
#define AES_PADDING_MODE_ZERO        5

#define AES_ENC_ENCRYPT 1
#define AES_ENC_DECRYPT 0

#define AES_ROW     4
#define AES_COLUMNS 4

int aesAlgorithm(
	const unsigned char* in, int inLen,
	const unsigned char* key, const unsigned char* iv,
	unsigned char* out,
	int aesMode, int keyLen, int paddingMode,
	int enc
);
