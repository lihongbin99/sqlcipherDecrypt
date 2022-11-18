#include "aes.h"

const unsigned char S_BOX[256] = {
	0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
	0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
	0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
	0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
	0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
	0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
	0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
	0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
	0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
	0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
	0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
	0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
	0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
	0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
	0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
	0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
};

const unsigned char ReS_BOX[256] = {
	0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
	0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
	0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
	0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
	0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
	0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
	0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
	0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
	0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
	0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
	0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
	0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
	0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
	0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
	0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
	0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D,
};

const unsigned char MixArray[16] = {
	0x02, 0x03, 0x01, 0x01,
	0x01, 0x02, 0x03, 0x01,
	0x01, 0x01, 0x02, 0x03,
	0x03, 0x01, 0x01, 0x02,
};

const unsigned char ReMixArray[16] = {
	0x0E, 0x0B, 0x0D, 0x09,
	0x09, 0x0E, 0x0B, 0x0D,
	0x0D, 0x09, 0x0E, 0x0B,
	0x0B, 0x0D, 0x09, 0x0E
};

const unsigned int Rcon[10] = {
	0x01, 0x02, 0x04, 0x08,
	0x10, 0x20, 0x40, 0x80,
	0x1B, 0x36,
};

void aesEncrypt(const unsigned char* in, int inLen,
	const unsigned char* key, const unsigned char* iv,
	unsigned char* out,
	int aesMode,
	int nk, int nr);
void aesDecrypt(const unsigned char* in, int inLen,
	const unsigned char* key, const unsigned char* iv,
	unsigned char* out,
	int aesMode,
	int nk, int nr);

void extendKey(unsigned char* subKey, int nk, int nr);
void AddRoundKey(unsigned char* state, unsigned char* key);
void SubBytes(unsigned char* state);
void ReSubBytes(unsigned char* state);
void ShiftRows(unsigned char* state);
void ReShiftRows(unsigned char* state);
void MixColumns(unsigned char* state, unsigned char* stateTemp);
void ReMixColumns(unsigned char* state, unsigned char* stateTemp);

int aesAlgorithm(const unsigned char* in, int inLen,
	const unsigned char* key, const unsigned char* iv,
	unsigned char* out,
	int aesMode, int keyLen, int paddingMode,
	int enc) {
	int nk, nr;

	switch (aesMode) {
	case AES_MODE_ECB:
		break;
	case AES_MODE_CBC:
		break;
	case AES_MODE_CFB:
		return 0;// 未支持
	case AES_MODE_OFB:
		return 0;// 未支持
	case AES_MODE_CTR:
		return 0;// 未支持
	default:
		return 0;
	}

	switch (keyLen) {
	case AES_KEY_LEN_128:
		nk = 4;
		nr = 10;
		break;
	case AES_KEY_LEN_192:
		nk = 6;
		nr = 12;
		break;
	case AES_KEY_LEN_256:
		nk = 8;
		nr = 14;
		break;
	default:
		return 0;
	}

	if (enc == AES_ENC_ENCRYPT) {
		switch (paddingMode) {
		case AES_PADDING_MODE_NONE:
			if (inLen % 16 != 0) {
				return 0;
			}
			break;
		case AES_PADDING_MODE_PKCS7:
			return 0;// 未支持
		case AES_PADDING_MODE_ISO7816_4:
			return 0;// 未支持
		case AES_PADDING_MODE_ANSI923:
			return 0;// 未支持
		case AES_PADDING_MODE_ISO10126:
			return 0;// 未支持
		case AES_PADDING_MODE_ZERO:
			return 0;// 未支持
		default:
			return 0;
		}
	}
	else if (inLen % 16 != 0) {
		return 0;
	}

	if (enc == AES_ENC_ENCRYPT) {
		aesEncrypt(in, inLen, key, iv, out, aesMode, nk, nr);
	}
	else if (enc == AES_ENC_DECRYPT) {
		aesDecrypt(in, inLen, key, iv, out, aesMode, nk, nr);
	}
	else {
		return 0;
	}

	if (enc == AES_ENC_DECRYPT) {
		switch (paddingMode) {
		case AES_PADDING_MODE_NONE:
			break;
		case AES_PADDING_MODE_PKCS7:
			return 0;// 未支持
		case AES_PADDING_MODE_ISO7816_4:
			return 0;// 未支持
		case AES_PADDING_MODE_ANSI923:
			return 0;// 未支持
		case AES_PADDING_MODE_ISO10126:
			return 0;// 未支持
		case AES_PADDING_MODE_ZERO:
			return 0;// 未支持
		default:
			return 0;
		}
	}

	return inLen;
}

void aesEncrypt(const unsigned char* in, int inLen,
	const unsigned char* key, const unsigned char* iv,
	unsigned char* out,
	int aesMode,
	int nk, int nr) {
	// 分配内存
	unsigned char* state = new unsigned char[AES_ROW * AES_COLUMNS];
	unsigned char* subKey = new unsigned char[AES_ROW * AES_COLUMNS * (nr + 1)];
	memcpy(subKey, key, nk * AES_COLUMNS);
	unsigned char* stateTemp = new unsigned char[AES_ROW * AES_COLUMNS];

	// 密钥扩展
	extendKey(subKey, nk, nr);

	// 分组加密
	for (int index = 0; index < inLen; index += AES_ROW * AES_COLUMNS) {
		memcpy(state, in + index, AES_ROW * AES_COLUMNS);

		if (aesMode == AES_MODE_CBC) {
			if (index == 0) {
				for (int i = 0; i < AES_ROW * AES_COLUMNS; ++i) {
					state[i] ^= iv[i];
				}
			}
			else {
				for (int i = 0; i < AES_ROW * AES_COLUMNS; ++i) {
					state[i] ^= out[index - AES_ROW * AES_COLUMNS + i];
				}
			}
		}

		// 在开始加密前先执行一次轮密钥加(密钥漂白)
		AddRoundKey(state, subKey);

		// 开始加密
		for (int currentNr = 0; currentNr < nr; ++currentNr) {
			// 字节代换层
			SubBytes(state);

			// 行位移
			ShiftRows(state);

			// 列混淆
			if (currentNr != nr - 1) {// 最后一轮不进行列混淆
				MixColumns(state, stateTemp);
			}
			// 密钥加法层
			AddRoundKey(state, subKey + AES_ROW * AES_COLUMNS * (currentNr + 1));
		}
		memcpy(out + index, state, AES_ROW * AES_COLUMNS);
	}

	// 释放内存
	delete[] state;
	delete[] subKey;
	delete[] stateTemp;
}

void aesDecrypt(const unsigned char* in, int inLen,
	const unsigned char* key, const unsigned char* iv,
	unsigned char* out,
	int aesMode,
	int nk, int nr) {
	// 分配内存
	unsigned char* state = new unsigned char[AES_ROW * AES_COLUMNS];
	unsigned char* subKey = new unsigned char[AES_ROW * AES_COLUMNS * (nr + 1)];
	memcpy(subKey, key, nk * AES_COLUMNS);
	unsigned char* stateTemp = new unsigned char[AES_ROW * AES_COLUMNS];

	// 密钥扩展
	extendKey(subKey, nk, nr);

	// 分组解密
	for (int index = inLen - AES_ROW * AES_COLUMNS; index >= 0; index -= AES_ROW * AES_COLUMNS) {
		memcpy(state, in + index, AES_ROW * AES_COLUMNS);

		// 开始解密
		for (int currentNr = nr - 1; currentNr >= 0; --currentNr) {
			// 密钥加法层
			AddRoundKey(state, subKey + AES_ROW * AES_COLUMNS * (currentNr + 1));

			// 列混淆
			if (currentNr != nr - 1) {// 最后一轮不进行列混淆
				ReMixColumns(state, stateTemp);
			}

			// 行位移
			ReShiftRows(state);

			// 字节代换层
			ReSubBytes(state);
		}

		// 在解密后需要在执行一次轮密钥加(密钥漂白)
		AddRoundKey(state, subKey);

		if (aesMode == AES_MODE_CBC) {
			if (index == 0) {
				for (int i = 0; i < AES_ROW * AES_COLUMNS; ++i) {
					state[i] ^= iv[i];
				}
			}
			else {
				for (int i = 0; i < AES_ROW * AES_COLUMNS; ++i) {
					state[i] ^= in[index - AES_ROW * AES_COLUMNS + i];
				}
			}
		}

		memcpy(out + index, state, AES_ROW * AES_COLUMNS);
	}

	// 释放内存
	delete[] state;
	delete[] subKey;
	delete[] stateTemp;
}

void extendKey(unsigned char* subKey, int nk, int nr) {
	int rconIndex = 0;
	for (int i = nk; i < (nr + 1) * AES_ROW; ++i) {
		unsigned char temp[AES_COLUMNS];
		memcpy(temp, subKey + ((i - 1) * AES_COLUMNS), sizeof(temp));

		if (i % nk == 0) {
			// 字循环
			unsigned int* tip = (unsigned int*)temp;
			*tip = (*tip) << 24 | (*tip) >> 8;
			// 字节代换
			temp[0] = S_BOX[temp[0]];
			temp[1] = S_BOX[temp[1]];
			temp[2] = S_BOX[temp[2]];
			temp[3] = S_BOX[temp[3]];
			// 轮常量异或
			temp[0] ^= Rcon[rconIndex++];
		}
		else if (nk == 8 && i % 4 == 0) {
			// AES-256 的特殊处理
			// 字节代换
			temp[0] = S_BOX[temp[0]];
			temp[1] = S_BOX[temp[1]];
			temp[2] = S_BOX[temp[2]];
			temp[3] = S_BOX[temp[3]];
		}

		subKey[i * AES_COLUMNS + 0] = subKey[(i - nk) * AES_COLUMNS + 0] ^ temp[0];
		subKey[i * AES_COLUMNS + 1] = subKey[(i - nk) * AES_COLUMNS + 1] ^ temp[1];
		subKey[i * AES_COLUMNS + 2] = subKey[(i - nk) * AES_COLUMNS + 2] ^ temp[2];
		subKey[i * AES_COLUMNS + 3] = subKey[(i - nk) * AES_COLUMNS + 3] ^ temp[3];
	}
}

void AddRoundKey(unsigned char* state, unsigned char* key) {
	for (int i = 0; i < AES_ROW * AES_COLUMNS; ++i) {
		state[i] ^= key[i];
	}
}

void SubBytes(unsigned char* state) {
	for (int i = 0; i < AES_ROW * AES_COLUMNS; ++i) {
		state[i] = S_BOX[state[i]];
	}
}

void ReSubBytes(unsigned char* state) {
	for (int i = 0; i < AES_ROW * AES_COLUMNS; ++i) {
		state[i] = ReS_BOX[state[i]];
	}
}

void ShiftRows(unsigned char* state) {
	int num = state[1];
	state[1] = state[5];
	state[5] = state[9];
	state[9] = state[13];
	state[13] = num;

	num = state[2];
	state[2] = state[10];
	state[10] = num;
	num = state[6];
	state[6] = state[14];
	state[14] = num;

	num = state[3];
	state[3] = state[15];
	state[15] = state[11];
	state[11] = state[7];
	state[7] = num;
}

void ReShiftRows(unsigned char* state) {
	int num = state[1];
	state[1] = state[13];
	state[13] = state[9];
	state[9] = state[5];
	state[5] = num;

	num = state[2];
	state[2] = state[10];
	state[10] = num;
	num = state[6];
	state[6] = state[14];
	state[14] = num;

	num = state[3];
	state[3] = state[7];
	state[7] = state[11];
	state[11] = state[15];
	state[15] = num;
}

unsigned char MixColumnsImpl(unsigned char mix, unsigned char num) {
	unsigned char result = 0;
	while (mix) {
		if (mix & 0x01) {
			result ^= num;
		}

		mix = mix >> 1;

		if (num & 0x80) {
			num = num << 1;
			num ^= 0x1B;
		}
		else {
			num = num << 1;
		}
	}
	return result;
}
void MixColumns(unsigned char* state, unsigned char* stateTemp) {
	memcpy(stateTemp, state, AES_ROW * AES_COLUMNS);
	for (int i = 0; i < AES_ROW; ++i) {
		for (int j = 0; j < AES_COLUMNS; j++) {
			state[i * AES_COLUMNS + j] =
				MixColumnsImpl(MixArray[j * AES_COLUMNS + 0], stateTemp[i * AES_COLUMNS + 0]) ^
				MixColumnsImpl(MixArray[j * AES_COLUMNS + 1], stateTemp[i * AES_COLUMNS + 1]) ^
				MixColumnsImpl(MixArray[j * AES_COLUMNS + 2], stateTemp[i * AES_COLUMNS + 2]) ^
				MixColumnsImpl(MixArray[j * AES_COLUMNS + 3], stateTemp[i * AES_COLUMNS + 3]);
		}
	}
}

void ReMixColumns(unsigned char* state, unsigned char* stateTemp) {
	memcpy(stateTemp, state, AES_ROW * AES_COLUMNS);
	for (int i = 0; i < AES_ROW; ++i) {
		for (int j = 0; j < AES_COLUMNS; j++) {
			state[i * AES_COLUMNS + j] =
				MixColumnsImpl(ReMixArray[j * AES_COLUMNS + 0], stateTemp[i * AES_COLUMNS + 0]) ^
				MixColumnsImpl(ReMixArray[j * AES_COLUMNS + 1], stateTemp[i * AES_COLUMNS + 1]) ^
				MixColumnsImpl(ReMixArray[j * AES_COLUMNS + 2], stateTemp[i * AES_COLUMNS + 2]) ^
				MixColumnsImpl(ReMixArray[j * AES_COLUMNS + 3], stateTemp[i * AES_COLUMNS + 3]);
		}
	}
}