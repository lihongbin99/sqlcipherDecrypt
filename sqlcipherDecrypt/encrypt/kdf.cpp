#include "kdf.h"

void kdfHmacSha1(const unsigned char* key, int keyLen, const unsigned char* salt, int saltLen, int iter, int outLen, unsigned char* out) {
	unsigned char hmacSha1Out[20];
	unsigned char hmacSha1OutTemp[20];
	int currentIter = 1;
	int currentOutLen = 0;

	unsigned char* value = new unsigned char[saltLen + 4];
	memcpy(value, salt, saltLen);
	while (currentOutLen < outLen) {
		value[saltLen + 0] = (unsigned char)((currentIter >> 24) & 0xFF);
		value[saltLen + 1] = (unsigned char)((currentIter >> 16) & 0xFF);
		value[saltLen + 2] = (unsigned char)((currentIter >> 8) & 0xFF);
		value[saltLen + 3] = (unsigned char)((currentIter) & 0xFF);
		hmacSha1(key, keyLen, value, saltLen + 4, hmacSha1Out);

		if (iter > 1) {
			memcpy(hmacSha1OutTemp, hmacSha1Out, 20);
			for (int i = 1; i < iter; ++i) {
				hmacSha1(key, keyLen, hmacSha1OutTemp, 20, hmacSha1OutTemp);
				for (int j = 0; j < 20; ++j) {
					hmacSha1Out[j] ^= hmacSha1OutTemp[j];
				}
			}
		}

		memcpy(out + currentOutLen, hmacSha1Out, outLen - currentOutLen < 20 ? outLen - currentOutLen : 20);
		currentIter++;
		currentOutLen += 20;
	}
	delete[] value;
}