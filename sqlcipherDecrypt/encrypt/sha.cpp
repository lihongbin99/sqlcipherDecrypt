#include "sha.h"

unsigned int sha1_get_k(int i) {
	if (i < 20) {
		return 0x5A827999;
	}
	else if (i < 40) {
		return 0x6ED9EBA1;
	}
	else if (i < 60) {
		return 0x8F1BBCDC;
	}
	else {
		return 0xCA62C1D6;
	}
}

unsigned int sha1_f(int i, unsigned int b, unsigned int c, unsigned int d) {
	if (i < 20) {
		return d ^ (b & (c ^ d));
	}
	else if (i < 40) {
		return b ^ c ^ d;
	}
	else if (i < 60) {
		return (b & c) | (b & d) | (c & d);
	}
	else {
		return b ^ c ^ d;
	}
}

void sha1Encode(const unsigned char* message, int messageLen, unsigned char* out) {
	int paddingCount = SHA1_GROUP_LEN - messageLen % SHA1_GROUP_LEN;
	paddingCount = paddingCount < SHA1_LAST_LEN + 1 ? SHA1_GROUP_LEN - SHA1_LAST_LEN + paddingCount : paddingCount - SHA1_LAST_LEN;// TODO 测试如果正好不用填充或者只用填充一个1的时候需要增加填充

	long long bufLen = messageLen + paddingCount + SHA1_LAST_LEN;
	unsigned char* buf = new unsigned char[bufLen];

	memcpy(buf, message, messageLen);
	buf[messageLen] = 0x80;
	for (int i = 0; i < paddingCount; ++i) {
		buf[messageLen + i + 1] = 0;
	}
	long long lastLen = messageLen * 8;
	buf[bufLen - SHA1_LAST_LEN + 0] = (unsigned char)(lastLen >> 56);
	buf[bufLen - SHA1_LAST_LEN + 1] = (unsigned char)(lastLen >> 48);
	buf[bufLen - SHA1_LAST_LEN + 2] = (unsigned char)(lastLen >> 40);
	buf[bufLen - SHA1_LAST_LEN + 3] = (unsigned char)(lastLen >> 32);
	buf[bufLen - SHA1_LAST_LEN + 4] = (unsigned char)(lastLen >> 24);
	buf[bufLen - SHA1_LAST_LEN + 5] = (unsigned char)(lastLen >> 16);
	buf[bufLen - SHA1_LAST_LEN + 6] = (unsigned char)(lastLen >> 8);
	buf[bufLen - SHA1_LAST_LEN + 7] = (unsigned char)(lastLen >> 0);

	unsigned int a = 0x67452301;
	unsigned int b = 0xEFCDAB89;
	unsigned int c = 0x98BADCFE;
	unsigned int d = 0x10325476;
	unsigned int e = 0xC3D2E1F0;

	unsigned char w[80 * 32];       // 把 512bit 分为 16dword 再扩充为 80dword
	for (int group = 0; group < bufLen / SHA1_GROUP_LEN; ++group) {
		// 数据扩充
		unsigned int* iw = (unsigned int*)w;
		for (int wi = 0; wi < 80; wi++) {
			if (wi < SHA1_GROUP_BIT / 32) {
				*(iw + wi) = 0;
				*(iw + wi) += (((unsigned int*)buf + group * (SHA1_GROUP_BIT / 32))[wi]) >> 24;
				*(iw + wi) += ((((unsigned int*)buf + group * (SHA1_GROUP_BIT / 32))[wi]) >> 8) & 0x0000FF00;
				*(iw + wi) += ((((unsigned int*)buf + group * (SHA1_GROUP_BIT / 32))[wi]) << 8) & 0x00FF0000;
				*(iw + wi) += ((((unsigned int*)buf + group * (SHA1_GROUP_BIT / 32))[wi]) << 24) & 0xFF000000;
			}
			else {
				unsigned int num = iw[wi - 3] ^ iw[wi - 8] ^ iw[wi - 14] ^ iw[wi - 16];
				*(iw + wi) = num << 1 | num >> 31;
			}
		}

		unsigned int aa = a;
		unsigned int bb = b;
		unsigned int cc = c;
		unsigned int dd = d;
		unsigned int ee = e;

		// 主循环
		for (int i = 0; i < 80; ++i) {
			unsigned int t = (aa << 5 | aa >> 27) + sha1_f(i, bb, cc, dd) + ee + sha1_get_k(i) + iw[i];
			ee = dd;
			dd = cc;
			cc = bb << 30 | bb >> 2;
			bb = aa;
			aa = t;
		}
		// 最终处理
		a = aa + a;
		b = bb + b;
		c = cc + c;
		d = dd + d;
		e = ee + e;
	}

	out[0] = a >> 24;
	out[1] = a >> 16;
	out[2] = a >> 8;
	out[3] = a;
	out[4] = b >> 24;
	out[5] = b >> 16;
	out[6] = b >> 8;
	out[7] = b;
	out[8] = c >> 24;
	out[9] = c >> 16;
	out[10] = c >> 8;
	out[11] = c;
	out[12] = d >> 24;
	out[13] = d >> 16;
	out[14] = d >> 8;
	out[15] = d;
	out[16] = e >> 24;
	out[17] = e >> 16;
	out[18] = e >> 8;
	out[19] = e;
}