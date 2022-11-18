#pragma once

#include "base.h"

#define SHA1_GROUP_BIT 512
#define SHA1_GROUP_LEN (SHA1_GROUP_BIT / 8)
#define SHA1_LAST_BIT  64
#define SHA1_LAST_LEN  (SHA1_LAST_BIT / 8)
void sha1Encode(const unsigned char* message, int messageLen, unsigned char* out);
