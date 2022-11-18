#pragma once

#include "base.h"
#include "hmac.h"

void kdfHmacSha1(const unsigned char* key, int keyLen, const unsigned char* salt, int saltLen, int iter, int outLen, unsigned char* out);