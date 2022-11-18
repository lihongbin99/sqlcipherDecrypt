#pragma once

#include "base.h"
#include "sha.h"

void hmacSha1(const unsigned char* key, int keyLen, const unsigned char* message, int messageLen, unsigned char* out);
