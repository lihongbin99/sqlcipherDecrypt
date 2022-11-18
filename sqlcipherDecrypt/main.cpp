#include <windows.h>

#include "encrypt/kdf.h"
#include "encrypt/aes.h"

#define IV_SIZE 16
#define HMAC_SHA1_SIZE 20
#define KEY_SIZE 32
#define DEFAULT_PAGESIZE 4096
#define DEFAULT_ITER 64000
#define AES_BLOCK_SIZE 16
#define SQLITE3 "SQLite format 3"

void doMain(WCHAR* filePath, int pathLen, BYTE* key);
BOOL decryptDb(WCHAR* basePath, int basePathLen, LPCWCH path, int pathLen, WCHAR* name, BYTE* key);
size_t openFile(WCHAR* file, BYTE** buf);
size_t createFile(WCHAR* file, BYTE* buf, int len);

int main() {
	setlocale(LC_ALL, "chs");

	BYTE key[0x20]{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20 };
	WCHAR filePath[] = L"C:\\Users\\Lee\\Documents\\Msg\\";

	WCHAR pathBuf[MAX_PATH];
	memcpy(pathBuf, filePath, sizeof(filePath));

	doMain(pathBuf, sizeof(filePath) / sizeof(WCHAR) - 1, key);

	wprintf(L"解密完成, 输入任意字符退出程序\n");
	getchar();

	return EXIT_SUCCESS;
}

void doMain(WCHAR* filePath, int pathLen, BYTE* key) {
	WCHAR tag[] = L"*.db";
	memcpy(filePath + pathLen, tag, sizeof(tag));

	WIN32_FIND_DATAW dir;
	HANDLE handle = FindFirstFileW(filePath, &dir);
	if (handle == INVALID_HANDLE_VALUE) {
		wprintf(L"获取文件目录失败\n");
		return;
	}

	do {
		wprintf(L"开始解密: %ls\n", dir.cFileName);
		decryptDb(filePath, pathLen, L"\\decrypt\\", 9, dir.cFileName, key);
	} while (FindNextFileW(handle, &dir));

}

BOOL decryptDb(WCHAR* basePath, int basePathLen, LPCWCH path, int pathLen, WCHAR* name, BYTE* srcKey) {
	WCHAR* srcFile = basePath;
	memcpy(srcFile + basePathLen, name, (lstrlenW(name) + 1) * sizeof(WCHAR));

	WCHAR decryptFile[MAX_PATH];
	DWORD currentPathLen = GetCurrentDirectoryW(sizeof(decryptFile) / sizeof(WCHAR), decryptFile);
	memcpy(decryptFile + currentPathLen, path, pathLen * sizeof(WCHAR));
	decryptFile[currentPathLen + pathLen] = 0;

	CreateDirectoryW(decryptFile, NULL) != 0;
	memcpy(decryptFile + currentPathLen + pathLen, name, (lstrlenW(name) + 1) * sizeof(WCHAR));

	BYTE* fileBuf = NULL;
	size_t fileSize = openFile(srcFile, &fileBuf);
	if (fileSize == 0) {
		return FALSE;
	}

	if (!memcmp(fileBuf, SQLITE3, sizeof(SQLITE3))) {
		wprintf(L"%ls 文件本身没有加密, 不进行解密\n", name);
		return TRUE;
	}

	BYTE salt[IV_SIZE];
	memcpy(salt, fileBuf, IV_SIZE);
	BYTE mac_salt[IV_SIZE];
	memcpy(mac_salt, fileBuf, IV_SIZE);
	for (int i = 0; i < sizeof(salt); i++) {
		mac_salt[i] ^= 0x3a;
	}

	BYTE key[KEY_SIZE] = { 0 };
	BYTE macKey[KEY_SIZE] = { 0 };

	kdfHmacSha1(srcKey, 0x20, salt, sizeof(salt), DEFAULT_ITER, sizeof(key), key);
	kdfHmacSha1(key, sizeof(key), mac_salt, sizeof(mac_salt), 2, sizeof(macKey), macKey);

	int reserve = IV_SIZE + HMAC_SHA1_SIZE;
	// 保持 AES 的 16 位对齐
	reserve = ((reserve % AES_BLOCK_SIZE) == 0) ? reserve : ((reserve / AES_BLOCK_SIZE) + 1) * AES_BLOCK_SIZE;

	BYTE* tempBuf = fileBuf;
	int page = 1;
	BYTE* pageBuf = new BYTE[fileSize];
	BYTE* wPageBuf = pageBuf;
	int pageLen = 0;
	int offset = IV_SIZE;// 第一页有16字节的iv
	while (tempBuf < fileBuf + fileSize) {
		// 判断 hmac 是否一致
		BYTE hmac[HMAC_SHA1_SIZE] = { 0 };
		BYTE* hmacBuf = new BYTE[DEFAULT_PAGESIZE - reserve - offset + IV_SIZE + sizeof(page)];
		memcpy(hmacBuf, tempBuf + offset, DEFAULT_PAGESIZE - reserve - offset + IV_SIZE);
		memcpy(hmacBuf + DEFAULT_PAGESIZE - reserve - offset + IV_SIZE, (const unsigned char*)&page, sizeof(page));
		hmacSha1(macKey, sizeof(macKey), hmacBuf, DEFAULT_PAGESIZE - reserve - offset + IV_SIZE + sizeof(page), hmac);
		delete[] hmacBuf;

		BYTE* fileHMAC = tempBuf + DEFAULT_PAGESIZE - reserve + IV_SIZE;
		if (0 != memcmp(hmac, fileHMAC, sizeof(hmac))) {
			for (int i = 0; i < HMAC_SHA1_SIZE; ++i) {
				if ((int)fileHMAC[i] != 0) {
					wprintf(L"在 %d/%d 中出现了 HMAC 校验错误\n", page, fileSize / DEFAULT_PAGESIZE);
					return FALSE;
				}
			}
			break;
		}

		if (page == 1) {
			memcpy(wPageBuf, SQLITE3, sizeof(SQLITE3));
		}

		// 解密数据
		aesAlgorithm(tempBuf + offset, DEFAULT_PAGESIZE - reserve - offset, key, tempBuf + (DEFAULT_PAGESIZE - reserve), wPageBuf + offset, AES_MODE_CBC, AES_KEY_LEN_256, AES_PADDING_MODE_NONE, AES_ENC_DECRYPT);

		page++;
		offset = 0;// 剩余页没有16字节的iv
		tempBuf += DEFAULT_PAGESIZE;
		pageLen += DEFAULT_PAGESIZE;
		wPageBuf += DEFAULT_PAGESIZE;
	}

	size_t writeLen = createFile(decryptFile, pageBuf, pageLen);
	if (writeLen == 0) {
		return FALSE;
	}
	return TRUE;
}

size_t openFile(WCHAR* file, BYTE** buf) {
	HANDLE hFile = CreateFileW(file, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, NULL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		wprintf(L"打开文件失败: %d\n", GetLastError());
		return 0;
	}

	DWORD fileSize = GetFileSize(hFile, NULL);
	*buf = (BYTE*)malloc(sizeof(BYTE) * fileSize);

	DWORD readSize;
	BOOL readFlag = ReadFile(hFile, *buf, fileSize, &readSize, NULL);
	if (!readFlag || readSize != fileSize) {
		wprintf(L"读取文件异常\n");
		return 0;
	}
	CloseHandle(hFile);
	return fileSize;
};

size_t createFile(WCHAR* file, BYTE* buf, int len) {
	HANDLE hFile = CreateFileW(file, GENERIC_WRITE, FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, NULL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		wprintf(L"创建文件失败: %d\n", GetLastError());
		return 0;
	}

	DWORD writeSize;
	BOOL writeFlag = WriteFile(hFile, buf, len, &writeSize, NULL);
	if (!writeFlag || writeSize != len) {
		wprintf(L"写入文件异常\n");
		return 0;
	}
	CloseHandle(hFile);
	return writeSize;
}