#include "pingWrapper.h"
#include <iostream>
#include <time.h>



#define IP_TTL 4  //from #include <ws2tcpip.h>

#define PLATFORM_WIN32  1
//#define PLATFORM_LUNIX  1

//#ifdef PLATFORM_LUNIX
//#include <unistd.h>
//#include <sys/time.h>
//#include <sys/socket.h>
//#include <netinet/in.h>
//#include <arpa/inet.h>
//#include <netdb.h>
//
//typedef int             SOCKET;
//typedef unsigned char   BYTE;
//typedef unsigned short  USHORT;
//typedef unsigned long   DWORD;
//
//#define SOCKET_ERROR    -1
//#else
//#endif // PLATFORM_LUNIX
#include <winsock2.h>
#pragma comment(lib, "WS2_32") // 鏈接到WS2_32.lib


#define _LOG(...) {\
do \
{\
	printf(##__VA_ARGS__); \
	printf("\n"); \
} while (0); \
}\

// IP報頭  共20bytes
typedef struct
{
	unsigned char hdr_len : 4;         //4位頭部長度
	unsigned char version : 4;         //4位版本號
	unsigned char tos;               //8位服務類型
	unsigned short total_len;        //16位總長度
	unsigned short identifier;       //16位標識符
	unsigned short frag_and_flags;   //3位標誌加13位片偏移
	unsigned char ttl;               //8位生存時間
	unsigned char protocol;          //8位上層協議號
	unsigned short checksum;         //16位效驗和
	unsigned long sourceIP;          //32位源IP地址
	unsigned long destIP;            //32位目的IP地址
}IP_HEADER;

//ICMP報頭
typedef struct
{
	BYTE type;     //8位類型字段
	BYTE code;     //8位代碼字段
	USHORT cksum;  //16位效驗和
	USHORT id;     //16位標識符
	USHORT seq;    //16位序列號
}ICMP_HEADER;


//報文解碼結構
typedef struct 
{
	USHORT usSeqNo;          //序列號
	DWORD dwRoundTripTime;   //返回時間
	in_addr dwIPaddr;        //返回報文的IP地址
}DECODE_RESULT;


//計算網際效驗和函數
USHORT checksum(USHORT* pBuf, int iSize)
{
	unsigned long cksum = 0;
	while (iSize > 1)
	{
		cksum += *pBuf++;
		iSize -= sizeof(USHORT);
	}
	if (iSize)
	{
		cksum += *(USHORT*)pBuf;
	}
	cksum = (cksum >> 16) + (cksum & 0xffff);
	cksum += (cksum >> 16);
	return(USHORT)(~cksum);
}

//decode data
bool DecodeIcmpResponse(char* pBuf, int iPacketSize, DECODE_RESULT& DecodeResult, BYTE ICMP_ECHO_REPLY, BYTE ICMP_TIMEOUT)
{
	//檢查數據報大小的合法性
	IP_HEADER* pIpHdr = (IP_HEADER*)pBuf;
	int iIpHdrLen = pIpHdr->hdr_len * 4;
	if (iPacketSize < (int)(iIpHdrLen + sizeof(ICMP_HEADER)))
		return false;
	//根據ICMP報文類型提取ID字段和序列號字段
	ICMP_HEADER* pIcmpHdr = (ICMP_HEADER*)(pBuf + iIpHdrLen);
	USHORT usID, usSquNo;
	if (pIcmpHdr->type == ICMP_ECHO_REPLY)    //ICMP回顯應答報文
	{
		usID = pIcmpHdr->id;   //報文ID
		usSquNo = pIcmpHdr->seq;  //報文序列號
	}
	else if (pIcmpHdr->type == ICMP_TIMEOUT)   //ICMP超時差錯報文
	{
		char* pInnerIpHdr = pBuf + iIpHdrLen + sizeof(ICMP_HEADER);  //載荷中的IP頭
		int iInnerIPHdrLen = ((IP_HEADER*)pInnerIpHdr)->hdr_len * 4; //載荷中的IP頭長
		ICMP_HEADER* pInnerIcmpHdr = (ICMP_HEADER*)(pInnerIpHdr + iInnerIPHdrLen);//載荷中的ICMP頭
		usID = pInnerIcmpHdr->id;  //報文ID
		usSquNo = pInnerIcmpHdr->seq;  //序列號
	}
	else {
		return false;
	}
	//檢查ID和序列號以確定收到期待數據報

	if (usID != (USHORT)pingWrapper::getInstance()->getCurProcessId() || usSquNo != DecodeResult.usSeqNo)
	{
		return false;
	}

	//記錄IP地址並計算往返時間
	DecodeResult.dwIPaddr.s_addr = pIpHdr->sourceIP;
	DecodeResult.dwRoundTripTime = pingWrapper::getInstance()->getTime() - DecodeResult.dwRoundTripTime;

	//處理正確收到的ICMP數據報
	if (pIcmpHdr->type == ICMP_ECHO_REPLY || pIcmpHdr->type == ICMP_TIMEOUT)
	{
		return true;
	}
	else {
		return false;
	}
	return true;
}

//---
static pingWrapper* instance = nullptr;
pingWrapper* pingWrapper::getInstance()
{
	if (!instance)
	{
		instance = new pingWrapper;
	}
	return instance;
}

pingWrapper::pingWrapper()
{
	this->init();
}

pingWrapper::~pingWrapper()
{

}

void pingWrapper::init()
{
#ifdef PLATFORM_WIN32
	WSADATA wsaData;
	WORD sockVersion = MAKEWORD(2, 2);
	if (::WSAStartup(sockVersion, &wsaData) != 0)
	{
		printf("init socket failed \n");
	}
#endif
}

void pingWrapper::checkNetSpeed(const std::vector<std::string>& vec)
{
	auto p = std::thread(std::bind(&pingWrapper::pingAll, this, vec));
	p.detach();
}

void pingWrapper::pingAll(const std::vector<std::string>& vec)
{
	for (auto v : vec) {
		this->ping(v.c_str());
	}
	_LOG("pingAll finish");
}

void pingWrapper::ping(const char* ip)
{
	char IpAddress[255] = { 0 };
	sprintf(IpAddress, "%s", ip);
	u_long ulDestIP = inet_addr(IpAddress);
	//轉換不成功時按域名解析
	if (ulDestIP == INADDR_NONE)
	{
		hostent* pHostent = gethostbyname(IpAddress);
		if (pHostent)
		{
			ulDestIP = (*(in_addr*)pHostent->h_addr).s_addr;
		}
		else
		{
			_LOG("invalid ip");
#ifdef PLATFORM_WIN32
			WSACleanup();
#endif
			return;
		}
	}
	_LOG("Ping %s 32 bytes data：\n", IpAddress);

	sockaddr_in destSockAddr;
	memset(&destSockAddr, 0, sizeof(sockaddr_in));
	destSockAddr.sin_family = AF_INET;
	destSockAddr.sin_addr.s_addr = ulDestIP;

	SOCKET sockRaw = -1;
#ifdef PLATFORM_WIN32
	int timeout = 3000;
	sockRaw = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	setsockopt(sockRaw, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
	setsockopt(sockRaw, SOL_SOCKET, SO_SNDTIMEO, (char*)&timeout, sizeof(timeout));
#else
	struct timeval timeout = { 1,0 };
	sockRaw = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
	setsockopt(sockRaw, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
	setsockopt(sockRaw, SOL_SOCKET, SO_SNDTIMEO, (char*)&timeout, sizeof(timeout));
#endif
	//構造ICMP回顯請求消息，並以TTL遞增的順序發送報文
	//ICMP類型字段
	const BYTE ICMP_ECHO_REQUEST = 8;   //請求回顯
	const BYTE ICMP_ECHO_REPLY = 0;     //回顯應答
	const BYTE ICMP_TIMEOUT = 11;       //傳輸超時

	const int DEF_ICMP_DATA_SIZE = 32;     //ICMP報文默認數據字段長度
	const int MAX_ICMP_PACKET_SIZE = 1024; //ICMP報文最大長度（包括報頭）
	const int DEF_MAX_HOP = 4;             //最大跳站數

	//填充ICMP報文中每次發送時不變的字段
	char IcmpSendBuf[sizeof(ICMP_HEADER) + DEF_ICMP_DATA_SIZE]; //發送緩衝區
	memset(IcmpSendBuf, 0, sizeof(IcmpSendBuf));     //初始化發送緩衝區
	char IcmpRecvBuf[MAX_ICMP_PACKET_SIZE];        //接收緩衝區
	memset(IcmpRecvBuf, 0, sizeof(IcmpRecvBuf));     //初始化接收緩衝區

	ICMP_HEADER* pIcmpHeader = (ICMP_HEADER*)IcmpSendBuf;
	pIcmpHeader->type = ICMP_ECHO_REQUEST;             //類型爲請求回顯
	pIcmpHeader->code = 0;                             //代碼字段爲0
	pIcmpHeader->id = (USHORT)this->getCurProcessId();   //ID字段爲當前進程號
	memset(IcmpSendBuf + sizeof(ICMP_HEADER), 'E', DEF_ICMP_DATA_SIZE);   //數據字段
	USHORT usSeqNo = 0;                //ICMP報文序列號
	int iTTL = 64;                      //TTL初始值爲1
	int recvNum = 0, loseNum = 0;
	bool bReachDestHost = false;       //循環退出標誌
	int iMaxHop = DEF_MAX_HOP;         //循環的最大次數
	DECODE_RESULT DecodeResult;      //傳遞給報文解碼函數的結構化參數
	int sumTime = 0;
	while (!bReachDestHost && iMaxHop--)
	{
		//設置IP報頭的TTL字段
		setsockopt(sockRaw, IPPROTO_IP, IP_TTL, (char*)&iTTL, sizeof(iTTL));
		//填充ICMP報文中每次發送變化的字段
		((ICMP_HEADER*)IcmpSendBuf)->cksum = 0;                 //效驗和先置爲0
		((ICMP_HEADER*)IcmpSendBuf)->seq = htons(usSeqNo++);    //填充序列號
		((ICMP_HEADER*)IcmpSendBuf)->cksum = checksum((USHORT*)IcmpSendBuf, sizeof(ICMP_HEADER) + DEF_ICMP_DATA_SIZE);  //計算效驗和
		
		//記錄序列號和當前時間
		DecodeResult.usSeqNo = ((ICMP_HEADER*)IcmpSendBuf)->seq;    //當前序號
		DecodeResult.dwRoundTripTime = this->getTime();              //當前時間
		//發送TCP回顯請求信息
		sendto(sockRaw, IcmpSendBuf, sizeof(IcmpSendBuf), 0, (sockaddr*)&destSockAddr, sizeof(destSockAddr));
		//接收ICMP差錯報文並進行解析處理
		sockaddr_in from;                   //對端socket地址
		size_t iFromLen = sizeof(from);     //地址結構大小
		int iReadDataLen;
		while (1)
		{
			//iReadDataLen = recvfrom(sockRaw, IcmpRecvBuf, MAX_ICMP_PACKET_SIZE, 0, (sockaddr*)&from, &iFromLen);
			iReadDataLen = recv(sockRaw, IcmpRecvBuf, MAX_ICMP_PACKET_SIZE, 0);
			if (iReadDataLen != SOCKET_ERROR)//read data sucess
			{
				//decode
				if (DecodeIcmpResponse(IcmpRecvBuf, iReadDataLen, DecodeResult, ICMP_ECHO_REPLY, ICMP_TIMEOUT))
				{
					//到達目的地，退出循環
					if (this->isReachGoalIp() || DecodeResult.dwIPaddr.s_addr == destSockAddr.sin_addr.s_addr) {
						if (DecodeResult.dwRoundTripTime) {
							sumTime += DecodeResult.dwRoundTripTime;
							_LOG("   from %s  respond: bytes 32 time %d ms TTL:%d", inet_ntoa(DecodeResult.dwIPaddr), DecodeResult.dwRoundTripTime, iTTL);
						}
						else {
							sumTime += 1;
							_LOG("   from %s  respond: bytes 32 time< 1ms TTL:%d", inet_ntoa(DecodeResult.dwIPaddr), iTTL);
						}
						recvNum++;
						break;
					}

				}
			}
			else if (this->isTimeOut())
			{
				_LOG("time out...");
				loseNum++;
				sumTime += 9999;
				break;
			}
			else {
				break;
			}
		}
	}
	_LOG("\n%s Ping infos:", IpAddress);
	_LOG("\t data package:send=4,rec=%d,lose=%d,,ave time %d ms \n", recvNum, loseNum, sumTime / DEF_MAX_HOP);
	m_pingTimeMap[ip] = sumTime / DEF_MAX_HOP;

#ifdef PLATFORM_WIN32
	closesocket(sockRaw);
#elif defined PLATFORM_LUNIX
	close(sockRaw);
#endif
}

int pingWrapper::getCurProcessId()
{
#ifdef PLATFORM_WIN32
	return GetCurrentProcessId();
#elif defined PLATFORM_LUNIX
	return getpid();
#endif
}

int pingWrapper::getTime()
{
#ifdef PLATFORM_WIN32
	return GetTickCount();
#endif // PLATFORM_WIN32

#ifdef PLATFORM_LUNIX
	struct timeval tv;
	gettimeofday(&tv, NULL);
	return tv.tv_sec * 1000 + tv.tv_usec / 1000;
#endif
	return 0;
}


bool pingWrapper::isTimeOut()
{
#ifdef PLATFORM_WIN32
	return WSAGetLastError() == WSAETIMEDOUT;
#elif defined PLATFORM_LUNIX
	return (errno == ETIME || errno == EAGAIN);
#endif
	return false;
}

bool pingWrapper::isReachGoalIp()
{
#ifdef PLATFORM_LUNIX
	return true
#endif
		return false;
}