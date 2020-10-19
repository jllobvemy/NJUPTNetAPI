#include <WS2tcpip.h>
#include <iphlpapi.h>
#include <WinSock2.h>
#include <Windows.h>
#include <winhttp.h>
#include <codecvt>
#include <locale>
#include <sstream>
#include <utility>
#include <iostream>
#include "auto_login.hpp"

#pragma comment(lib,"Ws2_32.lib")
#pragma comment(lib,"Iphlpapi.lib")
#pragma comment(lib, "winhttp.lib")

void FreeIpForwardTable(PMIB_IPFORWARDTABLE pIpRouteTab)
{
	GlobalFree(pIpRouteTab);
}

PMIB_IPFORWARDTABLE GetIpForwardTable_(BOOL bOrder)
{
	PMIB_IPFORWARDTABLE pIpRouteTab = NULL;
	DWORD dwActualSize = 0;

	// 查询所需缓冲区的大小  
	if (GetIpForwardTable(pIpRouteTab, &dwActualSize, bOrder) == ERROR_INSUFFICIENT_BUFFER)
	{
		// 为MIB_IPFORWARDTABLE结构申请内存  
		pIpRouteTab = static_cast<PMIB_IPFORWARDTABLE>(GlobalAlloc(GPTR, dwActualSize));
		// 获取路由表  
		if (GetIpForwardTable(pIpRouteTab, &dwActualSize, bOrder) == NO_ERROR)
			return pIpRouteTab;
		GlobalFree(pIpRouteTab);
	}
	return NULL;
}


auto_login::auto_login(std::string _username, std::string _passwd, operators _operator, std::string _ip):
username(std::move(_username)), passwd(std::move(_passwd)), opt(_operator), ip_(std::move(_ip))
{
	check_status();
}

std::string format_operator(auto_login::operators o)
{
	switch (o)
	{
	case auto_login::operators::china_net:
		return std::string("@njxy");
	case auto_login::operators::cmcc:
		return std::string("@cmcc");
	case auto_login::operators::campus:
		return std::string("");
	}
	throw std::exception("operator format error");
}

auto_login::login_status auto_login::login()
{
	// 重复登录
	if (status)
		return login_status::repeat_login;
	
	std::stringstream error_msg;
	std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> convert;
	std::wstring wsIp = convert.from_bytes(ip_.c_str());
	std::wstring params = L"/eportal/?c=ACSetting&a=Login&protocol=http:&hostname=10.10.244.11&iTermType=1&wlanuserip="+ wsIp + L"&wlanacip=10.255.252.150&wlanacname=XL-BRAS-SR8806-X&mac=00-00-00-00-00-00&ip="+ wsIp +L"&enAdvert=0&queryACIP=0&loginMethod=1";
	std::string sData = "DDDDD=,0," + username + format_operator(opt) + "&upass=" + passwd + "&R1=0&R2=0&R3=0&R6=0&para=00&0MKKey=123456";
	const void* szData = sData.c_str();
	DWORD dwSize = 0;
	DWORD dwDownloaded = 0;
	wchar_t* pwText = NULL;
	BOOL bResults = FALSE;
	HINTERNET
		hSession = NULL,
		hConnect = NULL,
		hRequest = NULL;
	hSession = WinHttpOpen(L"login network", NULL, WINHTTP_NO_PROXY_NAME,
		WINHTTP_NO_PROXY_BYPASS, 0);
	if (hSession)
		hConnect = WinHttpConnect(hSession, L"10.10.244.11", 801, 0);
		// dwFlags 表示安全策略，这里不使用
	if (hConnect)
		hRequest = WinHttpOpenRequest(hConnect, L"POST", params.c_str(), NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0);

	if (hRequest)
		// 发送POST请求
		bResults = WinHttpSendRequest(hRequest, L"Content-Type: application/x-www-form-urlencoded", 0, const_cast<void*>(szData), static_cast<DWORD>(sData.length()), static_cast<DWORD>(sData.length()), 0);



//	我们并不关心返回的结果
// 	if (bResults)
//		bResults = WinHttpReceiveResponse(hRequest, NULL);

//	if (bResults)
//	{
//		dwSize = 0;
//		if (!WinHttpQueryDataAvailable(hRequest, &dwSize))
//		{
//			error_msg << "Error" << GetLastError() << "in WinHttpQueryDataAvailable.";
//			throw std::exception(error_msg.str().c_str());
//		}
//		auto* pszOutBuffer = new char[1 + static_cast<long long>(dwSize)];
//		if (!pszOutBuffer)
//		{
//			error_msg << "Out of memory";
//			throw std::exception(error_msg.str().c_str());
//			// dwSize = 0;
//		}
//		ZeroMemory(pszOutBuffer, dwSize + 1);
//		if (!WinHttpReadData(hRequest, static_cast<LPVOID>(pszOutBuffer), dwSize, &dwDownloaded))
//		{
//			error_msg << "Error" << GetLastError() << "in WinHttpReadData.";
//			throw std::exception(error_msg.str().c_str());
//		}
//		printf("%s", pszOutBuffer);
//		delete[] pszOutBuffer;
//	}

	
	if (!bResults)
	{
		error_msg << "Error" << GetLastError() << "has occurred";
	}


	WinHttpCloseHandle(hRequest);
	WinHttpCloseHandle(hConnect);
	WinHttpCloseHandle(hSession);

	check_status();
	if (status)
		return login_status::succeed;

	return login_status::failed;
}

std::string auto_login::get_ip()
{
	std::string strLocalhostIp;
	PMIB_IPFORWARDTABLE pIpRouteTable = GetIpForwardTable_(TRUE);
	if (pIpRouteTable != NULL)
	{
		in_addr inadDest{};
		in_addr inadMask{};
		char szDestIp[128] = { 0 };
		char szMaskIp[128] = { 0 };
		DWORD IfIndex = ULONG_MAX;
		DWORD ForwardMetric1 = 0;
		if (pIpRouteTable->dwNumEntries > 0)
		{
			for (DWORD i = 0; i < pIpRouteTable->dwNumEntries; i++)
			{
				DWORD dwCurrIndex = pIpRouteTable->table[i].dwForwardIfIndex;
				// 目的地址  
				inadDest.s_addr = pIpRouteTable->table[i].dwForwardDest;
				inet_ntop(AF_INET, &inadDest, szDestIp, 128);
				// 子网掩码  
				inadMask.s_addr = pIpRouteTable->table[i].dwForwardMask;
				inet_ntop(AF_INET, &inadMask, szMaskIp, 128);
				if ((strcmp(szDestIp, "0.0.0.0") == 0) && (strcmp(szMaskIp, "0.0.0.0") == 0))
				{
					// 关注当 目的地址 和 子网掩码 都为0.0.0.0时网关的下标，通过比较 最短路由 路径确定唯一下标
					if (i == 0)
					{
						ForwardMetric1 = pIpRouteTable->table[i].dwForwardMetric1;
						IfIndex = pIpRouteTable->table[i].dwForwardIfIndex;
					}
					else if (ForwardMetric1 > pIpRouteTable->table[i].dwForwardMetric1)
					{
						ForwardMetric1 = pIpRouteTable->table[i].dwForwardMetric1;
						IfIndex = pIpRouteTable->table[i].dwForwardIfIndex;
					}
				}
			}
			if (IfIndex == ULONG_MAX)
				throw std::exception("cannot find ip");
		}
		else
		{
			FreeIpForwardTable(pIpRouteTable);
			throw std::exception("IP Route Table Zero!");
		}
		FreeIpForwardTable(pIpRouteTable);

		// 通过下标确定网卡及ip
		if (IfIndex > 0)
		{
			auto* m_pBuffer = new BYTE[MAX_PATH];
			ULONG m_ulSize = MAX_PATH;
			in_addr ia{};
			GetIpAddrTable(reinterpret_cast<PMIB_IPADDRTABLE>(m_pBuffer), &m_ulSize, TRUE);
			delete[] m_pBuffer;
			m_pBuffer = new BYTE[m_ulSize];
			if (NULL != m_pBuffer)
			{
				const DWORD m_dwResult = GetIpAddrTable(reinterpret_cast<PMIB_IPADDRTABLE>(m_pBuffer), &m_ulSize, TRUE);
				if (m_dwResult == NO_ERROR)
				{
					auto* pAddrTable = reinterpret_cast<PMIB_IPADDRTABLE>(m_pBuffer);
					for (DWORD x = 0; x < pAddrTable->dwNumEntries; x++)
					{
						auto* pAddrRow = static_cast<PMIB_IPADDRROW>(&(pAddrTable->table[x]));
						ia.S_un.S_addr = pAddrRow->dwAddr;
						char IPMsg[100] = { 0 };
						if (IfIndex == pAddrRow->dwIndex)
						{
							char psz[128];
							inet_ntop(AF_INET, &ia, psz, 128);
							delete[] m_pBuffer;
							return std::string(psz);
						}
					}
				}
				else
				{
					throw std::exception("GetIpAddrTable ERROR!");
				}
				delete[] m_pBuffer;
			}
		}
	}
	else
	{
		FreeIpForwardTable(pIpRouteTable);
		throw std::exception("IP Route Table Zero!");
	}
	throw std::exception("IP Route Table Zero!");
}

void auto_login::check_status()
{
	std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> convert;
	std::wstring params = L"/eportal/?c=ACSetting&a=checkScanIP&callback=jQuery111309554246788418939_1602679411198&wlanuserip=" + convert.from_bytes(ip_.c_str()) + L"&_=1602679411199";
	std::stringstream error_msg;

	
	DWORD dwSize = 0;
	DWORD dwDownloaded = 0;
	wchar_t* pwText = NULL;
	BOOL bResults = FALSE;
	HINTERNET
		hSession = NULL,
		hConnect = NULL,
		hRequest = NULL;
	hSession = WinHttpOpen(L"Check_status", NULL, WINHTTP_NO_PROXY_NAME,
		WINHTTP_NO_PROXY_BYPASS, 0);
	if (hSession)
		hConnect = WinHttpConnect(hSession, L"10.10.244.11", 801, 0);
	// dwFlags 表示安全策略，这里不使用
	if (hConnect)
		hRequest = WinHttpOpenRequest(hConnect, L"Get", params.c_str(), NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0);

	if (hRequest)
		bResults = WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, NULL, NULL, NULL, 0);

	if (bResults)
		bResults = WinHttpReceiveResponse(hRequest, NULL);

	if (bResults)
	{
		dwSize = 0;
		if (!WinHttpQueryDataAvailable(hRequest, &dwSize))
		{
			error_msg << "Error" << GetLastError() << "in WinHttpQueryDataAvailable.";
			throw std::exception(error_msg.str().c_str());
		}
		auto* pszOutBuffer = new char[1 + static_cast<long long>(dwSize)];
		if (!pszOutBuffer)
		{
			error_msg << "Out of memory";
			throw std::exception(error_msg.str().c_str());
			// dwSize = 0;
		}
		ZeroMemory(pszOutBuffer, static_cast<unsigned long long>(dwSize) + 1);
		if (!WinHttpReadData(hRequest, static_cast<LPVOID>(pszOutBuffer), dwSize, &dwDownloaded))
		{
			error_msg << "Error" << GetLastError() << "in WinHttpReadData.";
			throw std::exception(error_msg.str().c_str());
		}
		// 返回的是一个json字符串，但我们只需要查找其中的关键字ok，无需对json进行解析
		auto* const flag = std::strpbrk(pszOutBuffer, "ok");
		if (flag)
			status = true;
		else
			status = false;
		delete[] pszOutBuffer;
	}
	if (!bResults)
	{
		error_msg << "Error" << GetLastError() << "has occurred";
	}


	WinHttpCloseHandle(hRequest);
	WinHttpCloseHandle(hConnect);
	WinHttpCloseHandle(hSession);

	
}

std::ostream& operator<<(std::ostream& out, auto_login::login_status s)
{
	switch (s)
	{
	case auto_login::login_status::succeed:
		out << "login succeed";
		break;
	case auto_login::login_status::failed:
		out << "login failed";
		break;
	case auto_login::login_status::repeat_login:
		out << "repeat login";
		break;
	}
	return out;
}


