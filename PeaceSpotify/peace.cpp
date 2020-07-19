#include "pch.h"
#include "peace.h"
#include <vector>
#include <string>
#include <stdexcept>

template<typename T>
void InitAddress(T& fncAddr, HMODULE hModule, LPCSTR fncName)
{
	fncAddr = (T)GetProcAddress(hModule, fncName);
	if (fncAddr == NULL)
	{
		throw std::runtime_error("Invalid Address");
	}
}

PCEF_URLREQUEST_CREATE_T 			original_cef_url_request_create = NULL;
PCEF_STRING_USERFREE_UTF16_FREE_T 	original_cef_string_user_free_utf_free = NULL;

static std::vector<std::wstring> black_list = {
		L"https://spclient.wg.spotify.com/ads/", // ads
		L"https://spclient.wg.spotify.com/ad-logic/", // ads
		L"https://spclient.wg.spotify.com/gabo-receiver-service/", // tracking
};

bool IsBlackListed(const std::wstring url) {
	for (std::wstring blacklisted : black_list)
		if (!url.compare(0, blacklisted.length(), blacklisted)) return TRUE;
	return FALSE;
}


bool Init(HMODULE hModule) {
		if (!hModule)
			return FALSE;
		InitAddress(original_cef_url_request_create, hModule, "cef_urlrequest_create");
		InitAddress(original_cef_string_user_free_utf_free, hModule, "cef_string_userfree_utf16_free");
		return TRUE;
}

cef_urlrequest_t*
_cef_urlrequest_create(
	cef_request_t* request,
	cef_urlrequest_client_t* client,
	cef_request_context_t* request_context)
{
	cef_string_userfree_t url_utf16 = request->get_url(request);
	std::wstring url = std::wstring(url_utf16->length, ' ');
	for (unsigned int i = 0; i < url_utf16->length; i++) url[i] = *(url_utf16->str + i);
	original_cef_string_user_free_utf_free(url_utf16);

	if (IsBlackListed(url)) {

		return NULL;
	}

	return original_cef_url_request_create(request, client, request_context);
}