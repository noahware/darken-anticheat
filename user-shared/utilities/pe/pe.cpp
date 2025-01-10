#include "pe.h"
#include <imports.h>

#include <Windows.h>
#include <Softpub.h>
#include <wincrypt.h>
#include <mscat.h>
#include <wintrust.h>

#include <vector>

struct s_catalog_and_hash_info
{
	std::wstring catalog_path;
	std::vector<uint8_t> hash;
};

s_catalog_and_hash_info get_catalog_and_hash_info(HANDLE file_handle);
bool win_verify_trust(uint32_t trust_info_choice, void* trust_info_data);

bool utilities::pe::has_embedded_signature(std::wstring_view binary_path)
{
	WINTRUST_FILE_INFO file_info = { };

	file_info.cbStruct = sizeof(WINTRUST_FILE_INFO);
	file_info.pcwszFilePath = binary_path.data();
	file_info.hFile = nullptr;
	file_info.pgKnownSubject = nullptr;

	return win_verify_trust(WTD_CHOICE_FILE, &file_info);
}

bool utilities::pe::has_catalog_signature(std::wstring_view binary_path)
{
	HANDLE file_handle = d_import(CreateFileW)(binary_path.data(), FILE_GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);

	if (file_handle == nullptr || file_handle == INVALID_HANDLE_VALUE)
	{
		return false;
	}

	s_catalog_and_hash_info catalog_and_hash_info = get_catalog_and_hash_info(file_handle);

	if (catalog_and_hash_info.catalog_path.empty() == true || catalog_and_hash_info.hash.empty() == true)
	{
		d_import(CloseHandle)(file_handle);

		return false;
	}

	WINTRUST_CATALOG_INFO wintrust_catalog_info = { };

	wintrust_catalog_info.cbStruct = sizeof(WINTRUST_CATALOG_INFO);
	wintrust_catalog_info.pcwszCatalogFilePath = catalog_and_hash_info.catalog_path.data();
	wintrust_catalog_info.pcwszMemberFilePath = binary_path.data();
	wintrust_catalog_info.hMemberFile = file_handle;
	wintrust_catalog_info.pbCalculatedFileHash = catalog_and_hash_info.hash.data();
	wintrust_catalog_info.cbCalculatedFileHash = static_cast<uint32_t>(catalog_and_hash_info.hash.size());

	bool is_digitally_signed = win_verify_trust(WTD_CHOICE_CATALOG, &wintrust_catalog_info);

	d_import(CloseHandle)(file_handle);

	return is_digitally_signed;
}

bool utilities::pe::is_digitally_signed(std::wstring_view binary_path)
{
	return has_embedded_signature(binary_path) || has_catalog_signature(binary_path);
}

s_catalog_and_hash_info get_catalog_and_hash_info(HANDLE file_handle)
{
	uint32_t hash_length = 0;

	if (d_import(CryptCATAdminCalcHashFromFileHandle)(file_handle, reinterpret_cast<DWORD*>(&hash_length), nullptr, 0) == 0)
	{
		return { };
	}

	std::vector<uint8_t> hash_data(hash_length);

	if (d_import(CryptCATAdminCalcHashFromFileHandle)(file_handle, reinterpret_cast<DWORD*>(&hash_length), hash_data.data(), 0) == 0)
	{
		return { };
	}

	HCATADMIN catalog_admin_handle = nullptr;

	if (d_import(CryptCATAdminAcquireContext)(&catalog_admin_handle, nullptr, 0) == 0)
	{
		return { };
	}

	HCATINFO catalog_info_handle = d_import(CryptCATAdminEnumCatalogFromHash)(catalog_admin_handle, hash_data.data(), hash_length, 0, nullptr);

	if (catalog_info_handle == nullptr || catalog_info_handle == INVALID_HANDLE_VALUE)
	{
		d_import(CryptCATAdminReleaseContext)(catalog_admin_handle, 0);

		return { };
	}

	CATALOG_INFO catalog_info = { };

	catalog_info.cbStruct = sizeof(CATALOG_INFO);

	if (d_import(CryptCATCatalogInfoFromContext)(catalog_info_handle, &catalog_info, 0) == 0)
	{
		d_import(CryptCATAdminReleaseCatalogContext)(catalog_admin_handle, catalog_info_handle, 0);
		d_import(CryptCATAdminReleaseContext)(catalog_admin_handle, 0);

		return { };
	}

	std::wstring catalog_file_path = catalog_info.wszCatalogFile;

	d_import(CryptCATAdminReleaseCatalogContext)(catalog_admin_handle, catalog_info_handle, 0);
	d_import(CryptCATAdminReleaseContext)(catalog_admin_handle, 0);

	return { catalog_file_path, hash_data };
}

bool win_verify_trust(uint32_t trust_info_choice, void* trust_info_data)
{
	GUID wvt_policy_guid = WINTRUST_ACTION_GENERIC_VERIFY_V2;
	WINTRUST_DATA win_trust_data = { };

	win_trust_data.cbStruct = sizeof(win_trust_data);
	win_trust_data.dwUIChoice = WTD_UI_NONE;
	win_trust_data.fdwRevocationChecks = WTD_REVOKE_WHOLECHAIN;
	win_trust_data.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL;
	win_trust_data.dwUnionChoice = trust_info_choice;
	win_trust_data.dwStateAction = WTD_STATEACTION_VERIFY;
	win_trust_data.pFile = reinterpret_cast<WINTRUST_FILE_INFO*>(trust_info_data); // (file, catalog, cert, etc) infos pointers are all within a union, so this is ambiguous

	bool is_digitally_signed = d_import(WinVerifyTrust)(nullptr, &wvt_policy_guid, &win_trust_data) == ERROR_SUCCESS;

	win_trust_data.dwStateAction = WTD_STATEACTION_CLOSE;

	d_import(WinVerifyTrust)(nullptr, &wvt_policy_guid, &win_trust_data);

	return is_digitally_signed;
}
