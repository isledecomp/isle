#include "detectdx5.h"

#include <ddraw.h>
#include <dinput.h>

typedef HRESULT WINAPI DirectDrawCreate_fn(GUID FAR* lpGUID, LPDIRECTDRAW FAR* lplpDD, IUnknown FAR* pUnkOuter);
typedef HRESULT WINAPI
DirectInputCreateA_fn(HINSTANCE hinst, DWORD dwVersion, LPDIRECTINPUTA* ppDI, LPUNKNOWN punkOuter);

// FUNCTION: CONFIG 0x004048f0
BOOL DetectDirectX5()
{
	unsigned int version;
	BOOL found;
	DetectDirectX(&version, &found);
	return version >= 0x500;
}

// FUNCTION: CONFIG 0x00404920
void DetectDirectX(unsigned int* p_version, BOOL* p_found)
{
	OSVERSIONINFOA os_version;

	os_version.dwOSVersionInfoSize = sizeof(os_version);
	if (!GetVersionExA(&os_version)) {
		*p_version = 0;
		*p_found = 0;
		return;
	}
	if (os_version.dwPlatformId == 2) {
		*p_found = 2;
		if (os_version.dwMajorVersion < 4) {
			*p_found = 0;
			return;
		}
		if (os_version.dwMajorVersion != 4) {
			*p_version = 0x501;
			return;
		}
		*p_version = 0x200;
		HMODULE dinput_module = LoadLibraryA("DINPUT.DLL");
		if (!dinput_module) {
			OutputDebugStringA("Couldn't LoadLibrary DInput\r\n");
			return;
		}
		DirectInputCreateA_fn* func_DirectInputCreateA =
			(DirectInputCreateA_fn*) GetProcAddress(dinput_module, "DirectInputCreateA");
		FreeLibrary(dinput_module);
		if (!func_DirectInputCreateA) {
			OutputDebugStringA("Couldn't GetProcAddress DInputCreate\r\n");
			return;
		}
		*p_version = 0x300;
		return;
	}
	*p_found = 1;
	if (LOWORD(os_version.dwBuildNumber) >= 0x550) {
		*p_version = 0x501;
		return;
	}
	HMODULE ddraw_module = LoadLibraryA("DDRAW.DLL");
	if (!ddraw_module) {
		*p_version = 0;
		*p_found = 0;
		FreeLibrary(ddraw_module);
		return;
	}
	DirectDrawCreate_fn* func_DirectDrawCreate =
		(DirectDrawCreate_fn*) GetProcAddress(ddraw_module, "DirectDrawCreate");
	if (!func_DirectDrawCreate) {
		*p_version = 0;
		*p_found = 0;
		FreeLibrary(ddraw_module);
		OutputDebugStringA("Couldn't LoadLibrary DDraw\r\n");
		return;
	}
	LPDIRECTDRAW ddraw;
	if (FAILED(func_DirectDrawCreate(NULL, &ddraw, NULL))) {
		*p_version = 0;
		*p_found = 0;
		FreeLibrary(ddraw_module);
		OutputDebugStringA("Couldn't create DDraw\r\n");
		return;
	}
	*p_version = 0x100;
	LPDIRECTDRAW2 ddraw2;
	if (FAILED(ddraw->QueryInterface(IID_IDirectDraw2, (LPVOID*) &ddraw2))) {
		ddraw->Release();
		FreeLibrary(ddraw_module);
		OutputDebugStringA("Couldn't QI DDraw2\r\n");
		return;
	}
	ddraw->Release();
	*p_version = 0x200;
	HMODULE dinput_module = LoadLibraryA("DINPUT.DLL");
	if (!dinput_module) {
		OutputDebugStringA("Couldn't LoadLibrary DInput\r\n");
		ddraw2->Release();
		FreeLibrary(ddraw_module);
		return;
	}
	DirectInputCreateA_fn* func_DirectInputCreateA =
		(DirectInputCreateA_fn*) GetProcAddress(dinput_module, "DirectInputCreateA");
	FreeLibrary(dinput_module);
	if (!func_DirectInputCreateA) {
		FreeLibrary(ddraw_module);
		ddraw2->Release();
		OutputDebugStringA("Couldn't GetProcAddress DInputCreate\r\n");
		return;
	}
	*p_version = 0x300;
	DDSURFACEDESC surface_desc;
	memset(&surface_desc, 0, sizeof(surface_desc));
	surface_desc.dwSize = sizeof(surface_desc);
	surface_desc.dwFlags = DDSD_CAPS;
	surface_desc.ddsCaps.dwCaps = DDCAPS2_NONLOCALVIDMEM;
	if (FAILED(ddraw2->SetCooperativeLevel(NULL, DISCL_BACKGROUND))) {
		ddraw2->Release();
		FreeLibrary(ddraw_module);
		*p_version = 0;
		OutputDebugStringA("Couldn't Set coop level\r\n");
		return;
	}
	LPDIRECTDRAWSURFACE surface;
	if (FAILED(ddraw2->CreateSurface(&surface_desc, &surface, NULL))) {
		ddraw2->Release();
		FreeLibrary(ddraw_module);
		*p_version = 0;
		OutputDebugStringA("Couldn't CreateSurface\r\n");
		return;
	}
	LPDIRECTDRAWSURFACE3 surface3;
	if (FAILED(surface->QueryInterface(IID_IDirectDrawSurface3, (LPVOID*) &surface3))) {
		ddraw2->Release();
		FreeLibrary(ddraw_module);
		return;
	}
	*p_version = 0x500;
	surface3->Release();
	ddraw2->Release();
	FreeLibrary(ddraw_module);
}
