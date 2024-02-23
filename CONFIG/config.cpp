#include "config.h"

#include "ConfigCommandLineInfo.h"
#include "MainDlg.h"
#include "detectdx5.h"

#include <direct.h> // _chdir
#include <mxdirectx/mxdirect3d.h>
#include <process.h> // _spawnl

DECOMP_SIZE_ASSERT(CWinApp, 0xc4)
DECOMP_SIZE_ASSERT(CConfigApp, 0x108)

DECOMP_STATIC_ASSERT(offsetof(CConfigApp, m_display_bit_depth) == 0xd0)

BEGIN_MESSAGE_MAP(CConfigApp, CWinApp)
ON_COMMAND(ID_HELP, OnHelp)
END_MESSAGE_MAP()

// FUNCTION: CONFIG 0x00402c40
CConfigApp::CConfigApp()
{
}

#define MiB (1024 * 1024)

// FUNCTION: CONFIG 0x00402dc0
BOOL CConfigApp::InitInstance()
{
	if (!IsLegoNotRunning()) {
		return FALSE;
	}
	if (!DetectDirectX5()) {
		AfxMessageBox(
			"\"LEGO\xae Island\" is not detecting DirectX 5 or later.  Please quit all other applications and try "
			"again."
		);
		return FALSE;
	}
#ifdef _AFXDLL
	Enable3dControls();
#else
	Enable3dControlsStatic();
#endif
	CConfigCommandLineInfo cmdInfo;
	ParseCommandLine(cmdInfo);
	if (_stricmp(afxCurrentAppName, "config") == 0) {
		m_run_config_dialog = TRUE;
	}
	m_device_enumerator = new MxDeviceEnumerate;
	if (m_device_enumerator->DoEnumerate()) {
		return FALSE;
	}
	m_driver = NULL;
	m_device = NULL;
	m_full_screen = TRUE;
	m_wide_view_angle = TRUE;
	m_use_joystick = FALSE;
	m_music = TRUE;
	m_flip_surfaces = FALSE;
	m_3d_video_ram = FALSE;
	m_joystick_index = -1;
	m_display_bit_depth = 16;
	MEMORYSTATUS memory_status;
	memory_status.dwLength = sizeof(memory_status);
	GlobalMemoryStatus(&memory_status);
	if (memory_status.dwTotalPhys < 12 * MiB) {
		m_3d_sound = FALSE;
		m_model_quality = 0;
		m_texture_quality = 1;
	}
	else if (memory_status.dwTotalPhys < 20 * MiB) {
		m_3d_sound = FALSE;
		m_model_quality = 1;
		m_texture_quality = 1;
	}
	else {
		m_model_quality = 2;
		m_3d_sound = TRUE;
		m_texture_quality = 1;
	}
	if (!m_run_config_dialog) {
		ReadRegisterSettings();
		ValidateSettings();
		WriteRegisterSettings();
		delete m_device_enumerator;
		m_device_enumerator = NULL;
		m_driver = NULL;
		m_device = NULL;
		char password[256];
		ReadReg("password", password, sizeof(password));
		const char* exe = _stricmp("ogel", password) == 0 ? "isled.exe" : "isle.exe";
		char diskpath[1024];
		if (ReadReg("diskpath", diskpath, sizeof(diskpath))) {
			_chdir(diskpath);
		}
		_spawnl(_P_NOWAIT, exe, exe, "/diskstream", "/script", "\\lego\\scripts\\isle\\isle.si", NULL);
		return FALSE;
	}
	CMainDialog main_dialog(NULL);
	main_dialog.DoModal();
	return FALSE;
}

// FUNCTION: CONFIG 0x00403100
BOOL CConfigApp::IsLegoNotRunning()
{
	HWND hWnd = FindWindowA("Lego Island MainNoM App", "LEGO\xae");
	if (_stricmp(afxCurrentAppName, "config") == 0 || !hWnd) {
		return TRUE;
	}
	if (SetForegroundWindow(hWnd)) {
		ShowWindow(hWnd, SW_RESTORE);
	}
	return FALSE;
}

// FUNCTION: CONFIG 0x004031b0
BOOL CConfigApp::WriteReg(const char* p_key, const char* p_value) const
{
	HKEY hKey;
	DWORD pos;

	if (RegCreateKeyExA(
			HKEY_LOCAL_MACHINE,
			"SOFTWARE\\Mindscape\\LEGO Island",
			0,
			"string",
			0,
			KEY_READ | KEY_WRITE,
			NULL,
			&hKey,
			&pos
		) == ERROR_SUCCESS) {
		if (RegSetValueExA(hKey, p_key, 0, REG_SZ, (LPBYTE) p_value, strlen(p_value)) == ERROR_SUCCESS) {
			if (RegCloseKey(hKey) == ERROR_SUCCESS) {
				return TRUE;
			}
		}
		else {
			RegCloseKey(hKey);
		}
	}
	return FALSE;
}

// FUNCTION: CONFIG 0x00403240
BOOL CConfigApp::ReadReg(LPCSTR p_key, LPCSTR p_value, DWORD p_size) const
{
	HKEY hKey;
	DWORD valueType;

	BOOL out = FALSE;
	DWORD size = p_size;
	if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Mindscape\\LEGO Island", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
		if (RegQueryValueExA(hKey, p_key, NULL, &valueType, (LPBYTE) p_value, &size) == ERROR_SUCCESS) {
			if (RegCloseKey(hKey) == ERROR_SUCCESS) {
				out = TRUE;
			}
		}
	}
	return out;
}

// FUNCTION: CONFIG 0x004032b0
BOOL CConfigApp::ReadRegBool(LPCSTR p_key, BOOL* p_bool) const
{
	char buffer[256];

	BOOL read = ReadReg(p_key, buffer, sizeof(buffer));
	if (read) {
		if (strcmp("YES", buffer) == 0) {
			*p_bool = TRUE;
			return read;
		}

		if (strcmp("NO", buffer) == 0) {
			*p_bool = FALSE;
			return read;
		}

		read = FALSE;
	}
	return read;
}

// FUNCTION: CONFIG 0x00403380
BOOL CConfigApp::ReadRegInt(LPCSTR p_key, int* p_value) const
{
	char buffer[256];

	BOOL read = ReadReg(p_key, buffer, sizeof(buffer));
	if (read) {
		*p_value = atoi(buffer);
	}

	return read;
}

// FUNCTION: CONFIG 0x004033d0
BOOL CConfigApp::FUN_004033d0() const
{
	/*
	 * BUG: should be:
	 *  return !GetHardwareDeviceColorModel() && (m_device->m_HELDesc.dcmColorModel & D3DCOLOR_RGB);
	 */
	return !GetHardwareDeviceColorModel() && m_device->m_HELDesc.dcmColorModel == D3DCOLOR_RGB;
}

// FUNCTION: CONFIG 0x00403400
D3DCOLORMODEL CConfigApp::GetHardwareDeviceColorModel() const
{
	return m_device->m_HWDesc.dcmColorModel;
}

// FUNCTION: CONFIG 0x00403410
BOOL CConfigApp::IsPrimaryDriver() const
{
	return m_driver == &m_device_enumerator->GetDriverList().front();
}

// FUNCTION: CONFIG 0x00403430
BOOL CConfigApp::ReadRegisterSettings()
{
	char buffer[256];
	BOOL is_modified = FALSE;
	int tmp = -1;

	if (ReadReg("3D Device ID", buffer, sizeof(buffer))) {
		tmp = m_device_enumerator->ParseDeviceName(buffer);
		if (tmp >= 0) {
			tmp = m_device_enumerator->GetDevice(tmp, m_driver, m_device);
		}
	}
	if (tmp != 0) {
		is_modified = TRUE;
		m_device_enumerator->FUN_1009d210();
		tmp = m_device_enumerator->FUN_1009d0d0();
		m_device_enumerator->GetDevice(tmp, m_driver, m_device);
	}
	if (!ReadRegInt("Display Bit Depth", &m_display_bit_depth)) {
		is_modified = TRUE;
	}
	if (!ReadRegBool("Flip Surfaces", &m_flip_surfaces)) {
		is_modified = TRUE;
	}
	if (!ReadRegBool("Full Screen", &m_full_screen)) {
		is_modified = TRUE;
	}
	if (!ReadRegBool("Back Buffers in Video RAM", &m_3d_video_ram)) {
		is_modified = TRUE;
	}
	if (!ReadRegBool("Wide View Angle", &m_wide_view_angle)) {
		is_modified = TRUE;
	}
	if (!ReadRegBool("3DSound", &m_3d_sound)) {
		is_modified = TRUE;
	}
	if (!ReadRegBool("Draw Cursor", &m_draw_cursor)) {
		is_modified = TRUE;
	}
	if (!ReadRegInt("Island Quality", &m_model_quality)) {
		is_modified = TRUE;
	}
	if (!ReadRegInt("Island Texture", &m_texture_quality)) {
		is_modified = TRUE;
	}
	if (!ReadRegBool("UseJoystick", &m_use_joystick)) {
		is_modified = TRUE;
	}
	if (!ReadRegBool("Music", &m_music)) {
		is_modified = TRUE;
	}
	if (!ReadRegInt("JoystickIndex", &m_joystick_index)) {
		is_modified = TRUE;
	}
	return is_modified;
}

// FUNCTION: CONFIG 0x00403630
BOOL CConfigApp::ValidateSettings()
{
	BOOL is_modified = FALSE;

	if (!IsPrimaryDriver() && !m_full_screen) {
		m_full_screen = TRUE;
		is_modified = TRUE;
	}
	if (FUN_004033d0()) {
		if (m_3d_video_ram) {
			m_3d_video_ram = FALSE;
			is_modified = TRUE;
		}
		if (m_flip_surfaces) {
			m_flip_surfaces = FALSE;
			is_modified = TRUE;
		}
		if (m_display_bit_depth != 16) {
			m_display_bit_depth = 16;
			is_modified = TRUE;
		}
	}
	if (!GetHardwareDeviceColorModel()) {
		m_draw_cursor = FALSE;
		is_modified = TRUE;
	}
	else {
		if (!m_3d_video_ram) {
			m_3d_video_ram = TRUE;
			is_modified = TRUE;
		}
		if (m_full_screen && !m_flip_surfaces) {
			m_flip_surfaces = TRUE;
			is_modified = TRUE;
		}
	}
	if (m_flip_surfaces) {
		if (!m_3d_video_ram) {
			m_3d_video_ram = TRUE;
			is_modified = TRUE;
		}
		if (!m_full_screen) {
			m_full_screen = TRUE;
			is_modified = TRUE;
		}
	}
	if ((m_display_bit_depth != 8 && m_display_bit_depth != 16) && (m_display_bit_depth != 0 || m_full_screen)) {
		m_display_bit_depth = 8;
		is_modified = TRUE;
	}
	if (m_model_quality < 0 || m_model_quality > 2) {
		m_model_quality = 1;
		is_modified = TRUE;
	}
	if (m_texture_quality < 0 || m_texture_quality > 1) {
		m_texture_quality = 0;
		is_modified = TRUE;
	}
	return is_modified;
}

// FUNCTION: CONFIG 0x004037a0
DWORD CConfigApp::FUN_004037a0() const
{
	if (FUN_004033d0()) {
		return 0;
	}
	if (GetHardwareDeviceColorModel()) {
		return 0;
	}
	return m_device->m_HELDesc.dwDeviceRenderBitDepth & 0x800;
}

// FUNCTION: CONFIG 0x004037e0
DWORD CConfigApp::FUN_004037e0() const
{
	if (GetHardwareDeviceColorModel()) {
		return m_device->m_HWDesc.dwDeviceRenderBitDepth & 0x400;
	}
	else {
		return m_device->m_HELDesc.dwDeviceRenderBitDepth & 0x400;
	}
}

// FUNCTION: CONFIG 0x00403810
BOOL CConfigApp::FUN_00403810()
{
	if (m_display_bit_depth == 8) {
		if (FUN_004037a0()) {
			return FALSE;
		}
	}
	if (m_display_bit_depth == 16) {
		if (FUN_004037e0()) {
			return FALSE;
		}
	}
	if (FUN_004037a0()) {
		m_display_bit_depth = 8;
		return TRUE;
	}
	if (FUN_004037e0()) {
		m_display_bit_depth = 16;
		return TRUE;
	}
	m_display_bit_depth = 8;
	return TRUE;
}

// FUNCTION: CONFIG 00403890
void CConfigApp::WriteRegisterSettings() const

{
	char buffer[128];

#define WriteRegBool(NAME, VALUE) WriteReg(NAME, VALUE ? "YES" : "NO")
#define WriteRegInt(NAME, VALUE)                                                                                       \
	do {                                                                                                               \
		sprintf(buffer, "%d", VALUE);                                                                                  \
		WriteReg(NAME, buffer);                                                                                        \
	} while (0)

	m_device_enumerator->FormatDeviceName(buffer, m_driver, m_device);
	WriteReg("3D Device ID", buffer);
	WriteReg("3D Device Name", m_device->m_deviceName);
	WriteRegInt("Display Bit Depth", m_display_bit_depth);
	WriteRegBool("Flip Surfaces", m_flip_surfaces);
	WriteRegBool("Full Screen", m_full_screen);
	WriteRegBool("Back Buffers in Video RAM", m_3d_video_ram);
	WriteRegBool("Wide View Angle", m_wide_view_angle);
	WriteRegBool("3DSound", m_3d_sound);
	WriteRegBool("Draw Cursor", m_draw_cursor);
	WriteRegInt("Island Quality", m_model_quality);
	WriteRegInt("Island Texture", m_texture_quality);
	WriteRegBool("UseJoystick", m_use_joystick);
	WriteRegBool("Music", m_music);
	WriteRegInt("JoystickIndex", m_joystick_index);

#undef WriteRegBool
#undef WriteRegInt
}

// FUNCTION: CONFIG 0x00403a90
int CConfigApp::ExitInstance()
{
	if (m_device_enumerator) {
		delete m_device_enumerator;
		m_device_enumerator = NULL;
	}
	return CWinApp::ExitInstance();
}

// GLOBAL: CONFIG 0x00408e50
CConfigApp g_theApp;
