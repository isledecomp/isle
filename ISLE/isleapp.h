#ifndef ISLEAPP_H
#define ISLEAPP_H

#include "mxtypes.h"
#include "mxvideoparam.h"

#include <windows.h>

// SIZE 0x8c
class IsleApp {
public:
	IsleApp();
	~IsleApp();

	void Close();

	BOOL SetupLegoOmni();
	void SetupVideoFlags(
		BOOL fullScreen,
		BOOL flipSurfaces,
		BOOL backBuffers,
		BOOL using8bit,
		BOOL using16bit,
		BOOL param_6,
		BOOL param_7,
		BOOL wideViewAngle,
		char* deviceId
	);
	MxResult SetupWindow(HINSTANCE hInstance, LPSTR lpCmdLine);

	BOOL ReadReg(LPCSTR name, LPSTR outValue, DWORD outSize);
	BOOL ReadRegBool(LPCSTR name, BOOL* out);
	BOOL ReadRegInt(LPCSTR name, int* out);

	void LoadConfig();
	void Tick(BOOL sleepIfNotNextFrame);
	void SetupCursor(WPARAM wParam);

	inline HWND GetWindowHandle() { return m_windowHandle; }
	inline MxLong GetFrameDelta() { return m_frameDelta; }
	inline BOOL GetFullScreen() { return m_fullScreen; }
	inline HCURSOR GetCursorCurrent() { return m_cursorCurrent; }
	inline HCURSOR GetCursorBusy() { return m_cursorBusy; }
	inline HCURSOR GetCursorNo() { return m_cursorNo; }
	inline BOOL GetDrawCursor() { return m_drawCursor; }

	inline void SetWindowActive(BOOL p_windowActive) { m_windowActive = p_windowActive; }

private:
	LPSTR m_hdPath;            // 0x00
	LPSTR m_cdPath;            // 0x04
	LPSTR m_deviceId;          // 0x08
	LPSTR m_savePath;          // 0x0c
	BOOL m_fullScreen;         // 0x10
	BOOL m_flipSurfaces;       // 0x14
	BOOL m_backBuffersInVram;  // 0x18
	BOOL m_using8bit;          // 0x1c
	BOOL m_using16bit;         // 0x20
	int m_unk0x24;             // 0x24
	BOOL m_use3dSound;         // 0x28
	BOOL m_useMusic;           // 0x2c
	BOOL m_useJoystick;        // 0x30
	int m_joystickIndex;       // 0x34
	BOOL m_wideViewAngle;      // 0x38
	int m_islandQuality;       // 0x3c
	int m_islandTexture;       // 0x40
	BOOL m_gameStarted;        // 0x44
	MxLong m_frameDelta;       // 0x48
	MxVideoParam m_videoParam; // 0x4c
	BOOL m_windowActive;       // 0x70
	HWND m_windowHandle;       // 0x74
	BOOL m_drawCursor;         // 0x78
	HCURSOR m_cursorArrow;     // 0x7c
	HCURSOR m_cursorBusy;      // 0x80
	HCURSOR m_cursorNo;        // 0x84
	HCURSOR m_cursorCurrent;   // 0x88
};

#endif // ISLEAPP_H
