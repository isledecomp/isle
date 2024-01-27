#ifndef ISLEAPP_H
#define ISLEAPP_H

#include "mxtypes.h"
#include "mxvideoparam.h"

#include <windows.h>

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
	int ReadRegBool(LPCSTR name, BOOL* out);
	int ReadRegInt(LPCSTR name, int* out);

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
	// 0
	LPSTR m_hdPath;
	LPSTR m_cdPath;
	LPSTR m_deviceId;
	LPSTR m_savePath;

	// 10
	BOOL m_fullScreen;
	BOOL m_flipSurfaces;
	BOOL m_backBuffersInVram;
	BOOL m_using8bit;

	// 20
	BOOL m_using16bit;
	int m_unk0x24;
	BOOL m_use3dSound;
	BOOL m_useMusic;

	// 30
	BOOL m_useJoystick;
	int m_joystickIndex;
	BOOL m_wideViewAngle;
	int m_islandQuality;

	// 40
	int m_islandTexture;
	int m_gameStarted;
	MxLong m_frameDelta;

	// 4c
	MxVideoParam m_videoParam;

	// 70
	BOOL m_windowActive;
	HWND m_windowHandle;
	BOOL m_drawCursor;
	HCURSOR m_cursorArrow;

	// 80
	HCURSOR m_cursorBusy;
	HCURSOR m_cursorNo;
	HCURSOR m_cursorCurrent;
};

#endif // ISLEAPP_H
