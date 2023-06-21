#ifndef ISLE_H
#define ISLE_H

#include <windows.h>

#include "mxresult.h"
#include "mxvideoparam.h"

class Isle
{
public:
  Isle();
  ~Isle();

  void Close();

  BOOL ReadReg(LPCSTR name, LPSTR outValue, DWORD outSize);
  int ReadRegBool(LPCSTR name, BOOL *out);
  int ReadRegInt(LPCSTR name, int *out);

  MxResult SetupWindow(HINSTANCE hInstance);

  void Tick(BOOL sleepIfNotNextFrame);

  BOOL SetupLegoOmni();
  void LoadConfig();
  void SetupVideoFlags(BOOL fullScreen, BOOL flipSurfaces, BOOL backBuffers,
                       BOOL using8bit, BOOL m_using16bit, BOOL param_6, BOOL param_7,
                       BOOL wideViewAngle, char *deviceId);

  void SetupCursor(WPARAM wParam);

// private:

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
  int m_unk24;
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
  long m_frameDelta;

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

#endif // ISLE_H
