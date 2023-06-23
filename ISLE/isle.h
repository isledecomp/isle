#ifndef ISLE_H
#define ISLE_H

#include "legoinc.h"
#include "define.h"

#include "legoomni.h"
#include "legoanimationmanager.h"
#include "legobuildingmanager.h"
#include "legomodelpresenter.h"
#include "legopartpresenter.h"
#include "legoworldpresenter.h"
#include "mxresult.h"
#include "mxvideoparam.h"
#include "mxdirectdraw.h"
#include "mxdsaction.h"
#include "mxomni.h"
#include "res/resource.h"

class Isle
{
public:
  Isle();
  ~Isle();

  void Close();

  BOOL ReadReg(LPCSTR name, LPSTR outValue, DWORD outSize);
  int ReadRegBool(LPCSTR name, BOOL *out);
  int ReadRegInt(LPCSTR name, int *out);

  MxResult SetupWindow(HINSTANCE hInstance, LPSTR lpCmdLine);

  void Tick(BOOL sleepIfNotNextFrame);

  BOOL SetupLegoOmni();
  void LoadConfig();
  void SetupVideoFlags(BOOL fullScreen, BOOL flipSurfaces, BOOL backBuffers,
                       BOOL using8bit, BOOL using16bit, BOOL param_6, BOOL param_7,
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


extern LRESULT WINAPI WndProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam);

// OFFSET: ISLE 0x4023e0
inline MxResult Isle::SetupWindow(HINSTANCE hInstance, LPSTR lpCmdLine)
{
  WNDCLASSA wndclass;
  ZeroMemory(&wndclass, sizeof(WNDCLASSA));

  LoadConfig();

  SetupVideoFlags(m_fullScreen, m_flipSurfaces, m_backBuffersInVram, m_using8bit,
                  m_using16bit, m_unk24, FALSE, m_wideViewAngle, m_deviceId);

  MxOmni::SetSound3D(m_use3dSound);

  srand(timeGetTime() / 1000);
  SystemParametersInfoA(SPI_SETMOUSETRAILS, 0, NULL, 0);

  ZeroMemory(&wndclass, sizeof(WNDCLASSA));

  wndclass.cbClsExtra = 0;
  wndclass.style = CS_HREDRAW | CS_VREDRAW;
  wndclass.lpfnWndProc = WndProc;
  wndclass.cbWndExtra = 0;
  wndclass.hIcon = LoadIconA(hInstance, MAKEINTRESOURCEA(APP_ICON));
  wndclass.hCursor = m_cursorArrow = m_cursorCurrent = LoadCursorA(hInstance, MAKEINTRESOURCEA(ISLE_ARROW));
  m_cursorBusy = LoadCursorA(hInstance, MAKEINTRESOURCEA(ISLE_BUSY));
  m_cursorNo = LoadCursorA(hInstance, MAKEINTRESOURCEA(ISLE_NO));
  wndclass.hInstance = hInstance;
  wndclass.hbrBackground = (HBRUSH) GetStockObject(BLACK_BRUSH);
  wndclass.lpszClassName = WNDCLASS_NAME;

  if (!RegisterClassA(&wndclass)) {
    return FAILURE;
  }

  if (m_fullScreen) {
    AdjustWindowRectEx(&g_windowRect, WS_CAPTION | WS_SYSMENU, 0, WS_EX_APPWINDOW);

    m_windowHandle = CreateWindowExA(
      WS_EX_APPWINDOW,
      WNDCLASS_NAME,
      WINDOW_TITLE,
      WS_CAPTION | WS_SYSMENU,
      g_windowRect.left,
      g_windowRect.top,
      g_windowRect.right - g_windowRect.left + 1,
      g_windowRect.bottom - g_windowRect.top + 1,
      NULL, NULL, hInstance, NULL
    );
  } else {
    AdjustWindowRectEx(&g_windowRect, WS_CAPTION | WS_SYSMENU, 0, WS_EX_APPWINDOW);

    m_windowHandle = CreateWindowExA(
      WS_EX_APPWINDOW,
      WNDCLASS_NAME,
      WINDOW_TITLE,
      WS_CAPTION | WS_SYSMENU | WS_MAXIMIZEBOX | WS_MINIMIZEBOX,
      CW_USEDEFAULT,
      CW_USEDEFAULT,
      g_windowRect.right - g_windowRect.left + 1,
      g_windowRect.bottom - g_windowRect.top + 1,
      NULL, NULL, hInstance, NULL
    );
  }

  if (!m_windowHandle) {
    return FAILURE;
  }

  if (m_fullScreen) {
    MoveWindow(m_windowHandle, g_windowRect.left, g_windowRect.top, (g_windowRect.right - g_windowRect.left) + 1, (g_windowRect.bottom - g_windowRect.top) + 1, TRUE);
  }

  ShowWindow(m_windowHandle, SW_SHOWNORMAL);
  UpdateWindow(m_windowHandle);
  if (!SetupLegoOmni()) {
    return FAILURE;
  }

  GameState()->SetSavePath(m_savePath);
  GameState()->SerializePlayersInfo(1);
  GameState()->SerializeScoreHistory(1);

  int iVar10;
  switch (m_islandQuality) {
    case 0:
      iVar10 = 1;
      break;
    case 1:
      iVar10 = 2;
      break;
    default:
      iVar10 = 100;
  }

  int uVar1 = (m_islandTexture == 0);
  LegoModelPresenter::configureLegoModelPresenter(uVar1);
  LegoPartPresenter::configureLegoPartPresenter(uVar1,iVar10);
  LegoWorldPresenter::configureLegoWorldPresenter(m_islandQuality);
  LegoBuildingManager::configureLegoBuildingManager(m_islandQuality);
  LegoROI::configureLegoROI(iVar10);
  LegoAnimationManager::configureLegoAnimationManager(m_islandQuality);
  if (LegoOmni::GetInstance()) {
    if (LegoOmni::GetInstance()->GetInputManager()) {
      LegoOmni::GetInstance()->GetInputManager()->m_useJoystick = m_useJoystick;
      LegoOmni::GetInstance()->GetInputManager()->m_joystickIndex = m_joystickIndex;
    }
  }
  if (m_fullScreen) {
    MoveWindow(m_windowHandle, g_windowRect.left, g_windowRect.top, (g_windowRect.right - g_windowRect.left) + 1, (g_windowRect.bottom - g_windowRect.top) + 1, TRUE);
  }
  ShowWindow(m_windowHandle, SW_SHOWNORMAL);
  UpdateWindow(m_windowHandle);

  return SUCCESS;
}

// OFFSET: ISLE 0x402c20
inline void Isle::Tick(BOOL sleepIfNotNextFrame)
{
  if (this->m_windowActive) {
    if (!Lego()) return;
    if (!TickleManager()) return;
    if (!Timer()) return;

    long currentTime = Timer()->GetRealTime();
    if (currentTime < g_lastFrameTime) {
      g_lastFrameTime = -this->m_frameDelta;
    }
    if (this->m_frameDelta + g_lastFrameTime < currentTime) {
      if (!Lego()->vtable40()) {
        TickleManager()->Tickle();
      }
      g_lastFrameTime = currentTime;

      if (g_startupDelay == 0) {
        return;
      }

      g_startupDelay--;
      if (g_startupDelay != 0) {
        return;
      }

      LegoOmni::GetInstance()->CreateBackgroundAudio();
      BackgroundAudioManager()->Enable(this->m_useMusic);

      MxStreamController *stream = Streamer()->Open("\\lego\\scripts\\isle\\isle", 0);
      MxDSAction ds;

      if (!stream) {
        stream = Streamer()->Open("\\lego\\scripts\\nocd", 0);
        if (!stream) {
          return;
        }

        ds.SetAtomId(stream->atom);
        ds.SetUnknown24(-1);
        ds.SetUnknown1c(0);
        VideoManager()->EnableFullScreenMovie(TRUE, TRUE);

        if (Start(&ds) != SUCCESS) {
          return;
        }
      } else {
        ds.SetAtomId(stream->atom);
        ds.SetUnknown24(-1);
        ds.SetUnknown1c(0);
        if (Start(&ds) != SUCCESS) {
          return;
        }
        this->m_gameStarted = 1;
      }
      return;
    }
    if (sleepIfNotNextFrame == 0) return;
  }

  Sleep(0);
}

#endif // ISLE_H
