#include "isle.h"

#include "define.h"
#include "legoomni.h"
#include "mxdirectdraw.h"
#include "mxdsaction.h"
#include "mxomni.h"
#include "res/resource.h"

// OFFSET: ISLE 0x401000
Isle::Isle()
{
  m_hdPath = NULL;
  m_cdPath = NULL;
  m_deviceId = NULL;
  m_savePath = NULL;
  m_fullScreen = 1;
  m_flipSurfaces = 0;
  m_backBuffersInVram = 1;
  m_using8bit = 0;
  m_using16bit = 1;
  m_unk24 = 0;
  m_drawCursor = 0;
  m_use3dSound = 1;
  m_useMusic = 1;
  m_useJoystick = 0;
  m_joystickIndex = 0;
  m_wideViewAngle = 1;
  m_islandQuality = 1;
  m_islandTexture = 1;
  m_gameStarted = 0;
  m_frameDelta = 10;
  m_windowActive = 1;

  MxRect32 rect;
  rect.m_left = 0;
  rect.m_top = 0;
  rect.m_right = 639;
  rect.m_bottom = 479;

  m_videoParam = MxVideoParam(rect, NULL, 1, MxVideoParamFlags());
  m_videoParam.flags().Enable16Bit(MxDirectDraw::GetPrimaryBitDepth() == 16);

  m_windowHandle = NULL;
  m_cursorArrow = NULL;
  m_cursorBusy = NULL;
  m_cursorNo = NULL;
  m_cursorCurrent = NULL;

  LegoOmni::CreateInstance();
}

// OFFSET: ISLE 0x4011a0
Isle::~Isle()
{
  if (LegoOmni::GetInstance()) {
    close();
    MxOmni::DestroyInstance();
  }

  if (m_hdPath) {
    delete [] m_hdPath;
  }

  if (m_cdPath) {
    delete [] m_cdPath;
  }

  if (m_deviceId) {
    delete [] m_deviceId;
  }

  if (m_savePath) {
    delete [] m_savePath;
  }
}

// OFFSET: ISLE 0x401260
void Isle::close()
{
  MxDSAction ds;

  if (Lego()) {
    GameState()->Save(0);
    if (InputManager()) {
      InputManager()->QueueEvent(KEYDOWN, 0, 0, 0, 0x20);
    }

    VideoManager()->Get3DManager()->GetLego3DView()->GetViewManager()->RemoveAll(NULL);

    long local_88 = 0;
    Lego()->RemoveWorld(ds.m_atomId, local_88);
    Lego()->vtable24(ds);
    TransitionManager()->SetWaitIndicator(NULL);
    Lego()->vtable3c();

    long lVar8;
    do {
      lVar8 = Streamer()->Close(NULL);
    } while (lVar8 == 0);

    while (Lego()) {
      if (Lego()->vtable28(ds) != MX_FALSE) {
        break;
      }

      Timer()->GetRealTime();
      TickleManager()->Tickle();
    }
  }
}

// OFFSET: ISLE 0x402740
BOOL readReg(LPCSTR name, LPSTR outValue, DWORD outSize)
{
  HKEY hKey;
  DWORD valueType;

  BOOL out = FALSE;
  unsigned long size = outSize;
  if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Mindscape\\LEGO Island", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
    if (RegQueryValueExA(hKey, name, NULL, &valueType, (LPBYTE) outValue, &size) == ERROR_SUCCESS) {
      if (RegCloseKey(hKey) == ERROR_SUCCESS) {
        out = TRUE;
      }
    }
  }

  return out;
}

// OFFSET: ISLE 0x4027b0
int readRegBool(LPCSTR name, BOOL *out)
{
  char buffer[256];

  BOOL read = readReg(name, buffer, sizeof(buffer));
  if (read) {
    if (strcmp("YES", buffer) == 0) {
      *out = TRUE;
      return TRUE;
    }

    if (strcmp("NO", buffer) == 0) {
      *out = FALSE;
      return TRUE;
    }
  }
  return FALSE;
}

// OFFSET: ISLE 0x402880
int readRegInt(LPCSTR name, int *out)
{
  char buffer[256];

  if (readReg(name, buffer, sizeof(buffer))) {
    *out = atoi(buffer);
    return TRUE;
  }

  return FALSE;
}

// OFFSET: ISLE 0x4028d0
void Isle::loadConfig()
{
  char buffer[1024];

  if (!readReg("diskpath", buffer, sizeof(buffer))) {
    strcpy(buffer, MxOmni::GetHD());
  }

  m_hdPath = new char[strlen(buffer) + 1];
  strcpy(m_hdPath, buffer);
  MxOmni::SetHD(m_hdPath);

  if (!readReg("cdpath", buffer, sizeof(buffer))) {
    strcpy(buffer, MxOmni::GetCD());
  }

  m_cdPath = new char[strlen(buffer) + 1];
  strcpy(m_cdPath, buffer);
  MxOmni::SetCD(m_cdPath);

  readRegBool("Flip Surfaces", &m_flipSurfaces);
  readRegBool("Full Screen", &m_fullScreen);
  readRegBool("Wide View Angle", &m_wideViewAngle);
  readRegBool("3DSound", &m_use3dSound);
  readRegBool("Music", &m_useMusic);
  readRegBool("UseJoystick", &m_useJoystick);
  readRegInt("JoystickIndex", &m_joystickIndex);
  readRegBool("Draw Cursor", &m_drawCursor);

  int backBuffersInVRAM;
  if (readRegBool("Back Buffers in Video RAM",&backBuffersInVRAM)) {
    m_backBuffersInVram = !backBuffersInVRAM;
  }

  int bitDepth;
  if (readRegInt("Display Bit Depth", &bitDepth)) {
    if (bitDepth == 8) {
      m_using8bit = TRUE;
    } else if (bitDepth == 16) {
      m_using16bit = TRUE;
    }
  }

  if (!readReg("Island Quality", buffer, sizeof(buffer))) {
    strcpy(buffer, "1");
  }
  m_islandQuality = atoi(buffer);

  if (!readReg("Island Texture", buffer, sizeof(buffer))) {
    strcpy(buffer, "1");
  }
  m_islandTexture = atoi(buffer);

  if (readReg("3D Device ID", buffer, sizeof(buffer))) {
    m_deviceId = new char[strlen(buffer) + 1];
    strcpy(m_deviceId, buffer);
  }

  if (readReg("savepath", buffer, sizeof(buffer))) {
    m_savePath = new char[strlen(buffer) + 1];
    strcpy(m_savePath, buffer);
  }
}

// OFFSET: ISLE 0x401560
void Isle::setupVideoFlags(BOOL fullScreen, BOOL flipSurfaces, BOOL backBuffers,
                           BOOL using8bit, BOOL m_using16bit, BOOL param_6, BOOL param_7,
                           BOOL wideViewAngle, char *deviceId)
{
  m_videoParam.flags().EnableFullScreen(fullScreen);
  m_videoParam.flags().EnableFlipSurfaces(flipSurfaces);
  m_videoParam.flags().EnableBackBuffers(backBuffers);
  m_videoParam.flags().EnableUnknown1(param_6);
  m_videoParam.flags().SetUnknown3(param_7);
  m_videoParam.flags().EnableWideViewAngle(wideViewAngle);
  m_videoParam.flags().EnableUnknown2();
  m_videoParam.SetDeviceName(deviceId);
  if (using8bit) {
    m_videoParam.flags().Set8Bit();
  }
  if (m_using16bit) {
    m_videoParam.flags().Set16Bit();
  }
}

// OFFSET: ISLE 0x4013b0
BOOL Isle::setupLegoOmni()
{
  char mediaPath[256];
  GetProfileStringA("LEGO Island", "MediaPath", "", mediaPath, sizeof(mediaPath));

  if (Lego()->Create(MxOmniCreateParam(mediaPath, (struct HWND__ *) m_windowHandle, m_videoParam, MxOmniCreateFlags())) != FAILURE) {
    VariableTable()->SetVariable("ACTOR_01", "");
    TickleManager()->vtable1c(VideoManager(), 10);
    return TRUE;
  }

  return FALSE;
}

// OFFSET: ISLE 0x402e80
void Isle::setupCursor(WPARAM wParam)
{
  switch (wParam) {
  case 0:
    m_cursorCurrent = m_cursorArrow;
    break;
  case 1:
    m_cursorCurrent = m_cursorBusy;
    break;
  case 2:
    m_cursorCurrent = m_cursorNo;
    break;
  case 0xB:
    m_cursorCurrent = NULL;
    break;
  }

  SetCursor(m_cursorCurrent);
}

// OFFSET: ISLE 0x401d20
LRESULT WINAPI WndProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
  if (!g_isle) {
    return DefWindowProcA(hWnd, uMsg, wParam, lParam);
  }

  switch (uMsg) {
  case WM_PAINT:
    return DefWindowProcA(hWnd, WM_PAINT, wParam, lParam);
  case WM_ACTIVATE:
    return DefWindowProcA(hWnd, WM_ACTIVATE, wParam, lParam);
  case WM_ACTIVATEAPP:
    if (g_isle) {
      if ((wParam != 0) && (g_isle->m_fullScreen)) {
        MoveWindow(hWnd, g_windowRect.left, g_windowRect.top,
                   (g_windowRect.right - g_windowRect.left) + 1,
                   (g_windowRect.bottom - g_windowRect.top) + 1, TRUE);
      }
      g_isle->m_windowActive = wParam;
    }
    return DefWindowProcA(hWnd,WM_ACTIVATEAPP,wParam,lParam);
  case WM_CLOSE:
    if (!g_closed && g_isle) {
      if (g_isle) {
        delete g_isle;
      }
      g_isle = NULL;
      g_closed = TRUE;
      return 0;
    }
    return DefWindowProcA(hWnd,WM_CLOSE,wParam,lParam);
  case WM_GETMINMAXINFO:
  {
    MINMAXINFO *mmi = (MINMAXINFO *) lParam;

    mmi->ptMaxTrackSize.x = (g_windowRect.right - g_windowRect.left) + 1;
    mmi->ptMaxTrackSize.y = (g_windowRect.bottom - g_windowRect.top) + 1;
    mmi->ptMinTrackSize.x = (g_windowRect.right - g_windowRect.left) + 1;
    mmi->ptMinTrackSize.y = (g_windowRect.bottom - g_windowRect.top) + 1;

    return 0;
  }
  case WM_ENTERMENULOOP:
    return DefWindowProcA(hWnd,WM_ENTERMENULOOP,wParam,lParam);
  case WM_SYSCOMMAND:
    if (wParam == SC_SCREENSAVE) {
      return 0;
    }
    if (wParam == SC_CLOSE && g_closed == 0) {
      if (g_isle) {
        if (g_rmDisabled) {
          ShowWindow(g_isle->m_windowHandle, SW_RESTORE);
        }
        PostMessageA(g_isle->m_windowHandle, WM_CLOSE, 0, 0);
        return 0;
      }
    } else if (g_isle && g_isle->m_fullScreen && (wParam == SC_MOVE || wParam == SC_KEYMENU)) {
      return 0;
    }
    return DefWindowProcA(hWnd,WM_SYSCOMMAND,wParam,lParam);
  case WM_EXITMENULOOP:
    return DefWindowProcA(hWnd, WM_EXITMENULOOP, wParam, lParam);
  case WM_MOVING:
    if (g_isle && g_isle->m_fullScreen) {
      GetWindowRect(hWnd, (LPRECT) lParam);
      return 0;
    }
    return DefWindowProcA(hWnd, WM_MOVING, wParam, lParam);
  case WM_NCPAINT:
    if (g_isle && g_isle->m_fullScreen) {
      return 0;
    }
    return DefWindowProcA(hWnd, WM_NCPAINT, wParam, lParam);
  case WM_DISPLAYCHANGE:
    if (g_isle && VideoManager() && g_isle->m_fullScreen && VideoManager()->m_unk74 && VideoManager()->m_unk74[0x220]) {
      if (!g_waitingForTargetDepth) {
        unsigned char valid = FALSE;
        if (LOWORD(lParam) == g_targetWidth && HIWORD(lParam) == g_targetHeight && g_targetDepth == wParam) {
          valid = TRUE;
        }
        if (!g_rmDisabled) {
          if (!valid) {
            g_rmDisabled = 1;
            Lego()->vtable38();
            VideoManager()->DisableRMDevice();
          }
        } else if (valid) {
          g_reqEnableRMDevice = 1;
        }
      } else {
        g_waitingForTargetDepth = 0;
        g_targetDepth = wParam;
      }
    }
    return DefWindowProcA(hWnd, WM_DISPLAYCHANGE, wParam, lParam);
  case WM_SETCURSOR:
  case WM_KEYDOWN:
  case WM_MOUSEMOVE:
  case WM_TIMER:
  case WM_LBUTTONDOWN:
  case WM_LBUTTONUP:
  case 0x5400:
  {

    NotificationId type = NONE;
    unsigned char keyCode = 0;

    switch (uMsg) {
    case WM_KEYDOWN:
      // While this probably should be (HIWORD(lParam) & KF_REPEAT), this seems
      // to be what the assembly is actually doing
      if (lParam & (KF_REPEAT << 16)) {
        return DefWindowProcA(hWnd, WM_KEYDOWN, wParam, lParam);
      }
      keyCode = wParam;
      type = KEYDOWN;
      break;
    case WM_MOUSEMOVE:
      g_mousemoved = 1;
      type = MOUSEMOVE;
      break;
    case WM_TIMER:
      type = TIMER;
      break;
    case WM_SETCURSOR:
      if (g_isle) {
        HCURSOR hCursor = g_isle->m_cursorCurrent;
        if (hCursor == g_isle->m_cursorBusy || hCursor == g_isle->m_cursorNo || !hCursor) {
          SetCursor(hCursor);
          return 0;
        }
      }
      break;
    case WM_LBUTTONDOWN:
      g_mousedown = 1;
      type = MOUSEDOWN;
      break;
    case WM_LBUTTONUP:
      g_mousedown = 0;
      type = MOUSEUP;
      break;
    case 0x5400:
      if (g_isle) {
        g_isle->setupCursor(wParam);
        return 0;
      }
    }

    if (g_isle) {
      if (InputManager()) {
        InputManager()->QueueEvent(type, wParam, LOWORD(lParam), HIWORD(lParam), keyCode);
      }
      if (g_isle && g_isle->m_drawCursor && type == MOUSEMOVE) {
        unsigned short x = LOWORD(lParam);
        unsigned short y = HIWORD(lParam);
        if (639 < x) {
          x = 639;
        }
        if (479 < y) {
          y = 479;
        }
        VideoManager()->MoveCursor(x,y);
      }
    }
    return 0;
  }
  }

  return DefWindowProcA(hWnd,uMsg,wParam,lParam);
}

// OFFSET: ISLE 0x4023e0
MxResult Isle::setupWindow(HINSTANCE hInstance)
{
  WNDCLASSA wndclass;
  ZeroMemory(&wndclass, sizeof(WNDCLASSA));

  loadConfig();

  setupVideoFlags(m_fullScreen, m_flipSurfaces, m_backBuffersInVram, m_using8bit,
                  m_using16bit, m_unk24, FALSE, m_wideViewAngle, m_deviceId);

  MxOmni::SetSound3D(m_use3dSound);

  srand(timeGetTime() / 1000);
  SystemParametersInfoA(SPI_SETMOUSETRAILS, 0, NULL, 0);

  ZeroMemory(&wndclass, sizeof(WNDCLASSA));

  wndclass.cbClsExtra = 0;
  wndclass.style = CS_HREDRAW | CS_VREDRAW;
  wndclass.lpfnWndProc = WndProc;
  wndclass.cbWndExtra = 0;
  wndclass.hIcon = LoadIconA(hInstance, MAKEINTRESOURCE(APP_ICON));
  wndclass.hCursor = LoadCursorA(hInstance, MAKEINTRESOURCE(ISLE_ARROW));
  m_cursorCurrent = wndclass.hCursor;
  m_cursorArrow = wndclass.hCursor;
  m_cursorBusy = LoadCursorA(hInstance, MAKEINTRESOURCE(ISLE_BUSY));
  m_cursorNo = LoadCursorA(hInstance, MAKEINTRESOURCE(ISLE_NO));
  wndclass.hInstance = hInstance;
  wndclass.hbrBackground = (HBRUSH) GetStockObject(BLACK_BRUSH);
  wndclass.lpszClassName = WNDCLASS_NAME;

  if (!RegisterClassA(&wndclass)) {
    return FAILURE;
  }

  DWORD dwStyle;
  int x, y, width, height;

  if (!m_fullScreen) {
    AdjustWindowRectEx(&g_windowRect, WS_CAPTION | WS_SYSMENU, 0, WS_EX_APPWINDOW);

    height = g_windowRect.bottom - g_windowRect.top;
    width = g_windowRect.right - g_windowRect.left;

    y = CW_USEDEFAULT;
    x = CW_USEDEFAULT;
    dwStyle = WS_CAPTION | WS_SYSMENU | WS_MAXIMIZEBOX | WS_MINIMIZEBOX;
  } else {
    AdjustWindowRectEx(&g_windowRect, WS_CAPTION | WS_SYSMENU, 0, WS_EX_APPWINDOW);
    height = g_windowRect.bottom - g_windowRect.top;
    width = g_windowRect.right - g_windowRect.left;
    dwStyle = WS_CAPTION | WS_SYSMENU;
    x = g_windowRect.left;
    y = g_windowRect.top;
  }

  m_windowHandle = CreateWindowExA(WS_EX_APPWINDOW, WNDCLASS_NAME, WINDOW_TITLE, dwStyle,
                           x, y, width + 1, height + 1, NULL, NULL, hInstance, NULL);
  if (!m_windowHandle) {
    return FAILURE;
  }

  if (m_fullScreen) {
    MoveWindow(m_windowHandle, g_windowRect.left, g_windowRect.top, (g_windowRect.right - g_windowRect.left) + 1, (g_windowRect.bottom - g_windowRect.top) + 1, TRUE);
  }

  ShowWindow(m_windowHandle, SW_SHOWNORMAL);
  UpdateWindow(m_windowHandle);
  if (!setupLegoOmni()) {
    return FAILURE;
  }

  GameState()->SetSavePath(m_savePath);
  GameState()->SerializePlayersInfo(1);
  GameState()->SerializeScoreHistory(1);

  int iVar10;
  if (m_islandQuality == 0) {
    iVar10 = 1;
  } else if (m_islandQuality == 1) {
    iVar10 = 2;
  } else {
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
      LegoOmni::GetInstance()->GetInputManager()->m_unk00[0xCD] = m_useJoystick;
      LegoOmni::GetInstance()->GetInputManager()->m_unk00[0x67] = m_joystickIndex;
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
void Isle::tick(BOOL sleepIfNotNextFrame)
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

        ds.setAtomId(stream->atom);
        ds.m_unk24 = 0xFFFF;
        ds.m_unk1c = 0;
        VideoManager()->EnableFullScreenMovie(TRUE, TRUE);

        if (Start(&ds) != SUCCESS) {
          return;
        }
      } else {
        ds.setAtomId(stream->atom);
        ds.m_unk24 = 0xFFFF;
        ds.m_unk1c = 0;
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
