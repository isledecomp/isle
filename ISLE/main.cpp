#include <dsound.h>

#include "legoinc.h"
#include "define.h"

#include "legoomni.h"
#include "isle.h"

// OFFSET: ISLE 0x401ca0
BOOL FindExistingInstance(void)
{
  HWND hWnd = FindWindowA(WNDCLASS_NAME, WINDOW_TITLE);
  if (hWnd) {
    if (SetForegroundWindow(hWnd)) {
      ShowWindow(hWnd, SW_RESTORE);
    }
    return 0;
  }
  return 1;
}

// OFFSET: ISLE 0x401ce0
BOOL StartDirectSound(void)
{
  LPDIRECTSOUND lpDS = NULL;
  HRESULT ret = DirectSoundCreate(NULL, &lpDS, NULL);
  if (ret == DS_OK && lpDS != NULL) {
    lpDS->Release();
    return TRUE;
  }

  return FALSE;
}

// OFFSET: ISLE 0x401610
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nShowCmd)
{
  // Look for another instance, if we find one, bring it to the foreground instead
  if (!FindExistingInstance()) {
    return 0;
  }

  // Attempt to create DirectSound instance
  BOOL soundReady = FALSE;
  for (int i = 0; i < 20; i++) {
    if (StartDirectSound()) {
      soundReady = TRUE;
      break;
    }
    Sleep(500);
  }

  // Throw error if sound unavailable
  if (!soundReady) {
    MessageBoxA(NULL, "\"LEGO\xAE Island\" is not detecting a DirectSound compatible sound card.  Please quit all other applications and try again.",
      "Lego Island Error", MB_OK);
    return 0;
  }

  // Create global app instance
  g_isle = new Isle();

  // Create window
  if (g_isle->SetupWindow(hInstance, lpCmdLine) != SUCCESS) {
    MessageBoxA(NULL, "\"LEGO\xAE Island\" failed to start.  Please quit all other applications and try again.", "LEGO\xAE Island Error", MB_OK);
    return 0;
  }

  // Get reference to window
  HWND window;
  if (g_isle->m_windowHandle) {
    window = g_isle->m_windowHandle;
  }

  // Load accelerators (this call actually achieves nothing - there is no "AppAccel" resource in the original - but we'll keep this for authenticity)
  // This line may actually be here because it's in DFVIEW, an example project that ships with
  // MSVC420, and was such a clean example of a Win32 app, that it was later adapted
  // into an "ExeSkeleton" sample for MSVC600. It's quite possible Mindscape derived
  // this app from that example since they no longer had the luxury of the
  // MFC AppWizard which we know they used for the frontend used during development (ISLEMFC.EXE, MAIN.EXE, et al.)
  LoadAcceleratorsA(hInstance, "AppAccel");

  MSG msg;

  while (!g_closed) {
    while (!PeekMessageA(&msg, NULL, 0, 0, PM_NOREMOVE)) {
      if (g_isle) {
        g_isle->Tick(1);
      }
    }

    if (g_isle) {
      g_isle->Tick(0);
    }

    while (!g_closed) {
      if (!PeekMessageA(&msg, NULL, 0, 0, PM_REMOVE)) {
        break;
      }

      MSG nextMsg;
      if (!g_isle
          || !g_isle->m_windowHandle
          || msg.message != WM_MOUSEMOVE
          || !PeekMessageA(&nextMsg, NULL, 0, 0, PM_NOREMOVE)
          || nextMsg.message != WM_MOUSEMOVE) {
        TranslateMessage(&msg);
        DispatchMessageA(&msg);
      }

      if (g_reqEnableRMDevice) {
        g_reqEnableRMDevice = 0;
        VideoManager()->EnableRMDevice();
        g_rmDisabled = 0;
        Lego()->vtable3c();
      }

      if (g_closed) {
        break;
      }

      if (g_mousedown == 0) {
LAB_00401bc7:
        if (g_mousemoved) {
          g_mousemoved = FALSE;
        }
      } else if (g_mousemoved) {
        if (g_isle) {
          g_isle->Tick(0);
        }
        goto LAB_00401bc7;
      }
    }
  }

  DestroyWindow(window);

  return msg.wParam;
}

// OFFSET: ISLE 0x401d20
LRESULT WINAPI WndProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
  NotificationId type;
  unsigned char keyCode = 0;

  MINMAXINFO *mmi = (MINMAXINFO*) lParam;

  if (!g_isle) {
    return DefWindowProcA(hWnd, uMsg, wParam, lParam);
  }

  switch (uMsg) {
  case WM_PAINT:
    return DefWindowProcA(hWnd, uMsg, wParam, lParam);
  case WM_ACTIVATE:
    return DefWindowProcA(hWnd, uMsg, wParam, lParam);
  case WM_ACTIVATEAPP:
    if (g_isle) {
      if ((wParam != 0) && (g_isle->m_fullScreen)) {
        MoveWindow(hWnd, g_windowRect.left, g_windowRect.top,
                   (g_windowRect.right - g_windowRect.left) + 1,
                   (g_windowRect.bottom - g_windowRect.top) + 1, TRUE);
      }
      g_isle->m_windowActive = wParam;
    }
    return DefWindowProcA(hWnd,uMsg,wParam,lParam);
  case WM_CLOSE:
    if (!g_closed && g_isle) {
      if (g_isle) {
        delete g_isle;
      }
      g_isle = NULL;
      g_closed = TRUE;
      return 0;
    }
    return DefWindowProcA(hWnd,uMsg,wParam,lParam);
  case WM_GETMINMAXINFO:
    mmi->ptMaxTrackSize.x = (g_windowRect.right - g_windowRect.left) + 1;
    mmi->ptMaxTrackSize.y = (g_windowRect.bottom - g_windowRect.top) + 1;
    mmi->ptMinTrackSize.x = (g_windowRect.right - g_windowRect.left) + 1;
    mmi->ptMinTrackSize.y = (g_windowRect.bottom - g_windowRect.top) + 1;
    return 0;
  case WM_ENTERMENULOOP:
    return DefWindowProcA(hWnd,uMsg,wParam,lParam);
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
    return DefWindowProcA(hWnd,uMsg,wParam,lParam);
  case WM_EXITMENULOOP:
    return DefWindowProcA(hWnd, uMsg, wParam, lParam);
  case WM_MOVING:
    if (g_isle && g_isle->m_fullScreen) {
      GetWindowRect(hWnd, (LPRECT) lParam);
      return 0;
    }
    return DefWindowProcA(hWnd, uMsg, wParam, lParam);
  case WM_NCPAINT:
    if (g_isle && g_isle->m_fullScreen) {
      return 0;
    }
    return DefWindowProcA(hWnd, uMsg, wParam, lParam);
  case WM_DISPLAYCHANGE:
    if (g_isle && VideoManager() && g_isle->m_fullScreen && VideoManager()->m_unk74 && VideoManager()->m_unk74[0x220]) {
      int targetWidth = LOWORD(lParam);
      int targetHeight = HIWORD(lParam);

      if (g_waitingForTargetDepth) {
        g_waitingForTargetDepth = 0;
        g_targetDepth = wParam;
      }
      else {
        BOOL valid = FALSE;
        if (targetWidth == g_targetWidth && targetHeight == g_targetHeight && g_targetDepth == wParam) {
          valid = TRUE;
        }

        if (g_rmDisabled) {
          if (valid) {
             g_reqEnableRMDevice = 1;
          }
        }
        else if (!valid) {
          g_rmDisabled = 1;
          Lego()->vtable38();
          VideoManager()->DisableRMDevice();
        }
      }
    }
    return DefWindowProcA(hWnd, uMsg, wParam, lParam);
  case WM_SETCURSOR:
    if (g_isle) {
      HCURSOR hCursor = g_isle->m_cursorCurrent;
      if (hCursor == g_isle->m_cursorBusy || hCursor == g_isle->m_cursorNo || !hCursor) {
        SetCursor(hCursor);
        return 0;
      }
    }
    break;
  case WM_KEYDOWN:
    // While this probably should be (HIWORD(lParam) & KF_REPEAT), this seems
    // to be what the assembly is actually doing
    if (lParam & (KF_REPEAT << 16)) {
      return DefWindowProcA(hWnd, uMsg, wParam, lParam);
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
      g_isle->SetupCursor(wParam);
      return 0;
    }
    break;
  default:
    return DefWindowProcA(hWnd,uMsg,wParam,lParam);
  }

  if (g_isle) {
    if (InputManager()) {
      InputManager()->QueueEvent(type, wParam, LOWORD(lParam), HIWORD(lParam), keyCode);
    }
    if (g_isle && g_isle->m_drawCursor && type == MOUSEMOVE) {
      int x = LOWORD(lParam);
      int y = HIWORD(lParam);
      if (x >= 640) {
        x = 639;
      }
      if (y >= 480) {
        y = 479;
      }
      VideoManager()->MoveCursor(x,y);
    }
  }

  return 0;
}