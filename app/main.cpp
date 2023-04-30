#include <DSOUND.H>
#include <Windows.h>

#include "define.h"
#include "isle.h"
#include "../lib/legoomni.h"

BOOL findExistingInstance(void)
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

BOOL startDirectSound(void)
{
  LPDIRECTSOUND lpDS;
  HRESULT ret = DirectSoundCreate(NULL, &lpDS, NULL);
  if (ret == DS_OK && lpDS != NULL) {
    lpDS->Release();
    return TRUE;
  }

  return FALSE;
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nShowCmd)
{
  // Look for another instance, if we find one, bring it to the foreground instead
  if (!findExistingInstance()) {
    return 0;
  }

  // Attempt to create DirectSound instance
  BOOL soundReady = FALSE;
  for (int i = 0; i < 20; i++) {
    if (startDirectSound()) {
      soundReady = TRUE;
      break;
    }
    Sleep(500);
  }

  // Throw error if sound unavailable
  if (!soundReady) {
    MessageBoxA(NULL, "\"LEGO® Island\" is not detecting a DirectSound compatible sound card.  Please quit all other applications and try again.",
      "Lego Island Error",0);
    return 0;
  }

  // Create global app instance
  g_isle = new Isle();

  // Create window
  if (g_isle->setupWindow(hInstance) != SUCCESS) {
    MessageBoxA(NULL, "\"LEGO® Island\" failed to start.  Please quit all other applications and try again.", "LEGO® Island Error",0);
    return 0;
  }

  // Get reference to window
  HWND window;
  if (g_isle->m_windowHandle) {
    window = g_isle->m_windowHandle;
  }

  // Load accelerator (don't know what this does)
  LoadAcceleratorsA(hInstance, "AppAccel");

  MSG msg;

  while (!g_closed) {
    while (!PeekMessageA(&msg, NULL, 0, 0, PM_NOREMOVE)) {
      if (g_isle) {
        g_isle->tick(1);
      }
    }

    if (g_isle) {
      g_isle->tick(1);
    }

    if (g_closed) {
      break;
    }

    do {
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

      if (_DAT_00410064 != 0) {
        _DAT_00410064 = 0;
        VideoManager()->EnableRMDevice();
        _DAT_00410050 = 0;
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
          g_isle->tick(0);
        }
        goto LAB_00401bc7;
      }
    } while (!g_closed);
  }

  DestroyWindow(window);

  return msg.wParam;
}
