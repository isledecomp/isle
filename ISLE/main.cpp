#include <dsound.h>

#include "legoinc.h"
#include "define.h"

#include "isle.h"
#include "legoomni.h"

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
  if (g_isle->SetupWindow(hInstance) != SUCCESS) {
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
      g_isle->Tick(1);
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
    } while (!g_closed);
  }

  DestroyWindow(window);

  return msg.wParam;
}
