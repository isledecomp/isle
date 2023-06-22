#ifndef ISLE_H
#define ISLE_H

#include "legoinc.h"
#include "define.h"

#include "legoomni.h"
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

// OFFSET: ISLE 0x401c40
inline void MxDSObject::SetAtomId(MxAtomId p_atomId) { this->m_atomId = p_atomId; }

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
