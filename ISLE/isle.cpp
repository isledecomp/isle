#include "isle.h"

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

  m_videoParam = MxVideoParam(MxRect32(0, 0, 639, 479), NULL, 1, MxVideoParamFlags());
  m_videoParam.flags().Set16Bit(MxDirectDraw::GetPrimaryBitDepth() == 16);

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
    Close();
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
void Isle::Close()
{
  MxDSAction ds;
  ds.SetUnknown24(-2);

  if (Lego()) {
    GameState()->Save(0);
    if (InputManager()) {
      InputManager()->QueueEvent(KEYDOWN, 0, 0, 0, 0x20);
    }

    VideoManager()->Get3DManager()->GetLego3DView()->GetViewManager()->RemoveAll(NULL);

    Lego()->RemoveWorld(ds.GetAtomId(), ds.GetUnknown1c());
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
BOOL Isle::ReadReg(LPCSTR name, LPSTR outValue, DWORD outSize)
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
int Isle::ReadRegBool(LPCSTR name, BOOL *out)
{
  char buffer[256];

  BOOL read = ReadReg(name, buffer, sizeof(buffer));
  if (read) {
    if (strcmp("YES", buffer) == 0) {
      *out = TRUE;
      return read;
    }

    if (strcmp("NO", buffer) == 0) {
      *out = FALSE;
      return read;
    }

    read = FALSE;
  }
  return read;
}

// OFFSET: ISLE 0x402880
int Isle::ReadRegInt(LPCSTR name, int *out)
{
  char buffer[256];

  BOOL read = ReadReg(name, buffer, sizeof(buffer));
  if (read) {
    *out = atoi(buffer);
  }

  return read;
}

// OFFSET: ISLE 0x4028d0
void Isle::LoadConfig()
{
  char buffer[1024];

  if (!ReadReg("diskpath", buffer, sizeof(buffer))) {
    strcpy(buffer, MxOmni::GetHD());
  }

  m_hdPath = new char[strlen(buffer) + 1];
  strcpy(m_hdPath, buffer);
  MxOmni::SetHD(m_hdPath);

  if (!ReadReg("cdpath", buffer, sizeof(buffer))) {
    strcpy(buffer, MxOmni::GetCD());
  }

  m_cdPath = new char[strlen(buffer) + 1];
  strcpy(m_cdPath, buffer);
  MxOmni::SetCD(m_cdPath);

  ReadRegBool("Flip Surfaces", &m_flipSurfaces);
  ReadRegBool("Full Screen", &m_fullScreen);
  ReadRegBool("Wide View Angle", &m_wideViewAngle);
  ReadRegBool("3DSound", &m_use3dSound);
  ReadRegBool("Music", &m_useMusic);
  ReadRegBool("UseJoystick", &m_useJoystick);
  ReadRegInt("JoystickIndex", &m_joystickIndex);
  ReadRegBool("Draw Cursor", &m_drawCursor);

  int backBuffersInVRAM;
  if (ReadRegBool("Back Buffers in Video RAM",&backBuffersInVRAM)) {
    m_backBuffersInVram = !backBuffersInVRAM;
  }

  int bitDepth;
  if (ReadRegInt("Display Bit Depth", &bitDepth)) {
    if (bitDepth == 8) {
      m_using8bit = TRUE;
    } else if (bitDepth == 16) {
      m_using16bit = TRUE;
    }
  }

  if (!ReadReg("Island Quality", buffer, sizeof(buffer))) {
    strcpy(buffer, "1");
  }
  m_islandQuality = atoi(buffer);

  if (!ReadReg("Island Texture", buffer, sizeof(buffer))) {
    strcpy(buffer, "1");
  }
  m_islandTexture = atoi(buffer);

  if (ReadReg("3D Device ID", buffer, sizeof(buffer))) {
    m_deviceId = new char[strlen(buffer) + 1];
    strcpy(m_deviceId, buffer);
  }

  if (ReadReg("savepath", buffer, sizeof(buffer))) {
    m_savePath = new char[strlen(buffer) + 1];
    strcpy(m_savePath, buffer);
  }
}

// OFFSET: ISLE 0x401560
void Isle::SetupVideoFlags(BOOL fullScreen, BOOL flipSurfaces, BOOL backBuffers,
                           BOOL using8bit, BOOL using16bit, BOOL param_6, BOOL param_7,
                           BOOL wideViewAngle, char *deviceId)
{
  m_videoParam.flags().SetFullScreen(fullScreen);
  m_videoParam.flags().SetFlipSurfaces(flipSurfaces);
  m_videoParam.flags().SetBackBuffers(!backBuffers);
  m_videoParam.flags().Set_f2bit0(!param_6);
  m_videoParam.flags().Set_f1bit7(param_7);
  m_videoParam.flags().SetWideViewAngle(wideViewAngle);
  m_videoParam.flags().Set_f2bit1(1);
  m_videoParam.SetDeviceName(deviceId);
  if (using8bit) {
    m_videoParam.flags().Set16Bit(0);
  }
  if (using16bit) {
    m_videoParam.flags().Set16Bit(1);
  }
}

// OFFSET: ISLE 0x4013b0
BOOL Isle::SetupLegoOmni()
{
  BOOL result = FALSE;
  char mediaPath[256];
  GetProfileStringA("LEGO Island", "MediaPath", "", mediaPath, sizeof(mediaPath));

  BOOL failure = Lego()->Create(MxOmniCreateParam(mediaPath, (struct HWND__ *) m_windowHandle, m_videoParam, MxOmniCreateFlags())) == FAILURE;
  if (!failure) {
    VariableTable()->SetVariable("ACTOR_01", "");
    TickleManager()->vtable1c(VideoManager(), 10);
    result = TRUE;
  }

  return result;
}

// OFFSET: ISLE 0x402e80
void Isle::SetupCursor(WPARAM wParam)
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
  case 3:
  case 4:
  case 5:
  case 6:
  case 7:
  case 8:
  case 9:
  case 0xA:
    break;
  }

  SetCursor(m_cursorCurrent);
}