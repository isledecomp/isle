#ifndef LEGOVIDEOMANAGER_H
#define LEGOVIDEOMANAGER_H

#include "mxvideomanager.h"
#include "mxdirect3d.h"
#include "lego3dmanager.h"
#include "decomp.h"
#include "ddraw.h"

// VTABLE 0x100d9c88
// SIZE 0x590
class LegoVideoManager : public MxVideoManager
{
public:
  LegoVideoManager();
  virtual ~LegoVideoManager() override;

  __declspec(dllexport) int EnableRMDevice();
  __declspec(dllexport) int DisableRMDevice();
  void EnableFullScreenMovie(MxBool p_enable);
  __declspec(dllexport) void EnableFullScreenMovie(MxBool p_enable, MxBool p_scale);
  __declspec(dllexport) void MoveCursor(int x, int y);

  inline Lego3DManager *Get3DManager() { return this->m_3dManager; }
  inline MxDirect3D *GetDirect3D() { return this->m_direct3d; }

  void SetSkyColor(float r, float g, float b);
  inline void SetUnkE4(MxBool p_value) { this->m_unke4 = p_value; }

  // OFFSET: LEGO1 0x1007c4c0
  void OverrideSkyColor(MxBool p_shouldOverride) { this->m_videoParam.GetPalette()->SetOverrideSkyColor(p_shouldOverride);}

private:
  undefined4 m_unk64;
  Lego3DManager *m_3dManager;
  undefined4 m_unk6c;
  undefined4 m_unk70;
  MxDirect3D *m_direct3d;
  undefined m_pad78[0x6c];
  MxBool m_unke4;
  undefined m_pade5[2];
  PALETTEENTRY m_paletteEntries[256];
  MxBool m_unk4e7;
  undefined4 m_unk4e8;
  MxBool m_isFullScreenMovie;
  undefined m_pad4ed[0x14];
  MxBool m_cursorMoved;
  undefined m_pad4f8[8];
  int m_cursorX;
  int m_cursorY;
};

#endif // LEGOVIDEOMANAGER_H
