#ifndef LEGOVIDEOMANAGER_H
#define LEGOVIDEOMANAGER_H

#include "mxvideomanager.h"
#include "mxdirect3d.h"
#include "lego3dmanager.h"
#include "decomp.h"

// VTABLE 0x100d9c88
// SIZE 0x590
class LegoVideoManager : public MxVideoManager
{
public:
  LegoVideoManager();
  virtual ~LegoVideoManager() override;

  __declspec(dllexport) int EnableRMDevice();
  __declspec(dllexport) int DisableRMDevice();
  __declspec(dllexport) void EnableFullScreenMovie(unsigned char a, unsigned char b);
  __declspec(dllexport) void MoveCursor(int x, int y);

  inline Lego3DManager *Get3DManager() { return this->m_3dManager; }
  inline MxDirect3D *GetDirect3D() { return this->m_direct3d; }

  void SetSkyColor(float r, float g, float b);

private:
  undefined4 m_unk64;
  Lego3DManager *m_3dManager;
  undefined4 m_unk6c;
  undefined4 m_unk70;
  MxDirect3D *m_direct3d;
};

#endif // LEGOVIDEOMANAGER_H
