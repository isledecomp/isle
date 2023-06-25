#ifndef LEGOVIDEOMANAGER_H
#define LEGOVIDEOMANAGER_H

#include "mxvideomanager.h"
#include "lego3dmanager.h"

class LegoVideoManager : public MxVideoManager
{
public:
  __declspec(dllexport) int EnableRMDevice();
  __declspec(dllexport) int DisableRMDevice();
  __declspec(dllexport) void EnableFullScreenMovie(unsigned char a, unsigned char b);
  __declspec(dllexport) void MoveCursor(int x, int y);

  inline Lego3DManager *Get3DManager() { return this->m_3dManager; }
  void SetSkyColor(float r, float g, float b);

  int m_unk64;
  Lego3DManager *m_3dManager;
  int m_unk6c;
  int m_unk70;
  int *m_unk74;
};

#endif // LEGOVIDEOMANAGER_H
