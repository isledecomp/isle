#ifndef LEGOVIDEOMANAGER_H
#define LEGOVIDEOMANAGER_H

#include "lego3dmanager.h"

// class LegoVideoManager : public MxVideoManager
class LegoVideoManager
{
public:
  __declspec(dllexport) int EnableRMDevice();
  __declspec(dllexport) int DisableRMDevice();
  __declspec(dllexport) void EnableFullScreenMovie(unsigned char a, unsigned char b);
  __declspec(dllexport) void MoveCursor(int x, int y);

  inline Lego3DManager *Get3DManager() { return this->m_3dManager; }

  int m_unk00;
  int m_unk04;
  int m_unk08;
  int m_unk0c;
  int m_unk10;
  int m_unk14;
  int m_unk18;
  int m_unk1c;
  int m_unk20;
  int m_unk24;
  int m_unk28;
  int m_unk2c;
  int m_unk30;
  int m_unk34;
  int m_unk38;
  int m_unk3c;
  int m_unk40;
  int m_unk44;
  int m_unk48;
  int m_unk4c;
  int m_unk50;
  int m_unk54;
  int m_unk58;
  int m_unk5c;
  int m_unk60;
  int m_unk64;
  Lego3DManager *m_3dManager;
  int m_unk6c;
  int m_unk70;
  int *m_unk74;
};

#endif // LEGOVIDEOMANAGER_H
