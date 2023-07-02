#ifndef LEGOSOUNDMANAGER_H
#define LEGOSOUNDMANAGER_H

#include "mxsoundmanager.h"

// VTABLE 0x100d6b10
// SIZE 0x44
class LegoSoundManager : public MxSoundManager
{
public:
  LegoSoundManager();
  virtual ~LegoSoundManager() override;
  virtual MxLong Tickle() override; // vtable+08

private:
  void Init();

};

#endif // LEGOSOUNDMANAGER_H
