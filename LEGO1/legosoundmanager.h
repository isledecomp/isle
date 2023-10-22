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

  virtual MxResult Tickle() override; // vtable+08
  virtual void Destroy() override; // vtable+18
  virtual void SetVolume(MxS32 p_volume) override; // vtable+2c
  virtual MxResult Create(MxU32 p_frequencyMS, MxBool p_createThread) override; //vtable+0x30
  virtual void vtable0x34() override; // vtable+0x34
  virtual void vtable0x38() override; // vtable+0x38

private:
  void Init();
  void Destroy(MxBool p_fromDestructor);
  undefined4 unk0x40;
  undefined4 unk0x3c;
};

#endif // LEGOSOUNDMANAGER_H
