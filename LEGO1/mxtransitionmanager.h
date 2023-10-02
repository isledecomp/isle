#ifndef MXTRANSITIONMANAGER_H
#define MXTRANSITIONMANAGER_H

#include "mxcore.h"
#include "mxvideopresenter.h"
#include "legoomni.h"

#include <ddraw.h>

class MxTransitionManagerUnknownSubclass2
{
public:
  virtual ~MxTransitionManagerUnknownSubclass2(){}

  undefined m_unk04[0x2c];
  undefined4 m_unk30;
  undefined4 m_unk34;
  undefined4 m_unk38;
  undefined4 m_unk3c;

};

// TODO: Don't know what this is yet
class MxTransitionManagerUnknownSubclass1
{
public:
  virtual ~MxTransitionManagerUnknownSubclass1(){}

  virtual void vtable04();
  virtual void vtable08();
  virtual void vtable0c();
  virtual void vtable10();
  virtual void vtable14();
  virtual void vtable18();
  virtual void vtable1c();
  virtual void vtable20();
  virtual void vtable24();
  virtual void vtable28();
  virtual void vtable2c();
  virtual void vtable30();
  virtual void vtable34();
  virtual void vtable38();
  virtual void vtable3c();
  virtual void vtable40();
  virtual void vtable44();
  virtual void vtable48();
  virtual void vtable4c();
  virtual void vtable50();
  virtual void vtable54(undefined4 p_unk1);

  undefined m_unk04[0x18];
  MxTransitionManagerUnknownSubclass2 *m_unk1c;

};

// VTABLE 0x100d7ea0
class MxTransitionManager : public MxCore
{
public:
  MxTransitionManager();
  virtual ~MxTransitionManager() override; // vtable+0x0

  __declspec(dllexport) void SetWaitIndicator(MxVideoPresenter *videoPresenter);

  virtual MxResult Tickle(); // vtable+0x8

  // OFFSET: LEGO1 0x1004b950
  inline virtual const char *ClassName() const override // vtable+0x0c
  {
    return "MxTransitionManager";
  }

  // OFFSET: LEGO1 0x1004b960
  inline virtual MxBool IsA(const char *name) const override // vtable+0x10
  {
    return !strcmp(name, MxTransitionManager::ClassName()) || MxCore::IsA(name);
  }

  virtual MxResult GetDDrawSurfaceFromVideoManager(); // vtable+0x14

  enum TransitionType {
    NOT_TRANSITIONING,
    NO_ANIMATION,
    DISSOLVE,
    PIXELATION,
    SCREEN_WIPE,
    WINDOWS,
    BROKEN // Unknown what this is supposed to be, it locks the game up
  };

  MxResult StartTransition(TransitionType p_animationType, MxS32 p_speed, MxBool p_unk, MxBool p_playMusicInAnim);

private:
  MxTransitionManagerUnknownSubclass1 *m_unk08;
  undefined4 m_unk0c;
  undefined4 m_unk10;
  undefined4 m_unk14;
  undefined4 m_unk18;
  void *m_unk1c;
  flag_bitfield m_unk20;
  undefined4 m_unk24;
  flag_bitfield m_unk28;

  TransitionType m_transitionType;
  LPDIRECTDRAWSURFACE m_ddSurface;
  MxU16 m_animationTimer;
  undefined m_pad36[0x8c2];
  MxULong m_systemTime;
  MxS32 m_animationSpeed;
};

#endif // MXTRANSITIONMANAGER_H
