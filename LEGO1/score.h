#ifndef SCORE_H
#define SCORE_H

#include "legoworld.h"
#include "scorestate.h"
#include "mxactionnotificationparam.h"
#include "mxappnotificationparam.h"
#include "mxtype17notificationparam.h"

extern MxAtomId *g_infoscorScript;

// VTABLE 0x100d4018
// SIZE 0x104
class Score : public LegoWorld
{
public:
  Score();
  virtual ~Score() override; // vtable+0x0
  virtual MxLong Notify(MxParam &p) override; // vtable+0x4
  
  // OFFSET: LEGO1 0x100010c0
  inline virtual const char *ClassName() const override // vtable+0x0c
  {
    // 0x100f0058
    return "Score";
  }

  // OFFSET: LEGO1 0x100010d0
  inline virtual MxBool IsA(const char *name) const override // vtable+0x10
  {
    return !strcmp(name, Score::ClassName()) || LegoWorld::IsA(name);
  }

  MxResult InitFromMxDSObject(MxDSObject& p_object); // vtable+0x18
  virtual void Stop() override; // vtable+0x50
  virtual MxBool VTable0x5c() override; // vtable+0x5c
  virtual MxBool VTable0x64() override; // vtable+64
  virtual void VTable0x68(MxBool p_add) override; // vtable+68

  void Paint();
  MxLong FUN_10001510(MxEndActionNotificationParam &p);
  MxLong FUN_100016d0(MxType17NotificationParam &p);
  void FillArea(MxU32 p_1, MxU32 p_2, MxS16 p_3);

protected:
  undefined4 m_unkF8;
  ScoreState *m_state;
  MxU8 *m_surface;
private:
  void DeleteScript();
};

#endif // SCORE_H
