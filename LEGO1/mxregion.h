#ifndef MXREGION_H
#define MXREGION_H

#include "mxcore.h"
#include "mxregionlist.h"
#include "mxrect32.h"
#include "decomp.h"

// SIZE 0x0c
struct MxRegionTopBottom
{
  MxS32 m_top;
  MxS32 m_bottom;
  MxRegionLeftRightList *m_leftRightList;
};

// SIZE 0x08
struct MxRegionLeftRight
{
  MxS32 m_left;
  MxS32 m_right;
};

// VTABLE 0x100dcae8
// SIZE 0x1c
class MxRegion : public MxCore
{
public:
  MxRegion();
  virtual ~MxRegion() override;

  virtual void Reset();
  virtual void vtable18(MxRect32 &p_rect);
  virtual void vtable1c();
  virtual MxBool vtable20();

  inline MxRect32 &GetRect() { return this->m_rect; }

private:
  MxRegionList *m_list;
  MxRect32 m_rect;
};

#endif // MXREGION_H
