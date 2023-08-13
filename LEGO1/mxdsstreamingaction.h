#ifndef MXDSSTREAMINGACTION_H
#define MXDSSTREAMINGACTION_H

#include "mxdsaction.h"

class MxDSBuffer;

// VTABLE 0x100dd088
// SIZE 0xb4
class MxDSStreamingAction : public MxDSAction
{
public:
  MxDSStreamingAction(MxDSAction &p_dsAction, MxU32 p_offset);
  MxDSStreamingAction(MxDSStreamingAction &p_dsStreamingAction);
  virtual ~MxDSStreamingAction();

  MxDSStreamingAction *CopyFrom(MxDSStreamingAction &p_dsStreamingAction);

  virtual MxBool HasId(MxU32 p_objectId); // vtable+34;

  MxResult Init();
  void SetInternalAction(MxDSAction *p_dsAction);
  void FUN_100CD2D0();

private:
  MxU32 m_unk94;
  MxU32 m_bufferOffset;
  MxS32 m_unk9c;
  MxDSBuffer *m_unka0;
  MxDSBuffer *m_unka4;
  MxLong m_unka8;
  undefined2 m_unkac;
  MxDSAction *m_internalAction;
};

#endif // MXDSSTREAMINGACTION_H
