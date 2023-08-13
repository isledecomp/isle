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

  MxResult Init();
  void SetInternalAction(MxDSAction *p_dsAction);

private:
  MxU32 m_unk94;
  MxU32 m_bufferOffset;
  MxS32 m_unk9c;
  MxDSBuffer *m_unka0;
  MxDSBuffer *m_unka4;
  undefined4 m_unka8;
  undefined2 m_unkac;
  MxDSAction *m_internalAction;
};

#endif // MXDSSTREAMINGACTION_H
