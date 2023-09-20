#include "mxdsmultiaction.h"

DECOMP_SIZE_ASSERT(MxDSMultiAction, 0x9c)

// OFFSET: LEGO1 0x100c9b90
MxDSMultiAction::MxDSMultiAction()
{
  this->SetType(MxDSType_MultiAction);
  this->m_actions = new MxDSActionList;
  this->m_actions->SetDestroy(MxDSActionList::Destroy);
}

// OFFSET: LEGO1 0x100ca060
MxDSMultiAction::~MxDSMultiAction()
{
  if (this->m_actions)
    delete this->m_actions;
}

// OFFSET: LEGO1 0x100ca5e0
undefined4 MxDSMultiAction::unk14()
{
  undefined4 result = MxDSAction::unk14();

  MxDSActionListCursor cursor(this->m_actions);
  MxDSAction *action;
  while (cursor.Next(action))
    result += action->unk14();

  return result;
}

// OFFSET: LEGO1 0x100ca6c0
MxU32 MxDSMultiAction::GetSizeOnDisk()
{
  MxU32 totalSizeOnDisk = MxDSAction::GetSizeOnDisk() + 16;

  MxDSActionListCursor cursor(this->m_actions);
  MxDSAction *action;
  while (cursor.Next(action))
    totalSizeOnDisk += action->GetSizeOnDisk();

  this->m_sizeOnDisk = totalSizeOnDisk - MxDSAction::GetSizeOnDisk();

  return totalSizeOnDisk;
}