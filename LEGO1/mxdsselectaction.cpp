#include "mxdsselectaction.h"

DECOMP_SIZE_ASSERT(MxDSSelectAction, 0xb0)

// OFFSET: LEGO1 0x100cb2b0
MxDSSelectAction::MxDSSelectAction()
{
  this->SetType(MxDSType_SelectAction);
  this->m_unk0xac = new MxStringList;
}

// OFFSET: LEGO1 0x100cb8d0
MxDSSelectAction::~MxDSSelectAction()
{
  if (this->m_unk0xac)
    delete this->m_unk0xac;
}

// OFFSET: LEGO1 0x100cb950
void MxDSSelectAction::CopyFrom(MxDSSelectAction &p_dsSelectAction)
{
  this->m_unk0x9c = p_dsSelectAction.m_unk0x9c;

  this->m_unk0xac->DeleteAll();

  MxStringListCursor cursor(p_dsSelectAction.m_unk0xac);
  MxString string;
  while (cursor.Next(string))
    this->m_unk0xac->OtherAppend(string);
}

// OFFSET: LEGO1 0x100cbd50
MxDSSelectAction &MxDSSelectAction::operator=(MxDSSelectAction &p_dsSelectAction)
{
  if (this != &p_dsSelectAction) {
    MxDSParallelAction::operator=(p_dsSelectAction);
    this->CopyFrom(p_dsSelectAction);
  }
  return *this;
}

// OFFSET: LEGO1 0x100cbd80
MxDSAction *MxDSSelectAction::Clone()
{
  MxDSSelectAction *clone = new MxDSSelectAction();

  if (clone)
    *clone = *this;

  return clone;
}