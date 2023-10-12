#include "mxdsselectaction.h"
#include "mxvariabletable.h"
#include "mxtimer.h"
#include "mxomni.h"

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

// OFFSET: LEGO1 0x100cbe10
MxU32 MxDSSelectAction::GetSizeOnDisk()
{
  MxU32 totalSizeOnDisk = MxDSParallelAction::GetSizeOnDisk();

  totalSizeOnDisk += strlen(this->m_unk0x9c.GetData()) + 1;

  MxStringListCursor cursor(this->m_unk0xac);
  MxString string;
  while (cursor.Next(string))
    totalSizeOnDisk += strlen(string.GetData()) + 1;

  // Note: unlike the other classes, MxDSSelectAction does not have its own
  // sizeOnDisk member. Instead, it overrides the one from MxDSMultiAction.
  this->m_sizeOnDisk = totalSizeOnDisk;

  return totalSizeOnDisk;
}

// OFFSET: LEGO1 0x100cbf60
void MxDSSelectAction::Deserialize(char **p_source, MxS16 p_unk24)
{
  MxString string;
  MxDSAction::Deserialize(p_source, p_unk24);

  MxU32 extraFlag = *(MxU32*)(*p_source + 4) & 1;
  *p_source += 12;

  this->m_unk0x9c = *p_source;

  if (!strnicmp(this->m_unk0x9c.GetData(), "RANDOM_", strlen("RANDOM_"))) {
    char buffer[10];
    MxS16 value = atoi(&this->m_unk0x9c.GetData()[strlen("RANDOM_")]);

    srand(Timer()->GetTime());
    MxS32 random = rand() % value;
    string = itoa((MxS16) random, buffer, 10);
  }
  else
    string = VariableTable()->GetVariable(*p_source);

  *p_source += strlen(*p_source) + 1;

  MxU32 count = *(MxU32*) *p_source;
  *p_source += sizeof(MxU32);

  if (count) {
    MxS32 index = -1;
    this->m_unk0xac->DeleteAll();

    MxU32 i;
    for (i = 0; i < count; i++) {
      if (!strcmp(string.GetData(), *p_source))
        index = i;

      this->m_unk0xac->OtherAppend(*p_source);
      *p_source += strlen(*p_source) + 1;
    }

    for (i = 0; i < count; i++) {
      MxU32 extraFlag = *(MxU32*)(*p_source + 4) & 1;
      *p_source += 8;

      MxDSAction *action = (MxDSAction*) DeserializeDSObjectDispatch(p_source, p_unk24);

      if (index == i)
        this->m_actions->Append(action);
      else
        delete action;

      *p_source += extraFlag;
    }
  }

  *p_source += extraFlag;
}