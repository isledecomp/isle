#include "mxdsobject.h"

#include <string.h>
#include <stdlib.h>

// OFFSET: LEGO1 0x100bf6a0
MxDSObject::MxDSObject()
{
  // The following code yields 100% matching assembly if m_unk24 is declared as (signed) short.
  // However, in other areas m_unk24 (notably, ISLE.EXE) is treated as unsigned short.
  // this->m_unk0c = 0;
  // this->m_unk10 = 0;
  // this->m_unk14 = 0;
  // this->m_name = NULL;
  // this->m_unk24 = -1;
  // this->m_unk1c = -1;
  // this->m_unk28 = 0;

  // Assembly not matching but m_unk24 is unsigned short (probably correct)
  this->m_unk0c = 0;
  this->m_unk10 = 0;
  this->m_unk14 = 0;
  this->m_name = NULL;
  this->m_unk24 = 0xFFFF;
  this->m_unk1c = -1;
  this->m_unk28 = 0;
}

// OFFSET: LEGO1 0x100bf8e0
void MxDSObject::SetObjectName(const char *p_name)
{
  // TODO: instead of the expected CMP EAX,ESI we get CMP ESI,EAX
  if (p_name != this->m_name)
  {
    free(this->m_name);

    if (p_name) {
      this->m_name = (char *)malloc(strlen(p_name) + 1);

      if (this->m_name) {
        strcpy(this->m_name, p_name);
      }
    }
    else {
      this->m_name = NULL;
    }
  }
}

// OFFSET: LEGO1 0x10005530
// OFFSET: ISLE 0x00401c40
void MxDSObject::SetAtomId(MxAtomId p_atomId)
{
  this->m_atomId = p_atomId;
}
