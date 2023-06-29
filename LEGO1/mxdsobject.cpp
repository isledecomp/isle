#include "mxdsobject.h"

#include <string.h>
#include <stdlib.h>

// OFFSET: LEGO1 0x100bf6a0
MxDSObject::MxDSObject()
{
  this->m_unk0c = 0;
  this->m_unk10 = 0;
  this->m_unk14 = 0;
  this->m_name = NULL;
  this->m_unk24 = -1;
  this->m_unk1c = -1;
  this->m_unk28 = 0;
}

// OFFSET: LEGO1 0x100bf7e0
MxDSObject::~MxDSObject()
{
  // TODO
}

// OFFSET: LEGO1 0x100bf8e0
void MxDSObject::SetObjectName(const char *p_name)
{
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
