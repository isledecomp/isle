#include "mxdsobject.h"

#include <string.h>
#include <stdlib.h>

// OFFSET: LEGO1 0x100bf6a0
MxDSObject::MxDSObject()
{
  this->m_unk0c = 0;
  this->m_unk10 = NULL;
  this->m_unk14 = 0;
  this->m_name = NULL;
  this->m_unk24 = -1;
  this->m_unk1c = -1;
  this->m_unk28 = 0;
}

// OFFSET: LEGO1 0x100bf7e0
MxDSObject::~MxDSObject()
{
  delete[] m_name;
  delete[] m_unk10;
}

// OFFSET: LEGO1 0x100bf870
void MxDSObject::CopyFrom(MxDSObject &p_dsObject)
{
  this->SetUnknown10(p_dsObject.m_unk10);
  this->m_unk14 = p_dsObject.m_unk14;
  this->SetObjectName(p_dsObject.m_name);
  this->m_unk1c = p_dsObject.m_unk1c;
  this->m_unk24 = p_dsObject.m_unk24;
  this->m_atomId = p_dsObject.m_atomId;
  this->m_unk28 = p_dsObject.m_unk28;
}

// OFFSET: LEGO1 0x100bf8c0
MxDSObject &MxDSObject::operator=(MxDSObject &p_dsObject)
{
  if (this == &p_dsObject)
    return *this;

  this->CopyFrom(p_dsObject);
  return *this;
}

// OFFSET: LEGO1 0x100bf8e0
void MxDSObject::SetObjectName(const char *p_name)
{
  if (p_name != this->m_name)
  {
    delete[] this->m_name;

    if (p_name) {
      this->m_name = new char[strlen(p_name) + 1];

      if (this->m_name) {
        strcpy(this->m_name, p_name);
      }
    }
    else {
      this->m_name = NULL;
    }
  }
}

// OFFSET: LEGO1 0x100bf950
void MxDSObject::SetUnknown10(const char *p_unk10)
{
  if (p_unk10 != this->m_unk10)
  {
    delete[] this->m_unk10;

    if (p_unk10) {
      this->m_unk10 = new char[strlen(p_unk10) + 1];

      if (this->m_unk10) {
        strcpy(this->m_unk10, p_unk10);
      }
    }
    else {
      this->m_unk10 = NULL;
    }
  }
}

// OFFSET: LEGO1 0x100bf9c0
int MxDSObject::unk14()
{
  return 10;
}

// OFFSET: LEGO1 0x100bf9d0
unsigned int MxDSObject::CalculateUnk08()
{
  unsigned int unk08;

  if (this->m_unk10)
    unk08 = strlen(this->m_unk10) + 3;
  else
    unk08 = 3;

  unk08 += 4;

  if (this->m_name)
    unk08 += strlen(this->m_name) + 1;
  else
    unk08++;

  unk08 += 4;
  this->m_unk08 = unk08;
  return unk08;
}

// OFFSET: LEGO1 0x100bfa20
void MxDSObject::Parse(char **p_source, unsigned short p_unk24)
{
  this->SetUnknown10(*p_source);
  *p_source += strlen(this->m_unk10) + 1;
  this->m_unk14 = *(int*) *p_source;
  *p_source += 4;

  this->SetObjectName(*p_source);
  *p_source += strlen(this->m_name) + 1;
  this->m_unk1c = *(int*) *p_source;
  *p_source += 4;

  this->m_unk24 = p_unk24;
}