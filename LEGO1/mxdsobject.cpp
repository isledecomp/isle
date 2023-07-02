#include "mxdsobject.h"

#include <string.h>
#include <stdlib.h>

// OFFSET: LEGO1 0x100bf6a0
MxDSObject::MxDSObject()
{
  this->m_unk0c = 0;
  this->m_sourceName = NULL;
  this->m_unk14 = 0;
  this->m_objectName = NULL;
  this->m_unk24 = -1;
  this->m_unk1c = -1;
  this->m_unk28 = 0;
}

// OFFSET: LEGO1 0x100bf7e0
MxDSObject::~MxDSObject()
{
  delete[] m_objectName;
  delete[] m_sourceName;
}

// OFFSET: LEGO1 0x100bf870
void MxDSObject::CopyFrom(MxDSObject &p_dsObject)
{
  this->SetSourceName(p_dsObject.m_sourceName);
  this->m_unk14 = p_dsObject.m_unk14;
  this->SetObjectName(p_dsObject.m_objectName);
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
void MxDSObject::SetObjectName(const char *p_objectName)
{
  if (p_objectName != this->m_objectName) {
    delete[] this->m_objectName;

    if (p_objectName) {
      this->m_objectName = new char[strlen(p_objectName) + 1];

      if (this->m_objectName) {
        strcpy(this->m_objectName, p_objectName);
      }
    }
    else {
      this->m_objectName = NULL;
    }
  }
}

// OFFSET: LEGO1 0x100bf950
void MxDSObject::SetSourceName(const char *p_sourceName)
{
  if (p_sourceName != this->m_sourceName) {
    delete[] this->m_sourceName;

    if (p_sourceName) {
      this->m_sourceName = new char[strlen(p_sourceName) + 1];

      if (this->m_sourceName) {
        strcpy(this->m_sourceName, p_sourceName);
      }
    }
    else {
      this->m_sourceName = NULL;
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

  if (this->m_sourceName)
    unk08 = strlen(this->m_sourceName) + 3;
  else
    unk08 = 3;

  unk08 += 4;

  if (this->m_objectName)
    unk08 += strlen(this->m_objectName) + 1;
  else
    unk08++;

  unk08 += 4;
  this->m_unk08 = unk08;
  return unk08;
}

// OFFSET: LEGO1 0x100bfa20
void MxDSObject::Parse(char **p_source, MxU16 p_unk24)
{
  this->SetSourceName(*p_source);
  *p_source += strlen(this->m_sourceName) + 1;
  this->m_unk14 = *(int*) *p_source;
  *p_source += 4;

  this->SetObjectName(*p_source);
  *p_source += strlen(this->m_objectName) + 1;
  this->m_unk1c = *(int*) *p_source;
  *p_source += 4;

  this->m_unk24 = p_unk24;
}
