#include "mxdsobject.h"

#include "mxdsaction.h"
#include "mxdsanim.h"
#include "mxdsevent.h"
#include "mxdsmediaaction.h"
#include "mxdsmultiaction.h"
#include "mxdsobjectaction.h"
#include "mxdsparallelaction.h"
#include "mxdsselectaction.h"
#include "mxdsserialaction.h"
#include "mxdssound.h"
#include "mxdsstill.h"
#include "mxutilities.h"

#include <stdlib.h>
#include <string.h>

DECOMP_SIZE_ASSERT(MxDSObject, 0x2c);

// FUNCTION: LEGO1 0x100bf6a0
MxDSObject::MxDSObject()
{
	this->SetType(e_object);
	this->m_sourceName = NULL;
	this->m_unk0x14 = 0;
	this->m_objectName = NULL;
	this->m_unk0x24 = -1;
	this->m_objectId = -1;
	this->m_unk0x28 = 0;
}

// FUNCTION: LEGO1 0x100bf7e0
MxDSObject::~MxDSObject()
{
	delete[] m_objectName;
	delete[] m_sourceName;
}

// FUNCTION: LEGO1 0x100bf870
void MxDSObject::CopyFrom(MxDSObject& p_dsObject)
{
	this->SetSourceName(p_dsObject.m_sourceName);
	this->m_unk0x14 = p_dsObject.m_unk0x14;
	this->SetObjectName(p_dsObject.m_objectName);
	this->m_objectId = p_dsObject.m_objectId;
	this->m_unk0x24 = p_dsObject.m_unk0x24;
	this->m_atomId = p_dsObject.m_atomId;
	this->m_unk0x28 = p_dsObject.m_unk0x28;
}

// FUNCTION: LEGO1 0x100bf8c0
MxDSObject& MxDSObject::operator=(MxDSObject& p_dsObject)
{
	if (this == &p_dsObject) {
		return *this;
	}

	this->CopyFrom(p_dsObject);
	return *this;
}

// FUNCTION: LEGO1 0x100bf8e0
void MxDSObject::SetObjectName(const char* p_objectName)
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

// FUNCTION: LEGO1 0x100bf950
void MxDSObject::SetSourceName(const char* p_sourceName)
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

// FUNCTION: LEGO1 0x100bf9c0
undefined4 MxDSObject::VTable0x14()
{
	return 10;
}

// FUNCTION: LEGO1 0x100bf9d0
MxU32 MxDSObject::GetSizeOnDisk()
{
	MxU32 sizeOnDisk;

	if (this->m_sourceName) {
		sizeOnDisk = strlen(this->m_sourceName) + 3;
	}
	else {
		sizeOnDisk = 3;
	}

	sizeOnDisk += 4;

	if (this->m_objectName) {
		sizeOnDisk += strlen(this->m_objectName) + 1;
	}
	else {
		sizeOnDisk++;
	}

	sizeOnDisk += 4;
	this->m_sizeOnDisk = sizeOnDisk;
	return sizeOnDisk;
}

// FUNCTION: LEGO1 0x100bfa20
void MxDSObject::Deserialize(MxU8*& p_source, MxS16 p_unk0x24)
{
	GetString(p_source, this->m_sourceName, this, &MxDSObject::SetSourceName);
	GetScalar(p_source, this->m_unk0x14);
	GetString(p_source, this->m_objectName, this, &MxDSObject::SetObjectName);
	GetScalar(p_source, this->m_objectId);

	this->m_unk0x24 = p_unk0x24;
}

// FUNCTION: LEGO1 0x100bfb30
MxDSObject* DeserializeDSObjectDispatch(MxU8*& p_source, MxS16 p_flags)
{
	MxU16 type = *(MxU16*) p_source;
	p_source += 2;

	MxDSObject* obj = NULL;

	switch (type) {
	default:
		return NULL;
	case MxDSObject::e_object:
		obj = new MxDSObject();
		break;
	case MxDSObject::e_action:
		obj = new MxDSAction();
		break;
	case MxDSObject::e_mediaAction:
		obj = new MxDSMediaAction();
		break;
	case MxDSObject::e_anim:
		obj = new MxDSAnim();
		break;
	case MxDSObject::e_sound:
		obj = new MxDSSound();
		break;
	case MxDSObject::e_multiAction:
		obj = new MxDSMultiAction();
		break;
	case MxDSObject::e_serialAction:
		obj = new MxDSSerialAction();
		break;
	case MxDSObject::e_parallelAction:
		obj = new MxDSParallelAction();
		break;
	case MxDSObject::e_event:
		obj = new MxDSEvent();
		break;
	case MxDSObject::e_selectAction:
		obj = new MxDSSelectAction();
		break;
	case MxDSObject::e_still:
		obj = new MxDSStill();
		break;
	case MxDSObject::e_objectAction:
		obj = new MxDSObjectAction();
		break;
	}

	if (obj) {
		obj->Deserialize(p_source, p_flags);
	}

	return obj;
}
