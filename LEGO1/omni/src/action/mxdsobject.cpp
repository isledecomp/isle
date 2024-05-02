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
// FUNCTION: BETA10 0x101478c0
MxDSObject::MxDSObject()
{
	this->m_type = e_object;
	this->m_sourceName = NULL;
	this->m_unk0x14 = 0;
	this->m_objectName = NULL;
	this->m_objectId = -1;
	this->m_unk0x24 = -1;
	this->m_unk0x28 = 0;
}

// FUNCTION: LEGO1 0x100bf7e0
// FUNCTION: BETA10 0x1014798e
MxDSObject::~MxDSObject()
{
	delete[] m_objectName;
	delete[] m_sourceName;
}

// FUNCTION: LEGO1 0x100bf870
// FUNCTION: BETA10 0x10147a45
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

// FUNCTION: BETA10 0x10147abf
MxDSObject::MxDSObject(MxDSObject& p_dsObject)
{
	this->CopyFrom(p_dsObject);
}

// FUNCTION: LEGO1 0x100bf8c0
// FUNCTION: BETA10 0x10147b57
MxDSObject& MxDSObject::operator=(MxDSObject& p_dsObject)
{
	if (this == &p_dsObject) {
		return *this;
	}

	this->CopyFrom(p_dsObject);
	return *this;
}

// FUNCTION: LEGO1 0x100bf8e0
// FUNCTION: BETA10 0x10147b92
void MxDSObject::SetObjectName(const char* p_objectName)
{
	if (p_objectName == this->m_objectName) {
		return;
	}

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

// FUNCTION: LEGO1 0x100bf950
// FUNCTION: BETA10 0x10147c2e
void MxDSObject::SetSourceName(const char* p_sourceName)
{
	if (p_sourceName == this->m_sourceName) {
		return;
	}

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

// FUNCTION: LEGO1 0x100bf9c0
// FUNCTION: BETA10 0x10147cca
undefined4 MxDSObject::VTable0x14()
{
	// DECOMP: Rendered as 8 + 2 in beta. Maybe a sizeof() call?
	return 10;
}

// FUNCTION: LEGO1 0x100bf9d0
// FUNCTION: BETA10 0x10147cee
MxU32 MxDSObject::GetSizeOnDisk()
{
	MxU32 sizeOnDisk = 0;

	sizeOnDisk += 2;

	if (this->m_sourceName) {
		sizeOnDisk += strlen(this->m_sourceName) + 1;
	}
	else {
		sizeOnDisk++;
	}

	sizeOnDisk += sizeof(this->m_unk0x14);

	if (this->m_objectName) {
		sizeOnDisk += strlen(this->m_objectName) + 1;
	}
	else {
		sizeOnDisk++;
	}

	sizeOnDisk += sizeof(this->m_objectId);

	this->m_sizeOnDisk = sizeOnDisk;
	return sizeOnDisk;
}

// FUNCTION: LEGO1 0x100bfa20
// FUNCTION: BETA10 0x10147d73
void MxDSObject::Deserialize(MxU8*& p_source, MxS16 p_unk0x24)
{
	this->SetSourceName((char*) p_source);
	p_source += strlen(this->m_sourceName) + 1;

	this->m_unk0x14 = *(MxU32*) p_source;
	p_source += sizeof(this->m_unk0x14);

	this->SetObjectName((char*) p_source);
	p_source += strlen(this->m_objectName) + 1;

	this->m_objectId = *(MxU32*) p_source;
	p_source += sizeof(this->m_objectId);

	this->m_unk0x24 = p_unk0x24;
}

// FUNCTION: LEGO1 0x100bfb30
// FUNCTION: BETA10 0x10147f35
MxDSObject* DeserializeDSObjectDispatch(MxU8*& p_source, MxS16 p_flags)
{
	MxDSObject* obj = NULL;

	MxU16 type = *(MxU16*) p_source;
	p_source += 2;

	switch (type) {
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
	case MxDSObject::e_event:
		obj = new MxDSEvent();
		break;
	case MxDSObject::e_still:
		obj = new MxDSStill();
		break;
	case MxDSObject::e_objectAction:
		obj = new MxDSObjectAction();
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
	case MxDSObject::e_selectAction:
		obj = new MxDSSelectAction();
		break;
	default:
		return NULL;
	}

	if (obj) {
		obj->Deserialize(p_source, p_flags);
	}

	return obj;
}
