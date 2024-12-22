#include "mxdsobject.h"

#include "mxdsaction.h"
#include "mxdsanim.h"
#include "mxdsevent.h"
#include "mxdsfile.h"
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

DECOMP_SIZE_ASSERT(MxDSObject, 0x2c)
DECOMP_SIZE_ASSERT(MxDSObjectList, 0x0c)

// FUNCTION: LEGO1 0x100bf6a0
// FUNCTION: BETA10 0x101478c0
MxDSObject::MxDSObject()
{
	m_type = e_object;
	m_sourceName = NULL;
	m_unk0x14 = 0;
	m_objectName = NULL;
	m_objectId = -1;
	m_unk0x24 = -1;
	m_unk0x28 = NULL;
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
	SetSourceName(p_dsObject.m_sourceName);
	m_unk0x14 = p_dsObject.m_unk0x14;
	SetObjectName(p_dsObject.m_objectName);
	m_objectId = p_dsObject.m_objectId;
	m_unk0x24 = p_dsObject.m_unk0x24;
	m_atomId = p_dsObject.m_atomId;
	m_unk0x28 = p_dsObject.m_unk0x28;
}

// FUNCTION: BETA10 0x10147abf
MxDSObject::MxDSObject(MxDSObject& p_dsObject)
{
	CopyFrom(p_dsObject);
}

// FUNCTION: LEGO1 0x100bf8c0
// FUNCTION: BETA10 0x10147b57
MxDSObject& MxDSObject::operator=(MxDSObject& p_dsObject)
{
	if (this == &p_dsObject) {
		return *this;
	}

	CopyFrom(p_dsObject);
	return *this;
}

// FUNCTION: LEGO1 0x100bf8e0
// FUNCTION: BETA10 0x10147b92
void MxDSObject::SetObjectName(const char* p_objectName)
{
	if (p_objectName == m_objectName) {
		return;
	}

	delete[] m_objectName;

	if (p_objectName) {
		m_objectName = new char[strlen(p_objectName) + 1];

		if (m_objectName) {
			strcpy(m_objectName, p_objectName);
		}
	}
	else {
		m_objectName = NULL;
	}
}

// FUNCTION: LEGO1 0x100bf950
// FUNCTION: BETA10 0x10147c2e
void MxDSObject::SetSourceName(const char* p_sourceName)
{
	if (p_sourceName == m_sourceName) {
		return;
	}

	delete[] m_sourceName;

	if (p_sourceName) {
		m_sourceName = new char[strlen(p_sourceName) + 1];

		if (m_sourceName) {
			strcpy(m_sourceName, p_sourceName);
		}
	}
	else {
		m_sourceName = NULL;
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

	if (m_sourceName) {
		sizeOnDisk += strlen(m_sourceName) + 1;
	}
	else {
		sizeOnDisk++;
	}

	sizeOnDisk += sizeof(m_unk0x14);

	if (m_objectName) {
		sizeOnDisk += strlen(m_objectName) + 1;
	}
	else {
		sizeOnDisk++;
	}

	sizeOnDisk += sizeof(m_objectId);

	m_sizeOnDisk = sizeOnDisk;
	return sizeOnDisk;
}

// FUNCTION: LEGO1 0x100bfa20
// FUNCTION: BETA10 0x10147d73
void MxDSObject::Deserialize(MxU8*& p_source, MxS16 p_unk0x24)
{
	SetSourceName((char*) p_source);
	p_source += strlen(m_sourceName) + 1;

	m_unk0x14 = *(undefined4*) p_source;
	p_source += sizeof(m_unk0x14);

	SetObjectName((char*) p_source);
	p_source += strlen(m_objectName) + 1;

	m_objectId = *(MxU32*) p_source;
	p_source += sizeof(m_objectId);

	m_unk0x24 = p_unk0x24;
}

// FUNCTION: LEGO1 0x100bfa80
// FUNCTION: BETA10 0x10147e02
MxDSObject* MxDSObjectList::FindInternal(MxDSObject* p_action, MxBool p_delete)
{
	// DECOMP ALPHA 0x1008b99d ?

	MxDSObject* found = NULL;

#ifdef COMPAT_MODE
	iterator it;
	for (it = begin(); it != end(); it++) {
#else
	for (iterator it = begin(); it != end(); it++) {
#endif
		if (p_action->GetObjectId() == -1 || p_action->GetObjectId() == (*it)->GetObjectId()) {
			if (p_action->GetUnknown24() == -2 || p_action->GetUnknown24() == -3 ||
				p_action->GetUnknown24() == (*it)->GetUnknown24()) {
				found = *it;
				if (p_action->GetUnknown24() != -3) {
					break;
				}
			}
		}
	}

	if (p_delete && found != NULL) {
		erase(it);
	}

	return found;
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

// FUNCTION: LEGO1 0x100c0280
MxDSObject* CreateStreamObject(MxDSFile* p_file, MxS16 p_ofs)
{
	MxU8* buf;
	_MMCKINFO tmpChunk;

	if (p_file->Seek(((MxLong*) p_file->GetBuffer())[p_ofs], SEEK_SET)) {
		return NULL;
	}

	if (p_file->Read((MxU8*) &tmpChunk.ckid, 8) == 0 && tmpChunk.ckid == FOURCC('M', 'x', 'S', 't')) {
		if (p_file->Read((MxU8*) &tmpChunk.ckid, 8) == 0 && tmpChunk.ckid == FOURCC('M', 'x', 'O', 'b')) {

			buf = new MxU8[tmpChunk.cksize];
			if (!buf) {
				return NULL;
			}

			if (p_file->Read(buf, tmpChunk.cksize) != 0) {
				return NULL;
			}

			// Save a copy so we can clean up properly, because
			// this function will alter the pointer value.
			MxU8* copy = buf;
			MxDSObject* obj = DeserializeDSObjectDispatch(buf, -1);
			delete[] copy;
			return obj;
		}

		return NULL;
	}

	return NULL;
}
