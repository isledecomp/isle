#include "mxdsmultiaction.h"

#include <assert.h>

DECOMP_SIZE_ASSERT(MxDSMultiAction, 0x9c)
DECOMP_SIZE_ASSERT(MxDSActionList, 0x1c);
DECOMP_SIZE_ASSERT(MxDSActionListCursor, 0x10);

// FUNCTION: LEGO1 0x100c9b90
// FUNCTION: BETA10 0x10159410
MxDSMultiAction::MxDSMultiAction()
{
	m_type = e_multiAction;
	m_actionList = new MxDSActionList;
	assert(m_actionList);
	m_actionList->SetDestroy(MxDSActionList::Destroy);
}

// FUNCTION: LEGO1 0x100ca060
// FUNCTION: BETA10 0x10159518
MxDSMultiAction::~MxDSMultiAction()
{
	delete m_actionList;
}

// FUNCTION: LEGO1 0x100ca0d0
// FUNCTION: BETA10 0x101595ad
void MxDSMultiAction::CopyFrom(MxDSMultiAction& p_dsMultiAction)
{
	m_actionList->DeleteAll();

	MxDSActionListCursor cursor(p_dsMultiAction.m_actionList);
	MxDSAction* action;
	while (cursor.Next(action)) {
		m_actionList->Append(action->Clone());
	}
}

// FUNCTION: BETA10 0x10159660
MxDSMultiAction::MxDSMultiAction(MxDSMultiAction& p_dsMultiAction) : MxDSAction(p_dsMultiAction)
{
	CopyFrom(p_dsMultiAction);
}

// FUNCTION: LEGO1 0x100ca260
// FUNCTION: BETA10 0x101596e1
MxDSMultiAction& MxDSMultiAction::operator=(MxDSMultiAction& p_dsMultiAction)
{
	if (this == &p_dsMultiAction) {
		return *this;
	}

	MxDSAction::operator=(p_dsMultiAction);
	CopyFrom(p_dsMultiAction);
	return *this;
}

// FUNCTION: LEGO1 0x100ca290
// FUNCTION: BETA10 0x10159728
void MxDSMultiAction::SetUnknown90(MxLong p_unk0x90)
{
	m_unk0x90 = p_unk0x90;

	MxDSActionListCursor cursor(m_actionList);
	MxDSAction* action;
	while (cursor.Next(action)) {
		action->SetUnknown90(p_unk0x90);
	}
}

// FUNCTION: LEGO1 0x100ca370
// FUNCTION: BETA10 0x101597ce
void MxDSMultiAction::MergeFrom(MxDSAction& p_dsMultiAction)
{
	MxDSAction::MergeFrom(p_dsMultiAction);

	MxDSActionListCursor cursor(m_actionList);
	MxDSAction* action;
	while (cursor.Next(action)) {
		action->MergeFrom(p_dsMultiAction);
	}
}

// FUNCTION: LEGO1 0x100ca450
// FUNCTION: BETA10 0x10159874
MxBool MxDSMultiAction::HasId(MxU32 p_objectId)
{
	if (GetObjectId() == p_objectId) {
		return TRUE;
	}

	MxDSActionListCursor cursor(m_actionList);
	MxDSAction* action;
	while (cursor.Next(action)) {
		if (action->HasId(p_objectId)) {
			return TRUE;
		}
	}

	return FALSE;
}

// FUNCTION: LEGO1 0x100ca550
// FUNCTION: BETA10 0x10159959
MxDSAction* MxDSMultiAction::Clone()
{
	MxDSMultiAction* clone = new MxDSMultiAction();

	if (clone) {
		*clone = *this;
	}

	return clone;
}

// FUNCTION: LEGO1 0x100ca5e0
// FUNCTION: BETA10 0x10159a03
undefined4 MxDSMultiAction::VTable0x14()
{
	undefined4 result = MxDSAction::VTable0x14();

	MxDSActionListCursor cursor(m_actionList);
	MxDSAction* action;
	while (cursor.Next(action)) {
		result += action->VTable0x14();
	}

	return result;
}

// FUNCTION: LEGO1 0x100ca6c0
// FUNCTION: BETA10 0x10159aaf
MxU32 MxDSMultiAction::GetSizeOnDisk()
{
	MxU32 totalSizeOnDisk = MxDSAction::GetSizeOnDisk();
	totalSizeOnDisk += 12;
	totalSizeOnDisk += 4;

	MxDSActionListCursor cursor(m_actionList);
	MxDSAction* action;
	while (cursor.Next(action)) {
		totalSizeOnDisk += action->GetSizeOnDisk();
	}

	m_sizeOnDisk = totalSizeOnDisk - MxDSAction::GetSizeOnDisk();

	return totalSizeOnDisk;
}

// FUNCTION: LEGO1 0x100ca7b0
// FUNCTION: BETA10 0x10159b79
void MxDSMultiAction::Deserialize(MxU8*& p_source, MxS16 p_unk0x24)
{
	MxDSAction::Deserialize(p_source, p_unk0x24);

	MxU32 extraFlag = *(MxU32*) (p_source + 4) & 1;
	p_source += 12;

	MxU32 count = *(MxU32*) p_source;
	p_source += sizeof(count);

	if (count) {
		while (count--) {
			MxU32 extraFlag = *(MxU32*) (p_source + 4) & 1;
			p_source += 8;

			MxDSAction* action = (MxDSAction*) DeserializeDSObjectDispatch(p_source, p_unk0x24);
			p_source += extraFlag;

			m_actionList->Append(action);
		}
	}

	p_source += extraFlag;
}

// FUNCTION: LEGO1 0x100ca8c0
// FUNCTION: BETA10 0x10159c37
void MxDSMultiAction::SetAtomId(MxAtomId p_atomId)
{
	MxDSAction::SetAtomId(p_atomId);

	MxDSActionListCursor cursor(m_actionList);
	MxDSAction* action;
	while (cursor.Next(action)) {
		action->SetAtomId(p_atomId);
	}
}
