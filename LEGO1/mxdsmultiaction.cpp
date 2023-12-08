#include "mxdsmultiaction.h"

DECOMP_SIZE_ASSERT(MxDSMultiAction, 0x9c)

// TODO: Should be moved later
// SYNTHETIC: LEGO1 0x1004ad10
// MxDSActionListCursor::`scalar deleting destructor'

// TEMPLATE: LEGO1 0x1004ad80
// MxListCursor<MxDSAction *>::~MxListCursor<MxDSAction *>

// SYNTHETIC: LEGO1 0x1004add0
// MxListCursor<MxDSAction *>::`scalar deleting destructor'

// FUNCTION: LEGO1 0x1004ae40
// MxDSActionListCursor::~MxDSActionListCursor

// FUNCTION: LEGO1 0x100c9b90
MxDSMultiAction::MxDSMultiAction()
{
	this->SetType(MxDSType_MultiAction);
	this->m_actions = new MxDSActionList;
	this->m_actions->SetDestroy(MxDSActionList::Destroy);
}

// FUNCTION: LEGO1 0x100ca060
MxDSMultiAction::~MxDSMultiAction()
{
	if (this->m_actions)
		delete this->m_actions;
}

// FUNCTION: LEGO1 0x100ca0d0
void MxDSMultiAction::CopyFrom(MxDSMultiAction& p_dsMultiAction)
{
	this->m_actions->DeleteAll();

	MxDSActionListCursor cursor(p_dsMultiAction.m_actions);
	MxDSAction* action;
	while (cursor.Next(action))
		this->m_actions->Append(action->Clone());
}

// FUNCTION: LEGO1 0x100ca260
MxDSMultiAction& MxDSMultiAction::operator=(MxDSMultiAction& p_dsMultiAction)
{
	if (this == &p_dsMultiAction)
		return *this;

	MxDSAction::operator=(p_dsMultiAction);
	this->CopyFrom(p_dsMultiAction);
	return *this;
}

// FUNCTION: LEGO1 0x100ca290
void MxDSMultiAction::SetUnkTimingField(MxLong p_unkTimingField)
{
	this->m_unkTimingField = p_unkTimingField;

	MxDSActionListCursor cursor(this->m_actions);
	MxDSAction* action;
	while (cursor.Next(action))
		action->SetUnkTimingField(p_unkTimingField);
}

// FUNCTION: LEGO1 0x100ca370
void MxDSMultiAction::MergeFrom(MxDSAction& p_dsMultiAction)
{
	MxDSAction::MergeFrom(p_dsMultiAction);

	MxDSActionListCursor cursor(this->m_actions);
	MxDSAction* action;
	while (cursor.Next(action))
		action->MergeFrom(p_dsMultiAction);
}

// FUNCTION: LEGO1 0x100ca450
MxBool MxDSMultiAction::HasId(MxU32 p_objectId)
{
	if (this->GetObjectId() == p_objectId)
		return TRUE;

	MxDSActionListCursor cursor(this->m_actions);
	MxDSAction* action;
	while (cursor.Next(action)) {
		if (action->HasId(p_objectId))
			return TRUE;
	}

	return FALSE;
}

// FUNCTION: LEGO1 0x100ca550
MxDSAction* MxDSMultiAction::Clone()
{
	MxDSMultiAction* clone = new MxDSMultiAction();

	if (clone)
		*clone = *this;

	return clone;
}

// FUNCTION: LEGO1 0x100ca5e0
undefined4 MxDSMultiAction::unk14()
{
	undefined4 result = MxDSAction::unk14();

	MxDSActionListCursor cursor(this->m_actions);
	MxDSAction* action;
	while (cursor.Next(action))
		result += action->unk14();

	return result;
}

// FUNCTION: LEGO1 0x100ca6c0
MxU32 MxDSMultiAction::GetSizeOnDisk()
{
	MxU32 totalSizeOnDisk = MxDSAction::GetSizeOnDisk() + 16;

	MxDSActionListCursor cursor(this->m_actions);
	MxDSAction* action;
	while (cursor.Next(action))
		totalSizeOnDisk += action->GetSizeOnDisk();

	this->m_sizeOnDisk = totalSizeOnDisk - MxDSAction::GetSizeOnDisk();

	return totalSizeOnDisk;
}

// FUNCTION: LEGO1 0x100ca7b0
void MxDSMultiAction::Deserialize(char** p_source, MxS16 p_unk24)
{
	MxDSAction::Deserialize(p_source, p_unk24);

	MxU32 extraFlag = *(MxU32*) (*p_source + 4) & 1;
	*p_source += 12;

	MxU32 count = *(MxU32*) *p_source;
	*p_source += sizeof(count);

	if (count) {
		while (count--) {
			MxU32 extraFlag = *(MxU32*) (*p_source + 4) & 1;
			*p_source += 8;

			MxDSAction* action = (MxDSAction*) DeserializeDSObjectDispatch(p_source, p_unk24);
			*p_source += extraFlag;

			this->m_actions->Append(action);
		}
	}

	*p_source += extraFlag;
}

// FUNCTION: LEGO1 0x100ca8c0
void MxDSMultiAction::SetAtomId(MxAtomId p_atomId)
{
	MxDSAction::SetAtomId(p_atomId);

	MxDSActionListCursor cursor(this->m_actions);
	MxDSAction* action;
	while (cursor.Next(action))
		action->SetAtomId(p_atomId);
}
