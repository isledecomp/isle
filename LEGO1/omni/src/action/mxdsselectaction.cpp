#include "mxdsselectaction.h"

#include "mxmisc.h"
#include "mxtimer.h"
#include "mxvariabletable.h"

DECOMP_SIZE_ASSERT(MxDSSelectAction, 0xb0)
DECOMP_SIZE_ASSERT(MxStringList, 0x18)
DECOMP_SIZE_ASSERT(MxStringListCursor, 0x10)
DECOMP_SIZE_ASSERT(MxListEntry<MxString>, 0x18)

// FUNCTION: LEGO1 0x100cb2b0
// FUNCTION: BETA10 0x1015a515
MxDSSelectAction::MxDSSelectAction()
{
	m_type = e_selectAction;
	m_unk0xac = new MxStringList;
}

// FUNCTION: LEGO1 0x100cb8d0
// FUNCTION: BETA10 0x1015a5fd
MxDSSelectAction::~MxDSSelectAction()
{
	delete m_unk0xac;
}

// FUNCTION: LEGO1 0x100cb950
// FUNCTION: BETA10 0x1015a6ae
void MxDSSelectAction::CopyFrom(MxDSSelectAction& p_dsSelectAction)
{
	m_unk0x9c = p_dsSelectAction.m_unk0x9c;

	m_unk0xac->DeleteAll();

	MxStringListCursor cursor(p_dsSelectAction.m_unk0xac);
	MxString string;
	while (cursor.Next(string)) {
		m_unk0xac->Append(string);
	}
}

// FUNCTION: BETA10 0x1015a7ad
MxDSSelectAction::MxDSSelectAction(MxDSSelectAction& p_dsSelectAction) : MxDSParallelAction(p_dsSelectAction)
{
	CopyFrom(p_dsSelectAction);
}

// FUNCTION: LEGO1 0x100cbd50
// FUNCTION: BETA10 0x1015a84f
MxDSSelectAction& MxDSSelectAction::operator=(MxDSSelectAction& p_dsSelectAction)
{
	if (this != &p_dsSelectAction) {
		MxDSParallelAction::operator=(p_dsSelectAction);
		CopyFrom(p_dsSelectAction);
	}
	return *this;
}

// FUNCTION: LEGO1 0x100cbd80
// FUNCTION: BETA10 0x1015a88e
MxDSAction* MxDSSelectAction::Clone()
{
	MxDSSelectAction* clone = new MxDSSelectAction();

	if (clone) {
		*clone = *this;
	}

	return clone;
}

// FUNCTION: LEGO1 0x100cbe10
// FUNCTION: BETA10 0x1015a938
MxU32 MxDSSelectAction::GetSizeOnDisk()
{
	MxU32 totalSizeOnDisk = MxDSParallelAction::GetSizeOnDisk();

	totalSizeOnDisk += strlen(m_unk0x9c.GetData()) + 1;

	MxStringListCursor cursor(m_unk0xac);
	MxString string;
	while (cursor.Next(string)) {
		totalSizeOnDisk += strlen(string.GetData()) + 1;
	}

	// Note: unlike the other classes, MxDSSelectAction does not have its own
	// sizeOnDisk member. Instead, it overrides the one from MxDSMultiAction.
	m_sizeOnDisk = totalSizeOnDisk;

	return totalSizeOnDisk;
}

// FUNCTION: LEGO1 0x100cbf60
// FUNCTION: BETA10 0x1015aa30
void MxDSSelectAction::Deserialize(MxU8*& p_source, MxS16 p_unk0x24)
{
	MxDSAction* action = NULL;
	MxString string;
	MxDSAction::Deserialize(p_source, p_unk0x24);

	MxU32 extraFlag = *(MxU32*) (p_source + 4) & 1;
	p_source += 12;

	m_unk0x9c = (char*) p_source;

	if (strnicmp(m_unk0x9c.GetData(), "RANDOM_", strlen("RANDOM_")) != 0) {
		string = VariableTable()->GetVariable((char*) p_source);
	}
	else {
		char buffer[10];
		MxS16 value = atoi(&m_unk0x9c.GetData()[strlen("RANDOM_")]);

		srand(Timer()->GetTime());
		MxS32 random = rand() % value;
		string = itoa((MxS16) random, buffer, 10);
	}

	p_source += strlen((char*) p_source) + 1;

	MxU32 count = *(MxU32*) p_source;
	p_source += sizeof(MxU32);

	if (count) {
		MxS32 index = -1;
		m_unk0xac->DeleteAll();

		MxU32 i;
		for (i = 0; i < count; i++) {
			if (!strcmp(string.GetData(), (char*) p_source)) {
				index = i;
			}

			m_unk0xac->Append((char*) p_source);
			p_source += strlen((char*) p_source) + 1;
		}

		for (i = 0; i < count; i++) {
			MxU32 extraFlag = *(MxU32*) (p_source + 4) & 1;
			p_source += 8;

			action = (MxDSAction*) DeserializeDSObjectDispatch(p_source, p_unk0x24);

			if (index == i) {
				m_actionList->Append(action);
			}
			else {
				delete action;
			}

			p_source += extraFlag;
		}
	}

	p_source += extraFlag;
}
