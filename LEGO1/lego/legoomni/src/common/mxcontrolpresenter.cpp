#include "mxcontrolpresenter.h"

#include "define.h"
#include "legocontrolmanager.h"
#include "mxdsmultiaction.h"
#include "mxmisc.h"
#include "mxticklemanager.h"
#include "mxtimer.h"
#include "mxutilities.h"
#include "mxvideopresenter.h"

DECOMP_SIZE_ASSERT(MxControlPresenter, 0x5c)

// GLOBAL: LEGO1 0x10102064
// STRING: LEGO1 0x10101fec
const char* g_style = "STYLE";

// GLOBAL: LEGO1 0x10102068
// STRING: LEGO1 0x10101fe4
const char* g_grid = "GRID";

// GLOBAL: LEGO1 0x1010206c
// STRING: LEGO1 0x10101fe0
const char* g_map = "MAP";

// GLOBAL: LEGO1 0x10102074
// STRING: LEGO1 0x10101fd0
const char* g_toggle = "TOGGLE";

// FUNCTION: LEGO1 0x10043f50
MxControlPresenter::MxControlPresenter()
{
	this->m_unk0x4c = 0;
	this->m_unk0x4e = -1;
	this->m_unk0x50 = FALSE;
	this->m_unk0x52 = 0;
	this->m_unk0x58 = 0;
	this->m_unk0x54 = 0;
}

// FUNCTION: LEGO1 0x10043fd0
void MxControlPresenter::RepeatingTickle()
{
	// empty
}

// FUNCTION: LEGO1 0x10043fe0
MxBool MxControlPresenter::VTable0x64(undefined4 p_undefined)
{
	return m_unk0x50;
}

// FUNCTION: LEGO1 0x10043ff0
void MxControlPresenter::VTable0x68(MxBool p_unk0x50)
{
	m_unk0x50 = p_unk0x50;
}

// FUNCTION: LEGO1 0x10044110
MxControlPresenter::~MxControlPresenter()
{
	if (m_unk0x58) {
		delete m_unk0x58;
	}
}

// FUNCTION: LEGO1 0x10044180
MxResult MxControlPresenter::AddToManager()
{
	m_unk0x4e = 0;
	return SUCCESS;
}

// FUNCTION: LEGO1 0x10044190
MxResult MxControlPresenter::StartAction(MxStreamController* p_controller, MxDSAction* p_action)
{
	MxResult result = MxCompositePresenter::StartAction(p_controller, p_action);

	FUN_100b7220(m_action, MxDSAction::c_world | MxDSAction::c_looping, TRUE);
	ParseExtra();

	MxS16 i = 0;
	for (MxCompositePresenterList::iterator it = m_list.begin(); it != m_list.end(); it++) {
		(*it)->Enable((m_unk0x4c != 3 || m_unk0x4e) && IsEnabled() ? m_unk0x4e == i : FALSE);
		i++;
	}

	if (m_unk0x4c == 3) {
		MxDSAction* action = (*m_list.begin())->GetAction();
		action->SetFlags(action->GetFlags() | MxDSAction::c_bit11);
	}

	TickleManager()->RegisterClient(this, 200);

	return result;
}

// FUNCTION: LEGO1 0x10044260
void MxControlPresenter::EndAction()
{
	if (m_action) {
		m_unk0x50 = TRUE;
		MxCompositePresenter::EndAction();
	}
}

// FUNCTION: LEGO1 0x10044270
MxBool MxControlPresenter::FUN_10044270(MxS32 p_x, MxS32 p_y, MxVideoPresenter* p_presenter)
{
	if (m_unk0x4c == 3) {
		MxVideoPresenter* frontPresenter = (MxVideoPresenter*) m_list.front();

		if (p_presenter == frontPresenter || frontPresenter->GetDisplayZ() < p_presenter->GetDisplayZ()) {
			if (p_presenter->VTable0x7c()) {
				MxS32 height = frontPresenter->GetHeight();
				MxS32 width = frontPresenter->GetWidth();

				if (frontPresenter->GetLocation().GetX() <= p_x &&
					p_x < width - 1 + frontPresenter->GetLocation().GetX() &&
					frontPresenter->GetLocation().GetY() <= p_y &&
					p_y < height - 1 + frontPresenter->GetLocation().GetY()) {
					MxU8* start;

					if (frontPresenter->GetAlphaMask() == NULL) {
						start = frontPresenter->GetBitmap()->GetStart(
							p_x - frontPresenter->GetLocation().GetX(),
							p_y - frontPresenter->GetLocation().GetY()
						);
					}
					else {
						start = NULL;
					}

					m_unk0x56 = 0;
					if (m_unk0x58 == NULL) {
						if (*start != 0) {
							m_unk0x56 = 1;
						}
					}
					else {
						for (MxS16 i = 1; i <= *m_unk0x58; i++) {
							if (m_unk0x58[i] == *start) {
								m_unk0x56 = i;
								break;
							}
						}
					}

					if (m_unk0x56) {
						return TRUE;
					}
				}
			}
		}
	}
	else {
		if (ContainsPresenter(m_list, p_presenter)) {
			if (m_unk0x4c == 2) {
				MxS32 width = p_presenter->GetWidth();
				MxS32 height = p_presenter->GetHeight();

				if (m_unk0x52 == 2 && m_unk0x54 == 2) {
					MxS16 val;
					if (p_x < p_presenter->GetLocation().GetX() + width / 2) {
						val = 3;
						if (p_y < p_presenter->GetLocation().GetY() + height / 2) {
							val = 1;
						}
						m_unk0x56 = val;
						return TRUE;
					}

					val = 4;
					if (p_y < p_presenter->GetLocation().GetY() + height / 2) {
						val = 2;
					}

					m_unk0x56 = val;
					return TRUE;
				}
			}
			else {
				m_unk0x56 = -1;
			}

			return TRUE;
		}
	}

	return FALSE;
}

// FUNCTION: LEGO1 0x10044480
MxBool MxControlPresenter::FUN_10044480(LegoControlManagerEvent* p_event, MxPresenter* p_presenter)
{
	if (IsEnabled()) {
		switch (p_event->GetType()) {
		case c_notificationButtonUp:
			if (m_unk0x4c == 0 || m_unk0x4c == 2 || m_unk0x4c == 3) {
				p_event->SetClickedObjectId(m_action->GetObjectId());
				p_event->SetClickedAtom(m_action->GetAtomId().GetInternal());
				VTable0x6c(0);
				p_event->SetType(c_notificationClick);
				p_event->SetUnknown0x28(m_unk0x4e);
				return TRUE;
			}
			break;
		case c_notificationButtonDown:
			if (FUN_10044270(p_event->GetX(), p_event->GetY(), (MxVideoPresenter*) p_presenter)) {
				p_event->SetClickedObjectId(m_action->GetObjectId());
				p_event->SetClickedAtom(m_action->GetAtomId().GetInternal());
				VTable0x6c(m_unk0x56);
				p_event->SetType(c_notificationClick);
				p_event->SetUnknown0x28(m_unk0x4e);
				return TRUE;
			}
			break;
		}
	}

	return FALSE;
}

// FUNCTION: LEGO1 0x10044540
void MxControlPresenter::VTable0x6c(MxS16 p_val)
{
	if (p_val == -1) {
		if ((MxS16) ((MxDSMultiAction*) m_action)->GetActionList()->GetCount() - m_unk0x4e == 1) {
			m_unk0x4e = 0;
		}
		else {
			m_unk0x4e++;
		}
	}
	else {
		m_unk0x4e = p_val;
	}

	m_action->SetUnknown90(Timer()->GetTime());

	MxS16 i = 0;
	for (MxCompositePresenterList::iterator it = m_list.begin(); it != m_list.end(); it++) {
		(*it)->Enable(((m_unk0x4c == 3 && m_unk0x4e == 0) || !IsEnabled()) ? FALSE : m_unk0x4e == i);
		i++;
	}
}

// FUNCTION: LEGO1 0x10044610
void MxControlPresenter::ReadyTickle()
{
	MxPresenter::ParseExtra();
	TickleManager()->UnregisterClient(this);
	ProgressTickleState(e_repeating);
}

// FUNCTION: LEGO1 0x10044640
void MxControlPresenter::ParseExtra()
{
	MxU16 extraLength;
	char* extraData;
	m_action->GetExtra(extraLength, extraData);

	if (extraLength & MAXWORD) {
		char extraCopy[256];
		memcpy(extraCopy, extraData, extraLength & MAXWORD);
		extraCopy[extraLength & MAXWORD] = '\0';

		char output[256];
		if (KeyValueStringParse(output, g_style, extraCopy)) {
			char* str = strtok(output, g_parseExtraTokens);

			if (!strcmpi(str, g_toggle)) {
				m_unk0x4c = 1;
			}
			else if (!strcmpi(str, g_grid)) {
				m_unk0x4c = 2;
				m_unk0x52 = atoi(strtok(NULL, g_parseExtraTokens));
				m_unk0x54 = atoi(strtok(NULL, g_parseExtraTokens));
			}
			else if (!strcmpi(str, g_map)) {
				m_unk0x4c = 3;
				str = strtok(NULL, g_parseExtraTokens);

				if (str) {
					MxS16 count = atoi(str);
					m_unk0x58 = new MxS16[count + 1];
					*m_unk0x58 = count;

					for (MxS16 i = 1; i <= count; i++) {
						m_unk0x58[i] = atoi(strtok(NULL, g_parseExtraTokens));
					}
				}
			}
			else {
				m_unk0x4c = 0;
			}
		}

		if (KeyValueStringParse(output, g_strVISIBILITY, extraCopy)) {
			if (!strcmpi(output, "FALSE")) {
				Enable(FALSE);
			}
		}
	}
}

// FUNCTION: LEGO1 0x10044820
void MxControlPresenter::Enable(MxBool p_enable)
{
	if (MxPresenter::IsEnabled() != p_enable) {
		MxPresenter::Enable(p_enable);

		MxS16 i = 0;
		for (MxCompositePresenterList::iterator it = m_list.begin(); it != m_list.end(); it++) {
			if (i == m_unk0x4e) {
				(*it)->Enable((m_unk0x4c != 3 || i != 0) ? p_enable : 0);
				break;
			}

			i++;
		}

		if (!p_enable) {
			m_unk0x4e = 0;
		}
	}
}

// FUNCTION: LEGO1 0x100448a0
MxBool MxControlPresenter::HasTickleStatePassed(TickleState p_tickleState)
{
	MxCompositePresenterList::iterator it = m_list.begin();
	for (MxS16 i = m_unk0x4e; i > 0; i--, it++) {
		;
	}

	return (*it)->HasTickleStatePassed(p_tickleState);
}
