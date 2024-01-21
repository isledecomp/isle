#include "mxcontrolpresenter.h"

#include "define.h"
#include "mxticklemanager.h"
#include "mxutil.h"

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
	if (m_unk0x58)
		delete m_unk0x58;
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

// STUB: LEGO1 0x10044270
MxBool MxControlPresenter::FUN_10044270(undefined4, undefined4, undefined4*)
{
	// TODO
	return TRUE;
}

// STUB: LEGO1 0x10044480
MxBool MxControlPresenter::FUN_10044480(undefined4, undefined4*)
{
	// TODO
	return TRUE;
}

// STUB: LEGO1 0x10044540
void MxControlPresenter::VTable0x6c(undefined4)
{
	// TODO
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
	char result[256];
	MxU16 len = m_action->GetExtraLength();
	if (len) {
		char buffer[256];
		memcpy(buffer, m_action->GetExtraData(), m_action->GetExtraLength());
		buffer[len] = 0;

		if (KeyValueStringParse(result, g_style, buffer)) {
			char* str = strtok(result, g_parseExtraTokens);
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
					for (MxU16 i = 1; i <= count; i++) {
						m_unk0x58[i] = atoi(strtok(NULL, g_parseExtraTokens));
					}
				}
			}
			else {
				m_unk0x4c = 0;
			}
		}

		if (KeyValueStringParse(result, g_strVISIBILITY, buffer)) {
			if (!strcmpi(result, "FALSE")) {
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
	for (MxS16 i = m_unk0x4e; i > 0; i--, it++)
		;

	return (*it)->HasTickleStatePassed(p_tickleState);
}
