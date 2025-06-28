#include "legoracemap.h"

#include "define.h"
#include "legocontrolmanager.h"
#include "legovideomanager.h"
#include "legoworld.h"
#include "misc.h"
#include "mxcontrolpresenter.h"
#include "mxstillpresenter.h"
#include "mxutilities.h"

DECOMP_SIZE_ASSERT(LegoRaceMap, 0x1b4)

// FUNCTION: LEGO1 0x1005d0d0
// FUNCTION: BETA10 0x100ca2c0
LegoRaceMap::LegoRaceMap()
{
	m_unk0x08 = FALSE;
	m_stillPresenter = NULL;
	m_Map_Ctl = 0;
	ControlManager()->Register(this);
}

// FUNCTION: LEGO1 0x1005d2b0
// FUNCTION: BETA10 0x100ca48c
LegoRaceMap::~LegoRaceMap()
{
	ControlManager()->Unregister(this);
}

// GLOBAL: LEGO1 0x1010208c
// STRING: LEGO1 0x10101f88
const char* g_mapLocator = "MAP_LOCATOR";

// GLOBAL: LEGO1 0x10102090
// STRING: LEGO1 0x10101f78
const char* g_mapGeometry = "MAP_GEOMETRY";

// FUNCTION: LEGO1 0x1005d310
// FUNCTION: BETA10 0x100ca543
void LegoRaceMap::ParseAction(char* p_extra)
{
	char value[256];

	if (KeyValueStringParse(value, g_mapLocator, p_extra)) {
		// variable name verified by BETA10 0x100ca5ac
		MxStillPresenter* p = (MxStillPresenter*) VideoManager()->GetPresenterByActionObjectName(value);

		assert(p);
		p->Enable(FALSE);
		m_stillPresenter = p;
	}

	if (KeyValueStringParse(value, g_mapGeometry, p_extra)) {
		char* token = strtok(value, g_parseExtraTokens);
		if (token != NULL) {
			m_unk0x14 = atof(token);
		}

		token = strtok(NULL, g_parseExtraTokens);
		if (token != NULL) {
			m_unk0x18 = atof(token);
		}

		token = strtok(NULL, g_parseExtraTokens);
		if (token != NULL) {
			m_unk0x1c = atof(token);
		}

		token = strtok(NULL, g_parseExtraTokens);
		if (token != NULL) {
			m_unk0x20 = atof(token);
		}

		token = strtok(NULL, g_parseExtraTokens);
		if (token != NULL) {
			m_unk0x24 = atof(token);
		}

		token = strtok(NULL, g_parseExtraTokens);
		if (token != NULL) {
			m_unk0x28 = atof(token);
		}

		token = strtok(NULL, g_parseExtraTokens);
		if (token != NULL) {
			m_unk0x2c = atof(token);
		}

		token = strtok(NULL, g_parseExtraTokens);
		if (token != NULL) {
			m_unk0x30 = atof(token);
		}
	}

	LegoWorld* currentWorld = CurrentWorld();

	if (currentWorld) {
		// STRING: LEGO1 0x100f67bc
		const char* mapCtl = "Map_Ctl";

		m_Map_Ctl = (MxControlPresenter*) currentWorld->Find("MxControlPresenter", mapCtl);
		assert(m_Map_Ctl);
	}
}

// FUNCTION: LEGO1 0x1005d4b0
// FUNCTION: BETA10 0x100ca849
void LegoRaceMap::FUN_1005d4b0()
{
	if (m_unk0x08) {
		short xPos = (GetWorldPosition()[0] - m_unk0x14) / m_unk0x18 * m_unk0x24;
		short yPos = (GetWorldPosition()[2] - m_unk0x1c) / m_unk0x20 * m_unk0x28;

		m_stillPresenter->SetPosition(xPos + m_unk0x2c, m_unk0x30 - yPos);
	}
}

// FUNCTION: LEGO1 0x1005d550
// FUNCTION: BETA10 0x100ca92d
MxLong LegoRaceMap::Notify(MxParam& p_param)
{
	if (!m_stillPresenter) {
		return 1;
	}

	MxNotificationParam& param = (MxNotificationParam&) p_param;

	if (param.GetNotification() == c_notificationControl &&
		m_Map_Ctl->GetAction()->GetObjectId() == ((LegoControlManagerNotificationParam&) p_param).m_clickedObjectId) {

		if (((LegoControlManagerNotificationParam&) p_param).m_enabledChild == 1) {
			m_unk0x08 = TRUE;
			FUN_1005d4b0();
			m_stillPresenter->Enable(TRUE);
		}
		else {
			m_unk0x08 = FALSE;
			m_stillPresenter->Enable(FALSE);
		}
	}

	return 1;
}
