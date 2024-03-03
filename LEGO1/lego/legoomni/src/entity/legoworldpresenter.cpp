#include "legoworldpresenter.h"

#include "define.h"
#include "legoanimationmanager.h"
#include "legobuildingmanager.h"
#include "legoentity.h"
#include "legoomni.h"
#include "legopartpresenter.h"
#include "legoplantmanager.h"
#include "legotexturepresenter.h"
#include "legovideomanager.h"
#include "legoworld.h"
#include "modeldb/modeldb.h"
#include "mxactionnotificationparam.h"
#include "mxautolocker.h"
#include "mxdsactionlist.h"
#include "mxdschunk.h"
#include "mxdsmediaaction.h"
#include "mxdsmultiaction.h"
#include "mxnotificationmanager.h"
#include "mxobjectfactory.h"
#include "mxpresenter.h"
#include "mxstl/stlcompat.h"
#include "mxutil.h"

#include <io.h>

// GLOBAL: LEGO1 0x100f75d4
MxS32 g_legoWorldPresenterQuality = 1;

// GLOBAL: LEGO1 0x100f75d8
long g_wdbOffset = 0;

// FUNCTION: LEGO1 0x100665b0
void LegoWorldPresenter::configureLegoWorldPresenter(MxS32 p_legoWorldPresenterQuality)
{
	g_legoWorldPresenterQuality = p_legoWorldPresenterQuality;
}

// FUNCTION: LEGO1 0x100665c0
LegoWorldPresenter::LegoWorldPresenter()
{
	m_unk0x50 = 50000;
}

// FUNCTION: LEGO1 0x10066770
LegoWorldPresenter::~LegoWorldPresenter()
{
	MxBool result = FALSE;
	if (m_entity) {
		MxS32 scriptIndex = ((LegoWorld*) m_entity)->GetScriptIndex();
		PlantManager()->FUN_10026360(scriptIndex);
		AnimationManager()->FUN_1005f720(scriptIndex);
		BuildingManager()->FUN_1002fa00();
		result = ((LegoWorld*) m_entity)->VTable0x5c();
	}

	if (result == FALSE) {
		FUN_10015820(FALSE, LegoOmni::c_disableInput | LegoOmni::c_disable3d | LegoOmni::c_clearScreen);
	}

	if (m_entity) {
#ifdef COMPAT_MODE
		{
			MxNotificationParam param(c_notificationNewPresenter, NULL);
			NotificationManager()->Send(m_entity, &param);
		}
#else
		NotificationManager()->Send(m_entity, &MxNotificationParam(c_notificationNewPresenter, NULL));
#endif
	}
}

// FUNCTION: LEGO1 0x10066870
MxResult LegoWorldPresenter::StartAction(MxStreamController* p_controller, MxDSAction* p_action)
{
	MxAutoLocker lock(&m_criticalSection);

	MxResult result = FAILURE;
	MxDSActionList* actions = ((MxDSMultiAction*) p_action)->GetActionList();
	MxObjectFactory* factory = ObjectFactory();
	MxDSActionListCursor cursor(actions);
	MxDSAction* action;

	if (MxPresenter::StartAction(p_controller, p_action) == SUCCESS) {
		cursor.Head();

		while (cursor.Current(action)) {
			MxBool success = FALSE;
			const char* presenterName;
			MxPresenter* presenter = NULL;

			cursor.Next();

			if (m_action->GetFlags() & MxDSAction::c_looping) {
				action->SetFlags(action->GetFlags() | MxDSAction::c_looping);
			}
			else if (m_action->GetFlags() & MxDSAction::c_bit3) {
				action->SetFlags(action->GetFlags() | MxDSAction::c_bit3);
			}

			presenterName = PresenterNameDispatch(*action);
			presenter = (MxPresenter*) factory->Create(presenterName);

			if (presenter && presenter->AddToManager() == SUCCESS) {
				presenter->SetCompositePresenter(this);
				if (presenter->StartAction(p_controller, action) == SUCCESS) {
					presenter->SetTickleState(e_idle);
					success = TRUE;
				}
			}

			if (success) {
				action->SetOrigin(this);
				m_list.push_back(presenter);
			}
			else if (presenter) {
				delete presenter;
			}
		}

		VideoManager()->RegisterPresenter(*this);

		result = SUCCESS;
	}

	return result;
}

// FUNCTION: LEGO1 0x10066a50
void LegoWorldPresenter::ReadyTickle()
{
	m_entity = (LegoEntity*) MxPresenter::CreateEntity("LegoWorld");
	if (m_entity) {
		m_entity->Create(*m_action);
		Lego()->AddWorld((LegoWorld*) m_entity);
		SetEntityLocation(m_action->GetLocation(), m_action->GetDirection(), m_action->GetUp());
	}

	ParseExtra();
	ProgressTickleState(e_starting);
}

// FUNCTION: LEGO1 0x10066ac0
void LegoWorldPresenter::StartingTickle()
{
	if (m_action->IsA("MxDSSerialAction")) {
		MxPresenter* presenter = *m_list.begin();
		if (presenter->GetCurrentTickleState() == e_idle) {
			presenter->SetTickleState(e_ready);
		}
	}
	else {
		for (MxCompositePresenterList::iterator it = m_list.begin(); it != m_list.end(); it++) {
			if ((*it)->GetCurrentTickleState() == e_idle) {
				(*it)->SetTickleState(e_ready);
			}
		}
	}

	ProgressTickleState(e_streaming);
}

// FUNCTION: LEGO1 0x10066b40
MxResult LegoWorldPresenter::LoadWorld(char* p_worldName, LegoWorld* p_world)
{
	char wdbPath[512];
	sprintf(wdbPath, "%s", MxOmni::GetHD());

	if (wdbPath[strlen(wdbPath) - 1] != '\\') {
		strcat(wdbPath, "\\");
	}

	strcat(wdbPath, "lego\\data\\world.wdb");

	if (access(wdbPath, 4) != 0) {
		sprintf(wdbPath, "%s", MxOmni::GetCD());

		if (wdbPath[strlen(wdbPath) - 1] != '\\') {
			strcat(wdbPath, "\\");
		}

		strcat(wdbPath, "lego\\data\\world.wdb");

		if (access(wdbPath, 4) != 0) {
			return FAILURE;
		}
	}

	ModelDbWorld* worlds = NULL;
	MxS32 numWorlds;
	FILE* wdbFile = fopen(wdbPath, "rb");

	if (wdbFile == NULL) {
		return FAILURE;
	}

	ReadModelDbWorlds(wdbFile, worlds, numWorlds);

	MxS32 i;
	for (i = 0; i < numWorlds; i++) {
		if (!strcmpi(worlds[i].m_worldName, p_worldName)) {
			break;
		}
	}

	if (i == numWorlds) {
		return FAILURE;
	}

	if (g_wdbOffset == 0) {
		MxU32 size;
		if (fread(&size, sizeof(size), 1, wdbFile) != 1) {
			return FAILURE;
		}

		MxU8* buff = new MxU8[size];
		if (fread(&buff, size, 1, wdbFile) != 1) {
			return FAILURE;
		}

		MxDSChunk chunk;
		chunk.SetLength(size);
		chunk.SetData(buff);

		LegoTexturePresenter texturePresenter;
		if (texturePresenter.ParseTexture(chunk) == SUCCESS) {
			texturePresenter.FUN_1004f290();
		}

		delete[] buff;
		// buff = NULL;

		if (fread(&size, sizeof(size), 1, wdbFile) != 1) {
			return FAILURE;
		}

		buff = new MxU8[size];
		if (fread(&buff, size, 1, wdbFile) != 1) {
			return FAILURE;
		}

		chunk.SetLength(size);
		chunk.SetData(buff);

		LegoPartPresenter partPresenter;
		if (partPresenter.ParsePart(chunk) == SUCCESS) {
			partPresenter.FUN_1007df20();
		}

		delete[] buff;

		g_wdbOffset = ftell(wdbFile);
	}
	else {
		if (fseek(wdbFile, g_wdbOffset, SEEK_SET) != 0) {
			return FAILURE;
		}
	}

	ModelDbPartListCursor cursor(worlds[i].m_partList);
	ModelDbPart* part;

	while (cursor.Next(part)) {
		if (GetViewLODListManager()->Lookup(part->m_name.GetData()) == NULL &&
			FUN_10067360(*part, wdbFile) != SUCCESS) {
			return FAILURE;
		}
	}

	for (MxS32 j = 0; j < worlds[i].m_numModels; j++) {
		if (!strnicmp(worlds[i].m_models[j].m_modelName, "isle", 4)) {
			switch (g_legoWorldPresenterQuality) {
			case 0:
				if (strcmpi(worlds[i].m_models[j].m_modelName, "isle_lo")) {
					continue;
				}
				break;
			case 1:
				if (strcmpi(worlds[i].m_models[j].m_modelName, "isle")) {
					continue;
				}
				break;
			case 2:
				if (strcmpi(worlds[i].m_models[j].m_modelName, "isle_hi")) {
					continue;
				}
				break;
			}

			if (FUN_100674b0(worlds[i].m_models[j], wdbFile, p_world) != SUCCESS) {
				return FAILURE;
			}
		}
		else {
			if (g_legoWorldPresenterQuality < 1 && !strcmpi(worlds[i].m_models[j].m_modelName, "haus")) {
				if (FUN_100674b0(worlds[i].m_models[j], wdbFile, p_world) != SUCCESS) {
					return FAILURE;
				}
			}
			else {
				if (worlds[i].m_models[j].m_modelName[4] == '3') {
					if (FUN_100674b0(worlds[i].m_models[j], wdbFile, p_world) != SUCCESS) {
						return FAILURE;
					}

					if (FUN_100674b0(worlds[i].m_models[j - 2], wdbFile, p_world) != SUCCESS) {
						return FAILURE;
					}

					if (FUN_100674b0(worlds[i].m_models[j - 1], wdbFile, p_world) != SUCCESS) {
						return FAILURE;
					}
				}
			}
		}
	}

	FreeModelDbWorlds(worlds, numWorlds);
	fclose(wdbFile);
	return SUCCESS;
}

// STUB: LEGO1 0x10067360
MxResult LegoWorldPresenter::FUN_10067360(ModelDbPart& p_part, FILE* p_wdbFile)
{
	// TODO
	return SUCCESS;
}

// STUB: LEGO1 0x100674b0
MxResult LegoWorldPresenter::FUN_100674b0(ModelDbModel& p_model, FILE* p_wdbFile, LegoWorld* p_world)
{
	// TODO
	return SUCCESS;
}

// FUNCTION: LEGO1 0x10067a70
void LegoWorldPresenter::VTable0x60(MxPresenter* p_presenter)
{
	MxCompositePresenter::VTable0x60(p_presenter);
	MxDSAction* action = p_presenter->GetAction();

	if (action->GetDuration() != -1 && (action->GetFlags() & MxDSAction::c_looping) == 0) {
		if (!action->IsA("MxDSMediaAction")) {
			return;
		}

		if (((MxDSMediaAction*) action)->GetSustainTime() != -1) {
			return;
		}
	}

	if (!p_presenter->IsA("LegoAnimPresenter") && !p_presenter->IsA("MxControlPresenter") &&
		!p_presenter->IsA("MxCompositePresenter")) {
		p_presenter->SendToCompositePresenter(Lego());
		((LegoWorld*) m_entity)->Add(p_presenter);
	}
}

// FUNCTION: LEGO1 0x10067b00
void LegoWorldPresenter::ParseExtra()
{
	MxU16 extraLength;
	char* extraData;
	m_action->GetExtra(extraLength, extraData);

	if (extraLength & MAXWORD) {
		char extraCopy[1024];
		memcpy(extraCopy, extraData, extraLength & MAXWORD);
		extraCopy[extraLength & MAXWORD] = '\0';

		char output[1024];
		if (KeyValueStringParse(output, g_strWORLD, extraCopy)) {
			char* worldKey = strtok(output, g_parseExtraTokens);
			LoadWorld(worldKey, (LegoWorld*) m_entity);
			((LegoWorld*) m_entity)->SetScriptIndex(Lego()->GetScriptIndex(worldKey));
		}
	}
}
