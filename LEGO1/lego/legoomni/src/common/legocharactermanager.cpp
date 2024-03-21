#include "legocharactermanager.h"

#include "legoanimactor.h"
#include "legogamestate.h"
#include "legovideomanager.h"
#include "misc.h"
#include "mxmisc.h"
#include "roi/legoroi.h"

DECOMP_SIZE_ASSERT(LegoCharacter, 0x08)
DECOMP_SIZE_ASSERT(LegoCharacterManager, 0x08)
DECOMP_SIZE_ASSERT(LegoCharacterData::Unknown, 0x18)
DECOMP_SIZE_ASSERT(LegoCharacterData, 0x108)

// GLOBAL: LEGO1 0x100da3bc
float g_roiBoundingSphere[] = {0.000267, 0.78080797, -0.01906, 0.951612};

// GLOBAL: LEGO1 0x100da3cc
float g_roiBoundingBox[] = {-0.46116599, -0.002794, -0.29944199, 0.46169999, 1.56441, 0.261321};

// GLOBAL: LEGO1 0x100f80c0
LegoCharacterData g_characterDataInit[66]; // TODO: add data

// GLOBAL: LEGO1 0x100fc4e4
char* LegoCharacterManager::g_customizeAnimFile = NULL;

// GLOBAL: LEGO1 0x10104f20
LegoCharacterData g_characterData[66];

// FUNCTION: LEGO1 0x10082a20
LegoCharacterManager::LegoCharacterManager()
{
	m_characters = new LegoCharacterMap();
	FUN_10083270();

	m_customizeAnimFile = new CustomizeAnimFileVariable("CUSTOMIZE_ANIM_FILE");
	VariableTable()->SetVariable(m_customizeAnimFile);
}

// FUNCTION: LEGO1 0x10083270
void LegoCharacterManager::FUN_10083270()
{
	for (MxS32 i = 0; i < _countof(g_characterData); i++) {
		g_characterData[i] = g_characterDataInit[i];
	}
}

// STUB: LEGO1 0x100832a0
void LegoCharacterManager::FUN_100832a0()
{
	// TODO
}

// FUNCTION: LEGO1 0x10083310
MxResult LegoCharacterManager::Write(LegoStorage* p_storage)
{
	MxResult result = FAILURE;

	for (MxS32 i = 0; i < _countof(g_characterData); i++) {
		LegoCharacterData* data = &g_characterData[i];

		if (p_storage->Write(&data->m_unk0x0c, sizeof(data->m_unk0x0c)) != SUCCESS) {
			goto done;
		}
		if (p_storage->Write(&data->m_unk0x10, sizeof(data->m_unk0x10)) != SUCCESS) {
			goto done;
		}
		if (p_storage->Write(&data->m_unk0x14, sizeof(data->m_unk0x14)) != SUCCESS) {
			goto done;
		}
		if (p_storage->Write(&data->m_unk0x18[1].m_unk0x08, sizeof(data->m_unk0x18[1].m_unk0x08)) != SUCCESS) {
			goto done;
		}
		if (p_storage->Write(&data->m_unk0x18[1].m_unk0x14, sizeof(data->m_unk0x18[1].m_unk0x14)) != SUCCESS) {
			goto done;
		}
		if (p_storage->Write(&data->m_unk0x18[2].m_unk0x14, sizeof(data->m_unk0x18[2].m_unk0x14)) != SUCCESS) {
			goto done;
		}
		if (p_storage->Write(&data->m_unk0x18[4].m_unk0x14, sizeof(data->m_unk0x18[4].m_unk0x14)) != SUCCESS) {
			goto done;
		}
		if (p_storage->Write(&data->m_unk0x18[5].m_unk0x14, sizeof(data->m_unk0x18[5].m_unk0x14)) != SUCCESS) {
			goto done;
		}
		if (p_storage->Write(&data->m_unk0x18[8].m_unk0x14, sizeof(data->m_unk0x18[8].m_unk0x14)) != SUCCESS) {
			goto done;
		}
		if (p_storage->Write(&data->m_unk0x18[9].m_unk0x14, sizeof(data->m_unk0x18[9].m_unk0x14)) != SUCCESS) {
			goto done;
		}
	}

	result = SUCCESS;

done:
	return result;
}

// FUNCTION: LEGO1 0x100833f0
MxResult LegoCharacterManager::Read(LegoStorage* p_storage)
{
	MxResult result = FAILURE;

	for (MxS32 i = 0; i < _countof(g_characterData); i++) {
		LegoCharacterData* data = &g_characterData[i];

		if (p_storage->Read(&data->m_unk0x0c, sizeof(data->m_unk0x0c)) != SUCCESS) {
			goto done;
		}
		if (p_storage->Read(&data->m_unk0x10, sizeof(data->m_unk0x10)) != SUCCESS) {
			goto done;
		}
		if (p_storage->Read(&data->m_unk0x14, sizeof(data->m_unk0x14)) != SUCCESS) {
			goto done;
		}
		if (p_storage->Read(&data->m_unk0x18[1].m_unk0x08, sizeof(data->m_unk0x18[1].m_unk0x08)) != SUCCESS) {
			goto done;
		}
		if (p_storage->Read(&data->m_unk0x18[1].m_unk0x14, sizeof(data->m_unk0x18[1].m_unk0x14)) != SUCCESS) {
			goto done;
		}
		if (p_storage->Read(&data->m_unk0x18[2].m_unk0x14, sizeof(data->m_unk0x18[2].m_unk0x14)) != SUCCESS) {
			goto done;
		}
		if (p_storage->Read(&data->m_unk0x18[4].m_unk0x14, sizeof(data->m_unk0x18[4].m_unk0x14)) != SUCCESS) {
			goto done;
		}
		if (p_storage->Read(&data->m_unk0x18[5].m_unk0x14, sizeof(data->m_unk0x18[5].m_unk0x14)) != SUCCESS) {
			goto done;
		}
		if (p_storage->Read(&data->m_unk0x18[8].m_unk0x14, sizeof(data->m_unk0x18[8].m_unk0x14)) != SUCCESS) {
			goto done;
		}
		if (p_storage->Read(&data->m_unk0x18[9].m_unk0x14, sizeof(data->m_unk0x18[9].m_unk0x14)) != SUCCESS) {
			goto done;
		}
	}

	result = SUCCESS;

done:
	return result;
}

// FUNCTION: LEGO1 0x10083500
LegoROI* LegoCharacterManager::GetROI(const char* p_key, MxBool p_createEntity)
{
	LegoCharacter* character = NULL;
	LegoCharacterMap::iterator it = m_characters->find(p_key);

	if (it != m_characters->end()) {
		character = (*it).second;
		character->AddRef();
	}

	if (character == NULL) {
		LegoROI* roi = CreateROI(p_key);
		roi->SetVisibility(FALSE);

		if (roi != NULL) {
			character = new LegoCharacter(roi);
			char* key = new char[strlen(p_key) + 1];

			if (key != NULL) {
				strcpy(key, p_key);
				(*m_characters)[key] = character;
				VideoManager()->Get3DManager()->Add(*roi);
			}
		}
	}
	else {
		VideoManager()->Get3DManager()->Remove(*character->m_roi);
		VideoManager()->Get3DManager()->Add(*character->m_roi);
	}

	if (character != NULL) {
		if (p_createEntity && character->m_roi->GetEntity() == NULL) {
			// TODO: Match
			LegoAnimActor* actor = new LegoAnimActor(1);

			actor->SetROI(character->m_roi, FALSE, FALSE);
			actor->FUN_100114e0(0);
			actor->SetFlag(LegoActor::c_bit2);
			FUN_10084c60(p_key)->m_actor = actor;
		}

		return character->m_roi;
	}

	return NULL;
}

// STUB: LEGO1 0x10083db0
void LegoCharacterManager::FUN_10083db0(LegoROI* p_roi)
{
	// TODO
}

// STUB: LEGO1 0x10083f10
void LegoCharacterManager::FUN_10083f10(LegoROI* p_roi)
{
	// TODO
}

// FUNCTION: LEGO1 0x10084030
LegoROI* LegoCharacterManager::CreateROI(const char* p_key)
{
	MxBool success = FALSE;
	LegoROI* roi = NULL;
	BoundingSphere boundingSphere;
	BoundingBox boundingBox;
	MxMatrix mat;
	CompoundObject* comp;

	Tgl::Renderer* renderer = VideoManager()->GetRenderer();
	ViewLODListManager* lodManager = GetViewLODListManager();
	LegoTextureContainer* textureContainer = TextureContainer();
	LegoCharacterData* entry = FUN_10084c60(p_key);

	if (entry == NULL) {
		goto done;
	}

	if (!strcmpi(p_key, "pep")) {
		LegoCharacterData* pepper = FUN_10084c60("pepper");

		entry->m_unk0x0c = pepper->m_unk0x0c;
		entry->m_unk0x10 = pepper->m_unk0x10;
		entry->m_unk0x14 = pepper->m_unk0x14;

		for (MxS32 i = 0; i < _countof(entry->m_unk0x18); i++) {
			entry->m_unk0x18[i] = pepper->m_unk0x18[i];
		}
	}

	roi = new LegoROI(renderer);
	roi->SetName(p_key);

	boundingSphere.Center()[0] = g_roiBoundingSphere[0];
	boundingSphere.Center()[1] = g_roiBoundingSphere[1];
	boundingSphere.Center()[2] = g_roiBoundingSphere[2];
	boundingSphere.Radius() = g_roiBoundingSphere[3];

	roi->SetBoundingSphere(boundingSphere);

	boundingBox.Min()[0] = g_roiBoundingBox[0];
	boundingBox.Min()[1] = g_roiBoundingBox[1];
	boundingBox.Min()[2] = g_roiBoundingBox[2];
	boundingBox.Max()[0] = g_roiBoundingBox[3];
	boundingBox.Max()[1] = g_roiBoundingBox[4];
	boundingBox.Max()[2] = g_roiBoundingBox[5];

	roi->SetUnknown0x80(boundingBox);

	comp = new CompoundObject();
	roi->SetComp(comp);

done:
	if (!success && roi != NULL) {
		delete roi;
		roi = NULL;
	}

	return roi;
}

// STUB: LEGO1 0x10084c00
MxBool LegoCharacterManager::FUN_10084c00(const LegoChar*)
{
	// TODO
	return FALSE;
}

// STUB: LEGO1 0x10084c60
LegoCharacterData* LegoCharacterManager::FUN_10084c60(const char* p_key)
{
	return NULL;
}

// STUB: LEGO1 0x10084ec0
MxBool LegoCharacterManager::FUN_10084ec0(LegoROI* p_roi)
{
	// TODO
	return FALSE;
}

// STUB: LEGO1 0x10085140
MxU32 LegoCharacterManager::FUN_10085140(LegoROI*, MxBool)
{
	// TODO
	return 0;
}

// FUNCTION: LEGO1 0x100851a0
void LegoCharacterManager::SetCustomizeAnimFile(const char* p_value)
{
	if (g_customizeAnimFile != NULL) {
		delete[] g_customizeAnimFile;
	}

	if (p_value != NULL) {
		g_customizeAnimFile = new char[strlen(p_value) + 1];

		if (g_customizeAnimFile != NULL) {
			strcpy(g_customizeAnimFile, p_value);
		}
	}
	else {
		g_customizeAnimFile = NULL;
	}
}

// STUB: LEGO1 0x10085210
LegoROI* LegoCharacterManager::FUN_10085210(const LegoChar*, LegoChar*, undefined)
{
	return NULL;
}

// FUNCTION: LEGO1 0x10085a80
LegoROI* LegoCharacterManager::FUN_10085a80(LegoChar* p_und1, LegoChar* p_und2, undefined p_und3)
{
	return FUN_10085210(p_und1, p_und2, p_und3);
}
