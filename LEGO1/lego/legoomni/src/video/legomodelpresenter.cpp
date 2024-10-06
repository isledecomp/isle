#include "legomodelpresenter.h"

#include "3dmanager/lego3dmanager.h"
#include "anim/legoanim.h"
#include "define.h"
#include "legocharactermanager.h"
#include "legoentity.h"
#include "legoentitypresenter.h"
#include "legovideomanager.h"
#include "legoworld.h"
#include "misc.h"
#include "misc/legocontainer.h"
#include "misc/legotexture.h"
#include "misc/version.h"
#include "mxcompositepresenter.h"
#include "mxdirectx/mxdirect3d.h"
#include "mxdssubscriber.h"
#include "mxutilities.h"
#include "realtime/realtime.h"
#include "roi/legoroi.h"

DECOMP_SIZE_ASSERT(LegoModelPresenter, 0x6c)

// GLOBAL: LEGO1 0x100f7ae0
MxS32 g_modelPresenterConfig = 1;

// FUNCTION: LEGO1 0x1000cca0
void LegoModelPresenter::Destroy()
{
	Destroy(FALSE);
}

// FUNCTION: LEGO1 0x1007f660
void LegoModelPresenter::configureLegoModelPresenter(MxS32 p_modelPresenterConfig)
{
	g_modelPresenterConfig = p_modelPresenterConfig;
}

// FUNCTION: LEGO1 0x1007f670
void LegoModelPresenter::Destroy(MxBool p_fromDestructor)
{
	m_criticalSection.Enter();
	m_roi = NULL;
	m_addedToView = FALSE;
	m_criticalSection.Leave();

	if (!p_fromDestructor) {
		MxVideoPresenter::Destroy(FALSE);
	}
}

// FUNCTION: LEGO1 0x1007f6b0
// FUNCTION: BETA10 0x1009845e
MxResult LegoModelPresenter::CreateROI(MxDSChunk* p_chunk)
{
	MxResult result = FAILURE;
	LegoU32 numROIs;
	Mx3DPointFloat vect;
	LegoMemory storage(p_chunk->GetData());
	LegoAnim anim;
	LegoU32 version, textureInfoOffset, i, numTextures, skipTextures;
	MxMatrix mat;
	LegoChar* textureName = NULL;
	LegoTexture* texture = NULL;
	LegoTextureInfo* textureInfo = NULL;
	LegoS32 hardwareMode = VideoManager()->GetDirect3D()->AssignedDevice()->GetHardwareMode();

	if (m_roi) {
		delete m_roi;
	}
	if (!(m_roi = new LegoROI(VideoManager()->GetRenderer()))) {
		goto done;
	}
	if (storage.Read(&version, sizeof(version)) != SUCCESS) {
		goto done;
	}
	if (version != MODEL_VERSION) {
		goto done;
	}
	if (storage.Read(&textureInfoOffset, sizeof(textureInfoOffset)) != SUCCESS) {
		goto done;
	}

	storage.SetPosition(textureInfoOffset);

	if (storage.Read(&numTextures, sizeof(numTextures)) != SUCCESS) {
		goto done;
	}
	if (storage.Read(&skipTextures, sizeof(skipTextures)) != SUCCESS) {
		goto done;
	}

	for (i = 0; i < numTextures; i++) {
		LegoU32 textureNameLength;

		storage.Read(&textureNameLength, sizeof(textureNameLength));
		textureName = new LegoChar[textureNameLength + 1];
		storage.Read(textureName, textureNameLength);
		textureName[textureNameLength] = '\0';

		strlwr(textureName);

		if (textureName[0] == '^') {
			strcpy(textureName, textureName + 1);

			if (g_modelPresenterConfig) {
				texture = new LegoTexture();
				if (texture->Read(&storage, hardwareMode) != SUCCESS) {
					goto done;
				}

				LegoTexture* discardTexture = new LegoTexture();
				if (discardTexture->Read(&storage, FALSE) != SUCCESS) {
					goto done;
				}
				delete discardTexture;
			}
			else {
				LegoTexture* discardTexture = new LegoTexture();
				if (discardTexture->Read(&storage, FALSE) != SUCCESS) {
					goto done;
				}
				delete discardTexture;

				texture = new LegoTexture();
				if (texture->Read(&storage, hardwareMode) != SUCCESS) {
					goto done;
				}
			}
		}
		else {
			texture = new LegoTexture();
			if (texture->Read(&storage, hardwareMode) != SUCCESS) {
				goto done;
			}
		}

		if (!skipTextures) {
			if (TextureContainer()->Get(textureName) == NULL) {
				textureInfo = LegoTextureInfo::Create(textureName, texture);

				if (textureInfo == NULL) {
					goto done;
				}

				TextureContainer()->Add(textureName, textureInfo);
			}

			delete[] textureName;
			textureName = NULL;
			delete texture;
			texture = NULL;
		}
	}

	storage.SetPosition(8);

	if (storage.Read(&numROIs, sizeof(numROIs)) != SUCCESS) {
		goto done;
	}
	if (anim.Read(&storage, FALSE) != SUCCESS) {
		goto done;
	}
	if (m_roi->Read(NULL, VideoManager()->GetRenderer(), GetViewLODListManager(), TextureContainer(), &storage) !=
		SUCCESS) {
		goto done;
	}
	if (m_roi->SetFrame(&anim, 0) != SUCCESS) {
		goto done;
	}

	// Get scripted location, direction and up vectors

	CalcLocalTransform(
		Mx3DPointFloat(m_action->GetLocation()[0], m_action->GetLocation()[1], m_action->GetLocation()[2]),
		Mx3DPointFloat(m_action->GetDirection()[0], m_action->GetDirection()[1], m_action->GetDirection()[2]),
		Mx3DPointFloat(m_action->GetUp()[0], m_action->GetUp()[1], m_action->GetUp()[2]),
		mat
	);
	m_roi->UpdateTransformationRelativeToParent(mat);

	result = SUCCESS;

done:
	if (textureName != NULL) {
		delete[] textureName;
	}
	if (texture != NULL) {
		delete texture;
	}
	if (result != SUCCESS) {
		if (m_roi) {
			delete m_roi;
			m_roi = NULL;
		}
	}

	return result;
}

// FUNCTION: LEGO1 0x1007ff70
MxResult LegoModelPresenter::FUN_1007ff70(
	MxDSChunk& p_chunk,
	LegoEntity* p_entity,
	MxBool p_roiVisible,
	LegoWorld* p_world
)
{
	MxResult result = SUCCESS;

	ParseExtra();

	if (m_roi == NULL && (result = CreateROI(&p_chunk)) == SUCCESS && p_entity != NULL) {
		VideoManager()->Get3DManager()->GetLego3DView()->Add(*m_roi);
		VideoManager()->Get3DManager()->GetLego3DView()->Moved(*m_roi);
	}

	if (m_roi != NULL) {
		m_roi->SetVisibility(p_roiVisible);
	}

	if (p_entity != NULL) {
		p_entity->SetROI(m_roi, TRUE, TRUE);
		p_entity->ClearFlag(LegoEntity::c_managerOwned);
	}
	else {
		p_world->GetROIList().push_back(m_roi);
	}

	return result;
}

// FUNCTION: LEGO1 0x10080050
// FUNCTION: BETA10 0x100991c2
void LegoModelPresenter::ReadyTickle()
{
	if (m_compositePresenter != NULL && m_compositePresenter->IsA("LegoEntityPresenter") &&
		m_compositePresenter->GetCurrentTickleState() <= e_ready) {
		return;
	}

	ParseExtra();

	if (m_roi != NULL) {
		if (m_compositePresenter && m_compositePresenter->IsA("LegoEntityPresenter")) {
			((LegoEntityPresenter*) m_compositePresenter)->GetInternalEntity()->SetROI(m_roi, m_addedToView, TRUE);
			((LegoEntityPresenter*) m_compositePresenter)
				->GetInternalEntity()
				->SetFlags(
					((LegoEntityPresenter*) m_compositePresenter)->GetInternalEntity()->GetFlags() &
					~LegoEntity::c_managerOwned
				);
			((LegoEntityPresenter*) m_compositePresenter)->GetInternalEntity()->SetType(LegoEntity::e_actor);
		}

		ParseExtra();
		ProgressTickleState(e_starting);
		EndAction();
	}
	else {
		MxStreamChunk* chunk = m_subscriber->PeekData();

		if (chunk != NULL && chunk->GetTime() <= m_action->GetElapsedTime()) {
			chunk = m_subscriber->PopData();
			MxResult result = CreateROI(chunk);
			m_subscriber->FreeDataChunk(chunk);

			if (result == SUCCESS) {
				VideoManager()->Get3DManager()->GetLego3DView()->Add(*m_roi);
				VideoManager()->Get3DManager()->GetLego3DView()->Moved(*m_roi);

				if (m_compositePresenter != NULL && m_compositePresenter->IsA("LegoEntityPresenter")) {
					((LegoEntityPresenter*) m_compositePresenter)->GetInternalEntity()->SetROI(m_roi, TRUE, TRUE);
					((LegoEntityPresenter*) m_compositePresenter)
						->GetInternalEntity()
						->SetFlags(
							((LegoEntityPresenter*) m_compositePresenter)->GetInternalEntity()->GetFlags() &
							~LegoEntity::c_managerOwned
						);
				}

				ParseExtra();
				ProgressTickleState(e_starting);
			}

			EndAction();
		}
	}
}

// FUNCTION: LEGO1 0x100801b0
void LegoModelPresenter::ParseExtra()
{
	MxU16 extraLength;
	char* extraData;
	m_action->GetExtra(extraLength, extraData);

	if (extraLength) {
		char extraCopy[1024], output[1024];
		output[0] = '\0';
		memcpy(extraCopy, extraData, extraLength);
		extraCopy[extraLength] = '\0';

		if (KeyValueStringParse(output, g_strAUTO_CREATE, extraCopy) != 0) {
			char* token = strtok(output, g_parseExtraTokens);

			if (m_roi == NULL) {
				m_roi = CharacterManager()->GetActorROI(token, FALSE);
				m_addedToView = FALSE;
			}
		}
		else if (KeyValueStringParse(output, g_strDB_CREATE, extraCopy) != 0 && m_roi == NULL) {
			LegoWorld* currentWorld = CurrentWorld();
			list<LegoROI*>& roiList = currentWorld->GetROIList();

			for (list<LegoROI*>::iterator it = roiList.begin(); it != roiList.end(); it++) {
				if (!strcmpi((*it)->GetName(), output)) {
					m_roi = *it;
					roiList.erase(it);

					m_addedToView = TRUE;
					VideoManager()->Get3DManager()->GetLego3DView()->Add(*m_roi);
					VideoManager()->Get3DManager()->GetLego3DView()->Moved(*m_roi);
					break;
				}
			}
		}
	}
}
