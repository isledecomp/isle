#include "legopartpresenter.h"

#include "legovideomanager.h"
#include "misc.h"
#include "misc/legocontainer.h"
#include "misc/legostorage.h"
#include "misc/legotexture.h"
#include "viewmanager/viewlodlist.h"

DECOMP_SIZE_ASSERT(LegoLODList, 0x18)
DECOMP_SIZE_ASSERT(LegoNamedPart, 0x14)
DECOMP_SIZE_ASSERT(LegoNamedPartList, 0x18)

// GLOBAL: LEGO1 0x100f7aa0
MxS32 g_partPresenterConfig1 = 1;

// GLOBAL: LEGO1 0x100f7aa4
MxS32 g_partPresenterConfig2 = 100;

// FUNCTION: LEGO1 0x1000cf60
void LegoPartPresenter::Destroy()
{
	Destroy(FALSE);
}

// FUNCTION: LEGO1 0x1007c990
void LegoPartPresenter::configureLegoPartPresenter(MxS32 p_partPresenterConfig1, MxS32 p_partPresenterConfig2)
{
	g_partPresenterConfig1 = p_partPresenterConfig1;
	g_partPresenterConfig2 = p_partPresenterConfig2;
}

// FUNCTION: LEGO1 0x1007c9b0
MxResult LegoPartPresenter::AddToManager()
{
	VideoManager()->RegisterPresenter(*this);
	return SUCCESS;
}

// STUB: LEGO1 0x1007c9d0
void LegoPartPresenter::Destroy(MxBool p_fromDestructor)
{
	// TODO
}

// FUNCTION: LEGO1 0x1007ca30
MxResult LegoPartPresenter::Read(MxDSChunk& p_chunk)
{
	MxResult result = FAILURE;
	LegoU32 numROIs, numLODs;
	LegoMemory storage(p_chunk.GetData());
	LegoU32 textureInfoOffset, i, j, numTextures;
	LegoU32 roiNameLength, roiInfoOffset, surplusLODs;
	LegoLODList* lods;
	LegoNamedPart* namedPart;
	LegoChar* roiName = NULL;
	LegoChar* textureName = NULL;
	LegoTexture* texture = NULL;
	LegoTextureInfo* textureInfo = NULL;
	LegoS32 hardwareMode = VideoManager()->GetDirect3D()->AssignedDevice()->GetHardwareMode();

	if (storage.Read(&textureInfoOffset, sizeof(textureInfoOffset)) != SUCCESS) {
		goto done;
	}
	if (storage.SetPosition(textureInfoOffset) != SUCCESS) {
		goto done;
	}
	if (storage.Read(&numTextures, sizeof(numTextures)) != SUCCESS) {
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

			if (g_partPresenterConfig1) {
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

	if (storage.SetPosition(4) != SUCCESS) {
		goto done;
	}

	m_parts = new LegoNamedPartList();

	if (storage.Read(&numROIs, sizeof(numROIs)) != SUCCESS) {
		goto done;
	}

	for (i = 0; i < numROIs; i++) {
		if (storage.Read(&roiNameLength, sizeof(roiNameLength)) != SUCCESS) {
			goto done;
		}

		roiName = new LegoChar[roiNameLength + 1];
		if (storage.Read(roiName, roiNameLength) != SUCCESS) {
			goto done;
		}

		roiName[roiNameLength] = '\0';
		strlwr(roiName);

		if (storage.Read(&numLODs, sizeof(numLODs)) != SUCCESS) {
			goto done;
		}
		if (storage.Read(&roiInfoOffset, sizeof(roiInfoOffset)) != SUCCESS) {
			goto done;
		}

		if (numLODs > g_partPresenterConfig2) {
			surplusLODs = numLODs - g_partPresenterConfig2;
			numLODs = g_partPresenterConfig2;
		}
		else {
			surplusLODs = 0;
		}

		lods = new LegoLODList();

		for (j = 0; j < numLODs; j++) {
			LegoLOD* lod = new LegoLOD(VideoManager()->GetRenderer());

			if (lod->Read(VideoManager()->GetRenderer(), TextureContainer(), &storage) != SUCCESS) {
				goto done;
			}

			if (j == 0) {
				if (surplusLODs != 0 && lod->GetUnknown0x08Test8()) {
					numLODs++;
					surplusLODs--;
				}
			}

			lods->Append(lod);
		}

		storage.SetPosition(roiInfoOffset);

		namedPart = new LegoNamedPart(roiName, lods);
		m_parts->Append(namedPart);

		delete[] roiName;
		roiName = NULL;
	}

	result = SUCCESS;

done:
	if (roiName != NULL) {
		delete[] roiName;
	}
	if (result != SUCCESS && m_parts != NULL) {
		delete m_parts;
		m_parts = NULL;
	}

	return result;
}

// FUNCTION: LEGO1 0x1007deb0
void LegoPartPresenter::ReadyTickle()
{
	MxStreamChunk* chunk = m_subscriber->PeekData();

	if (chunk != NULL && chunk->GetTime() <= m_action->GetElapsedTime()) {
		ParseExtra();
		ProgressTickleState(e_starting);

		chunk = m_subscriber->PopData();
		MxResult result = Read(*chunk);
		m_subscriber->FreeDataChunk(chunk);

		if (result == SUCCESS) {
			Store();
		}

		EndAction();
	}
}

// FUNCTION: LEGO1 0x1007df20
void LegoPartPresenter::Store()
{
	LegoNamedPartListCursor partCursor(m_parts);
	LegoNamedPart* part;

	while (partCursor.Next(part)) {
		ViewLODList* lodList = GetViewLODListManager()->Lookup(part->GetName()->GetData());

		if (lodList == NULL) {
			lodList = GetViewLODListManager()->Create(part->GetName()->GetData(), part->GetList()->GetCount());

			LegoLODListCursor lodCursor(part->GetList());
			LegoLOD* lod;

			while (lodCursor.First(lod)) {
				lodCursor.Detach();
				lodList->PushBack(lod);
			}
		}
		else {
			lodList->Release();
		}
	}

	if (m_parts != NULL) {
		delete m_parts;
	}

	m_parts = NULL;
}
