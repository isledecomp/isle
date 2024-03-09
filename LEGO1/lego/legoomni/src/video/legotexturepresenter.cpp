#include "legotexturepresenter.h"

#include "legovideomanager.h"
#include "misc.h"
#include "misc/legocontainer.h"
#include "misc/legoimage.h"
#include "misc/legostorage.h"
#include "mxcompositepresenter.h"

DECOMP_SIZE_ASSERT(LegoTexturePresenter, 0x54)
DECOMP_SIZE_ASSERT(LegoNamedTexture, 0x14)
DECOMP_SIZE_ASSERT(LegoNamedTextureList, 0x18)
DECOMP_SIZE_ASSERT(LegoNamedTextureListCursor, 0x10)

// FUNCTION: LEGO1 0x1004eb40
LegoTexturePresenter::~LegoTexturePresenter()
{
	VideoManager()->UnregisterPresenter(*this);
}

// FUNCTION: LEGO1 0x1004ebb0
MxResult LegoTexturePresenter::AddToManager()
{
	VideoManager()->RegisterPresenter(*this);
	return SUCCESS;
}

// FUNCTION: LEGO1 0x1004ebd0
MxResult LegoTexturePresenter::Read(MxDSChunk& p_chunk)
{
	MxResult result = FAILURE;
	LegoMemory storage(p_chunk.GetData());
	LegoChar* textureName = NULL;
	LegoS32 hardwareMode = VideoManager()->GetDirect3D()->AssignedDevice()->GetHardwareMode();

	m_textures = new LegoNamedTextureList();

	LegoU32 numTextures, i;
	if (storage.Read(&numTextures, sizeof(numTextures)) != SUCCESS) {
		goto done;
	}

	for (i = 0; i < numTextures; i++) {
		LegoU32 textureNameLength;
		LegoTexture* texture;
		LegoNamedTexture* namedTexture;

		if (storage.Read(&textureNameLength, sizeof(textureNameLength)) != SUCCESS) {
			goto done;
		}

		textureName = new LegoChar[textureNameLength + 1];
		if (storage.Read(textureName, textureNameLength) != SUCCESS) {
			goto done;
		}

		textureName[textureNameLength] = '\0';
		strlwr(textureName);

		texture = new LegoTexture();
		if (texture->Read(&storage, hardwareMode) != SUCCESS) {
			goto done;
		}

		namedTexture = new LegoNamedTexture(textureName, texture);
		m_textures->Append(namedTexture);

		delete[] textureName;
		textureName = NULL;
	}

	result = SUCCESS;

done:
	if (textureName != NULL) {
		delete[] textureName;
	}
	if (result != SUCCESS && m_textures != NULL) {
		delete m_textures;
		m_textures = NULL;
	}

	return result;
}

// FUNCTION: LEGO1 0x1004f290
MxResult LegoTexturePresenter::Store()
{
	LegoNamedTextureListCursor cursor(m_textures);
	LegoNamedTexture* namedTexture;
	VideoManager();

	while (cursor.Next(namedTexture)) {
		LegoTexture* texture = namedTexture->GetTexture();
		LegoTextureInfo* textureInfo = TextureContainer()->Get(namedTexture->GetName()->GetData());

		if (textureInfo == NULL) {
			textureInfo = LegoTextureInfo::Create(namedTexture->GetName()->GetData(), texture);

			if (textureInfo != NULL) {
				TextureContainer()->Add(namedTexture->GetName()->GetData(), textureInfo);
			}
		}
		else {
			textureInfo->FUN_10066010(texture->GetImage()->GetBits());
		}
	}

	if (m_textures != NULL) {
		delete m_textures;
	}

	m_textures = NULL;
	return SUCCESS;
}

// STUB: LEGO1 0x1004fc60
MxResult LegoTexturePresenter::PutData()
{
	// TODO
	return FAILURE;
}

// FUNCTION: LEGO1 0x1004fcb0
void LegoTexturePresenter::DoneTickle()
{
	if (this->m_compositePresenter && !this->m_compositePresenter->VTable0x64(2)) {
		SetTickleState(e_idle);
		return;
	}

	MxMediaPresenter::DoneTickle();
}
