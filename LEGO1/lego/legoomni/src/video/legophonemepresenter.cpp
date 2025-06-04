#include "legophonemepresenter.h"

#include "legocharactermanager.h"
#include "legovideomanager.h"
#include "misc.h"
#include "misc/legocontainer.h"
#include "mxcompositepresenter.h"
#include "mxdsaction.h"

DECOMP_SIZE_ASSERT(LegoPhonemePresenter, 0x88)

// FUNCTION: LEGO1 0x1004e180
LegoPhonemePresenter::LegoPhonemePresenter()
{
	Init();
}

// FUNCTION: LEGO1 0x1004e340
LegoPhonemePresenter::~LegoPhonemePresenter()
{
}

// FUNCTION: LEGO1 0x1004e3b0
void LegoPhonemePresenter::Init()
{
	m_rectCount = 0;
	m_textureInfo = NULL;
	m_unk0x70 = FALSE;
	m_unk0x84 = FALSE;
}

// FUNCTION: LEGO1 0x1004e3d0
// FUNCTION: BETA10 0x100c3646
void LegoPhonemePresenter::StartingTickle()
{
	MxFlcPresenter::StartingTickle();

	if (m_textureInfo == NULL) {
		MxU16 extraLength;
		char* extraData;

		m_action->GetExtra(extraLength, extraData);

		if (extraData != NULL) {
			m_roiName = extraData;
			m_roiName.ToUpperCase();

			LegoROI *entityROI, *head;

			if (m_compositePresenter != NULL && m_compositePresenter->IsA("LegoAnimMMPresenter")) {
				entityROI = FindROI(m_roiName.GetData());
				m_unk0x84 = TRUE;
			}
			else {
				entityROI = CharacterManager()->GetActorROI(m_roiName.GetData(), TRUE);
			}

			head = entityROI->FindChildROI("head", entityROI);
			head->GetTextureInfo(m_textureInfo);

			LegoPhonemeList* phonemeList = VideoManager()->GetPhonemeList();
			LegoPhoneme* phoneme = new LegoPhoneme(m_roiName.GetData(), 1);

			LegoPhonemeListCursor cursor(phonemeList);

			if (!cursor.Find(phoneme)) {
				LegoTextureInfo* textureInfo = TextureContainer()->GetCached(m_textureInfo);

				CharacterManager()->SetHeadTexture(entityROI, textureInfo);

				phoneme->VTable0x0c(m_textureInfo);
				phoneme->VTable0x14(textureInfo);
				phonemeList->Append(phoneme);
				m_textureInfo = textureInfo;
			}
			else {
				LegoPhoneme* newPhoneme = phoneme;
				cursor.Current(phoneme);
				delete newPhoneme;

				phoneme->VTable0x04(phoneme->VTable0x00() + 1);
				cursor.SetValue(phoneme);

				m_unk0x70 = TRUE;
			}
		}
	}
}

// FUNCTION: LEGO1 0x1004e800
// FUNCTION: BETA10 0x100c3ac9
void LegoPhonemePresenter::LoadFrame(MxStreamChunk* p_chunk)
{
	MxU8* data = p_chunk->GetData();

	m_rectCount = *(MxS32*) data;
	data += sizeof(MxS32);

	MxRect32* rects = (MxRect32*) data;
	data += m_rectCount * sizeof(MxRect32);

	MxBool decodedColorMap;
	DecodeFLCFrame(
		&m_frameBitmap->GetBitmapInfo()->m_bmiHeader,
		m_frameBitmap->GetImage(),
		m_flcHeader,
		(FLIC_FRAME*) data,
		&decodedColorMap
	);
}

// FUNCTION: LEGO1 0x1004e840
// FUNCTION: BETA10 0x100c3b5d
void LegoPhonemePresenter::PutFrame()
{
	if (m_textureInfo != NULL && m_rectCount != 0) {
		m_textureInfo->FUN_10066010(m_frameBitmap->GetImage());
		m_rectCount = 0;
	}
}

// FUNCTION: LEGO1 0x1004e870
// FUNCTION: BETA10 0x100c3c24
void LegoPhonemePresenter::EndAction()
{
	if (m_action != NULL) {
		MxFlcPresenter::EndAction();

		LegoPhonemeList* phonemeList = VideoManager()->GetPhonemeList();
		LegoPhoneme* phoneme = new LegoPhoneme(m_roiName.GetData(), 1);

		LegoPhonemeListCursor cursor(phonemeList);

		if (cursor.Find(phoneme)) {
			LegoPhoneme* newPhoneme = phoneme;
			cursor.Current(phoneme);
			delete newPhoneme;

			if (phoneme->VTable0x00() == 1) {
				LegoROI* roi;

				if (m_unk0x84) {
					roi = FindROI(m_roiName.GetData());
				}
				else {
					roi = CharacterManager()->GetActorROI(m_roiName.GetData(), TRUE);
				}

				if (roi != NULL) {
					CharacterManager()->SetHeadTexture(roi, NULL);
				}

				if (!m_unk0x84) {
					CharacterManager()->ReleaseActor(m_roiName.GetData());
				}

				TextureContainer()->EraseCached(phoneme->VTable0x10());
				TextureContainer()->EraseCached(phoneme->VTable0x08());
				cursor.Destroy();
			}
			else {
				phoneme->VTable0x04(phoneme->VTable0x00() - 1);
				cursor.SetValue(phoneme);
			}

			if (!m_unk0x84) {
				CharacterManager()->ReleaseActor(m_roiName.GetData());
			}
		}
	}
}
