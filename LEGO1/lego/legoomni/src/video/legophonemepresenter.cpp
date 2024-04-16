#include "legophonemepresenter.h"

#include "legocharactermanager.h"
#include "misc.h"
#include "misc/legocontainer.h"
#include "mxcompositepresenter.h"

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
	m_unk0x68 = 0;
	m_textureInfo = NULL;
	m_unk0x70 = FALSE;
	m_unk0x84 = FALSE;
}

// FUNCTION: LEGO1 0x1004e3d0
void LegoPhonemePresenter::StartingTickle()
{
	MxFlcPresenter::StartingTickle();

	if (m_textureInfo == NULL) {
		MxU16 extraLength;
		char* extraData;

		m_action->GetExtra(extraLength, extraData);

		if (extraData != NULL) {
			roiName = extraData;
			roiName.ToUpperCase();

			LegoROI *entityROI, *head;

			if (m_compositePresenter != NULL && m_compositePresenter->IsA("LegoAnimMMPresenter")) {
				entityROI = FindROI(roiName.GetData());
				m_unk0x84 = TRUE;
			}
			else {
				entityROI = CharacterManager()->GetROI(roiName.GetData(), TRUE);
			}

			head = entityROI->FindChildROI("head", entityROI);
			head->GetTexture(m_textureInfo);

			LegoPhonemeList* phonemeList = VideoManager()->GetPhonemeList();
			LegoPhoneme* phoneme = new LegoPhoneme(roiName.GetData(), 1);

			LegoPhonemeListCursor cursor(phonemeList);

			if (!cursor.Find(phoneme)) {
				LegoTextureInfo* textureInfo = TextureContainer()->AddToList(m_textureInfo);

				CharacterManager()->FUN_100849a0(entityROI, textureInfo);

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

// STUB: LEGO1 0x1004e800
void LegoPhonemePresenter::LoadFrame(MxStreamChunk* p_chunk)
{
	// TODO
}

// STUB: LEGO1 0x1004e840
void LegoPhonemePresenter::PutFrame()
{
	// TODO
}

// STUB: LEGO1 0x1004e870
void LegoPhonemePresenter::EndAction()
{
	// TODO

	if (m_action != NULL) {
		MxFlcPresenter::EndAction();
	}
}
