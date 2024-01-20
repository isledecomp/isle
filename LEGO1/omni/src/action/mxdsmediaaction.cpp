#include "mxdsmediaaction.h"

#include "mxutil.h"

DECOMP_SIZE_ASSERT(MxDSMediaAction, 0xb8)

// FUNCTION: LEGO1 0x100c8b40
MxDSMediaAction::MxDSMediaAction()
{
	this->m_mediaSrcPath = NULL;
	this->m_unk0x9c.m_unk0x00 = 0;
	this->m_unk0x9c.m_unk0x04 = 0;
	this->m_framesPerSecond = 0;
	this->m_mediaFormat = 0;
	this->m_paletteManagement = 1;
	this->m_unk0xb4 = -1;
	this->m_sustainTime = 0;
	this->SetType(e_mediaAction);
}

// FUNCTION: LEGO1 0x100c8cf0
MxDSMediaAction::~MxDSMediaAction()
{
	delete[] this->m_mediaSrcPath;
}

// FUNCTION: LEGO1 0x100c8d60
void MxDSMediaAction::CopyFrom(MxDSMediaAction& p_dsMediaAction)
{
	CopyMediaSrcPath(p_dsMediaAction.m_mediaSrcPath);

	this->m_unk0x9c = p_dsMediaAction.m_unk0x9c;
	this->m_framesPerSecond = p_dsMediaAction.m_framesPerSecond;
	this->m_mediaFormat = p_dsMediaAction.m_mediaFormat;
	this->m_paletteManagement = p_dsMediaAction.m_paletteManagement;
	this->m_sustainTime = p_dsMediaAction.m_sustainTime;
}

// FUNCTION: LEGO1 0x100c8dc0
MxDSMediaAction& MxDSMediaAction::operator=(MxDSMediaAction& p_dsMediaAction)
{
	if (this == &p_dsMediaAction)
		return *this;

	MxDSAction::operator=(p_dsMediaAction);
	this->CopyFrom(p_dsMediaAction);
	return *this;
}

// FUNCTION: LEGO1 0x100c8df0
MxDSAction* MxDSMediaAction::Clone()
{
	MxDSMediaAction* clone = new MxDSMediaAction();

	if (clone)
		*clone = *this;

	return clone;
}

// FUNCTION: LEGO1 0x100c8e80
void MxDSMediaAction::CopyMediaSrcPath(const char* p_mediaSrcPath)
{
	if (this->m_mediaSrcPath == p_mediaSrcPath)
		return;

	delete[] this->m_mediaSrcPath;

	if (p_mediaSrcPath) {
		this->m_mediaSrcPath = new char[strlen(p_mediaSrcPath) + 1];
		if (this->m_mediaSrcPath)
			strcpy(this->m_mediaSrcPath, p_mediaSrcPath);
	}
	else
		this->m_mediaSrcPath = NULL;
}

// FUNCTION: LEGO1 0x100c8f00
undefined4 MxDSMediaAction::VTable0x14()
{
	return MxDSAction::VTable0x14();
}

// FUNCTION: LEGO1 0x100c8f10
MxU32 MxDSMediaAction::GetSizeOnDisk()
{
	MxU32 totalSizeOnDisk = MxDSAction::GetSizeOnDisk();

	if (this->m_mediaSrcPath)
		totalSizeOnDisk += strlen(this->m_mediaSrcPath) + 1;
	else
		totalSizeOnDisk++;

	totalSizeOnDisk += 24;
	this->m_sizeOnDisk = totalSizeOnDisk - MxDSAction::GetSizeOnDisk();
	return totalSizeOnDisk;
}

// FUNCTION: LEGO1 0x100c8f60
void MxDSMediaAction::Deserialize(MxU8** p_source, MxS16 p_unk0x24)
{
	MxDSAction::Deserialize(p_source, p_unk0x24);

	GetString(p_source, &this->m_mediaSrcPath, this, &MxDSMediaAction::CopyMediaSrcPath);
	GetScalar(p_source, this->m_unk0x9c.m_unk0x00);
	GetScalar(p_source, this->m_unk0x9c.m_unk0x04);
	GetScalar(p_source, this->m_framesPerSecond);
	GetScalar(p_source, this->m_mediaFormat);
	GetScalar(p_source, this->m_paletteManagement);
	GetScalar(p_source, this->m_sustainTime);
}
