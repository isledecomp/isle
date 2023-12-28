#include "lego3dmanager.h"

#include "decomp.h"
#include "mxrendersettings.h"
#include "mxunknown100dbdbc.h"
#include "tgl/tgl.h"

DECOMP_SIZE_ASSERT(Lego3DManager, 0x10);

// FUNCTION: LEGO1 0x100ab320
Lego3DManager::Lego3DManager()
{
	m_render = NULL;
	m_3dView = NULL;
	m_unk0x0c = NULL;
}

// FUNCTION: LEGO1 0x100ab360
Lego3DManager::~Lego3DManager()
{
	Destroy();
}

// FUNCTION: LEGO1 0x100ab370
void Lego3DManager::Init(MxRenderSettings& p_settings)
{
	m_unk0x0c = new MxUnknown100dbdbc();
	m_render = Tgl::CreateRenderer();
	m_3dView = new Lego3DView();

	MxRenderSettings settings;
	MxRenderSettings::CopyFrom(settings, p_settings);

	m_3dView->Init(settings, *m_render);
}

// FUNCTION: LEGO1 0x100ab460
void Lego3DManager::Destroy()
{
	delete m_3dView;
	m_3dView = NULL;
	delete m_render;
	m_render = NULL;
	delete m_unk0x0c;
	m_unk0x0c = NULL;
}
