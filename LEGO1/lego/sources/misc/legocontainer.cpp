#include "legocontainer.h"

DECOMP_SIZE_ASSERT(LegoContainerInfo<LegoTexture>, 0x10);
// DECOMP_SIZE_ASSERT(LegoContainer<LegoTexture>, 0x18);
DECOMP_SIZE_ASSERT(LegoTextureContainer, 0x24);

// FUNCTION: LEGO1 0x10099870
LegoTextureContainer::~LegoTextureContainer()
{
}

// STUB: LEGO1 0x100998e0
LegoTextureInfo* LegoTextureContainer::Create(undefined* p_und)
{
	return NULL;
}

// FUNCTION: LEGO1 0x10099cc0
void LegoTextureContainer::Destroy(LegoTextureInfo* p_data)
{
	if (p_data == NULL) {
		return;
	}

#ifdef COMPAT_MODE
	LegoTextureList::iterator it;
	for (it = m_list.begin(); it != m_list.end(); it++) {
#else
	for (LegoTextureList::iterator it = m_list.begin(); it != m_list.end(); it++) {
#endif
		if (((*it).first) == p_data) {
			// TODO: Element type
			(*it).second = 0;

			if (p_data->m_texture->Release() == TRUE) {
				delete p_data;
				m_list.erase(it);
			}

			return;
		}
	}
}
