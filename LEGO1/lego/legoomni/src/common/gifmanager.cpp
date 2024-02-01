#include "gifmanager.h"

DECOMP_SIZE_ASSERT(GifData, 0x14);
DECOMP_SIZE_ASSERT(GifMap, 0x10);
DECOMP_SIZE_ASSERT(GifManagerBase, 0x18);
DECOMP_SIZE_ASSERT(GifManager, 0x24);

// FUNCTION: LEGO1 0x10065c00
GifData::~GifData()
{
	if (m_name) {
		delete[] m_name;
		m_name = NULL;
	}

	if (m_palette) {
		m_palette->Release();
		m_palette = NULL;
	}

	if (m_surface) {
		m_surface->Release();
		m_surface = NULL;
	}

	if (m_texture) {
		m_texture->Release();
		m_texture = NULL;
	}
}

// FUNCTION: LEGO1 0x10099870
GifManager::~GifManager()
{
}

// FUNCTION: LEGO1 0x10099cc0
void GifManager::FUN_10099cc0(GifData* p_data)
{
	if (p_data == NULL) {
		return;
	}

#ifdef COMPAT_MODE
	GifList::iterator it;
	for (it = m_list.begin(); it != m_list.end(); it++) {
#else
	for (GifList::iterator it = m_list.begin(); it != m_list.end(); it++) {
#endif
		if (*it == p_data) {
			// TODO: This is wrong, but what is at +0x0c on the iterator?
			*it = NULL;

			if (p_data->m_texture->Release() == TRUE) {
				delete p_data;
				m_list.erase(it);
			}

			return;
		}
	}
}
