#include "legobox.h"

#include "misc/legoutil.h"

// FUNCTION: LEGO1 0x100d3740
LegoResult LegoBox::Read(LegoStorage* p_storage)
{
	LegoResult result;
	if ((result = m_min.Read(p_storage)) != SUCCESS) {
		return result;
	}
	if ((result = m_max.Read(p_storage)) != SUCCESS) {
		return result;
	}
	return SUCCESS;
}
