#ifndef __LEGOTEXTURE_H
#define __LEGOTEXTURE_H

#include "LegoTypes.h"

class LegoImage;
class LegoStorage;

class LegoTexture {
public:
	LegoTexture();
	~LegoTexture();
	LegoImage* GetImage() { return m_image; }
	void SetImage(LegoImage* p_image) { m_image = p_image; }
	LegoResult Read(LegoStorage* p_storage, LegoU32 p_square);
	LegoResult Write(LegoStorage* p_storage);

protected:
	LegoImage* m_image;
};

#endif // __LEGOTEXTURE_H
