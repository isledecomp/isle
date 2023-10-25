#ifndef MXLIST_H
#define MXLIST_H

#include "mxcore.h"
#include "mxtypes.h"

template <class T>
class MxList;
template <class T>
class MxListCursor;

template <class T>
class MxListEntry {
public:
	MxListEntry() {}
	MxListEntry(T p_obj, MxListEntry* p_prev)
	{
		m_obj = p_obj;
		m_prev = p_prev;
		m_next = NULL;
	}
	MxListEntry(T p_obj, MxListEntry* p_prev, MxListEntry* p_next)
	{
		m_obj = p_obj;
		m_prev = p_prev;
		m_next = p_next;
	}

	T GetValue() { return this->m_obj; }

	friend class MxList<T>;
	friend class MxListCursor<T>;

private:
	T m_obj;
	MxListEntry* m_prev;
	MxListEntry* m_next;
};

// SIZE 0x10
template <class T>
class MxListParent : public MxCore {
public:
	MxListParent()
	{
		m_count = 0;
		m_customDestructor = Destroy;
	}

	virtual ~MxListParent() {}
	virtual MxS8 Compare(T, T) { return 0; };

	static void Destroy(T){};

protected:
	MxU32 m_count;                 // +0x8
	void (*m_customDestructor)(T); // +0xc
};

// SIZE 0x18
template <class T>
class MxList : protected MxListParent<T> {
public:
	MxList()
	{
		m_last = NULL;
		m_first = NULL;
	}

	virtual ~MxList();

	void Append(T);
	void OtherAppend(T p_obj) { _InsertEntry(p_obj, this->m_last, NULL); };
	void DeleteAll();
	MxU32 GetCount() { return this->m_count; }
	void SetDestroy(void (*p_customDestructor)(T)) { this->m_customDestructor = p_customDestructor; }

	friend class MxListCursor<T>;

protected:
	MxListEntry<T>* m_first; // +0x10
	MxListEntry<T>* m_last;  // +0x14

private:
	void _DeleteEntry(MxListEntry<T>* match);
	MxListEntry<T>* _InsertEntry(T, MxListEntry<T>*, MxListEntry<T>*);
};

template <class T>
class MxListCursor : public MxCore {
public:
	MxListCursor(MxList<T>* p_list)
	{
		m_list = p_list;
		m_match = NULL;
	}

	MxBool Find(T p_obj);
	void Detach();
	MxBool Next(T& p_obj);
	void SetValue(T p_obj);
	void Head() { m_match = m_list->m_first; }
	void Reset() { m_match = NULL; }

private:
	MxList<T>* m_list;
	MxListEntry<T>* m_match;
};

// Unclear purpose
template <class T>
class MxListCursorChild : public MxListCursor<T> {
public:
	MxListCursorChild(MxList<T>* p_list) : MxListCursor<T>(p_list) {}
};

// Unclear purpose
template <class T>
class MxListCursorChildChild : public MxListCursorChild<T> {
public:
	MxListCursorChildChild(MxList<T>* p_list) : MxListCursorChild<T>(p_list) {}
};

template <class T>
MxList<T>::~MxList()
{
	DeleteAll();
}

template <class T>
inline void MxList<T>::DeleteAll()
{
	for (MxListEntry<T>* t = m_first;;) {
		if (!t)
			break;

		MxListEntry<T>* next = t->m_next;
		this->m_customDestructor(t->GetValue());
		delete t;
		t = next;
	}

	this->m_count = 0;
	m_last = NULL;
	m_first = NULL;
}

template <class T>
inline void MxList<T>::Append(T p_newobj)
{
	MxListEntry<T>* currentLast = this->m_last;
	MxListEntry<T>* newEntry = new MxListEntry<T>(p_newobj, currentLast);

	if (currentLast)
		currentLast->m_next = newEntry;
	else
		this->m_first = newEntry;

	this->m_last = newEntry;
	this->m_count++;
}

template <class T>
inline MxListEntry<T>* MxList<T>::_InsertEntry(T p_newobj, MxListEntry<T>* p_prev, MxListEntry<T>* p_next)
{
	MxListEntry<T>* newEntry = new MxListEntry<T>(p_newobj, p_prev, p_next);

	if (p_prev)
		p_prev->m_next = newEntry;
	else
		this->m_first = newEntry;

	if (p_next)
		p_next->m_prev = newEntry;
	else
		this->m_last = newEntry;

	this->m_count++;
	return newEntry;
}

template <class T>
inline void MxList<T>::_DeleteEntry(MxListEntry<T>* match)
{
	MxListEntry<T>** pPrev = &match->m_prev;
	MxListEntry<T>** pNext = &match->m_next;

	if (match->m_prev)
		match->m_prev->m_next = *pNext;
	else
		m_first = *pNext;

	if (*pNext)
		(*pNext)->m_prev = *pPrev;
	else
		m_last = *pPrev;

	delete match;
	this->m_count--;
}

template <class T>
inline MxBool MxListCursor<T>::Find(T p_obj)
{
	for (m_match = m_list->m_first; m_match && m_list->Compare(m_match->m_obj, p_obj); m_match = m_match->m_next)
		;

	return m_match != NULL;
}

template <class T>
inline void MxListCursor<T>::Detach()
{
	m_list->_DeleteEntry(m_match);
	m_match = NULL;
}

template <class T>
inline MxBool MxListCursor<T>::Next(T& p_obj)
{
	if (!m_match)
		m_match = m_list->m_first;
	else
		m_match = m_match->m_next;

	if (m_match)
		p_obj = m_match->GetValue();

	return m_match != NULL;
}

template <class T>
inline void MxListCursor<T>::SetValue(T p_obj)
{
	if (m_match)
		m_match->m_obj = p_obj;
}

#endif // MXLIST_H
