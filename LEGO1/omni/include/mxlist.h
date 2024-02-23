#ifndef MXLIST_H
#define MXLIST_H

#include "mxcollection.h"
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
	MxListEntry* GetNext() { return m_next; }
	MxListEntry* GetPrev() { return m_prev; }

	void SetValue(T p_obj) { m_obj = p_obj; }
	void SetNext(MxListEntry* p_next) { m_next = p_next; }
	void SetPrev(MxListEntry* p_prev) { m_prev = p_prev; }

private:
	T m_obj;
	MxListEntry* m_prev;
	MxListEntry* m_next;
};

// SIZE 0x18
template <class T>
class MxList : protected MxCollection<T> {
public:
	MxList()
	{
		m_last = NULL;
		m_first = NULL;
	}

	~MxList() override;

	void Append(T p_obj) { InsertEntry(p_obj, this->m_last, NULL); }
	void Prepend(T p_obj) { InsertEntry(p_obj, NULL, this->m_first); }
	void DeleteAll(MxBool p_destroy = TRUE);
	MxU32 GetCount() { return this->m_count; }

	friend class MxListCursor<T>;
	using MxCollection<T>::SetDestroy;

protected:
	MxListEntry<T>* m_first; // 0x10
	MxListEntry<T>* m_last;  // 0x14

	void DeleteEntry(MxListEntry<T>*);
	MxListEntry<T>* InsertEntry(T, MxListEntry<T>*, MxListEntry<T>*);
};

// SIZE 0x18
template <class T>
class MxPtrList : public MxList<T*> {
public:
	MxPtrList(MxBool p_ownership) { SetOwnership(p_ownership); }

	static void Destroy(T* p_obj) { delete p_obj; }

	void SetOwnership(MxBool p_ownership)
	{
		MxCollection<T*>::SetDestroy(p_ownership ? MxPtrList<T>::Destroy : MxCollection<T*>::Destroy);
	}
};

// SIZE 0x10
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
	void Destroy();
	MxBool Next();
	MxBool Next(T& p_obj);
	MxBool Prev();
	MxBool Prev(T& p_obj);
	MxBool Current(T& p_obj);
	MxBool First(T& p_obj);
	MxBool Last(T& p_obj);
	MxBool HasMatch() { return m_match != NULL; }
	void SetValue(T p_obj);
	MxBool Head()
	{
		m_match = m_list->m_first;
		return m_match != NULL;
	}
	MxBool Tail()
	{
		m_match = m_list->m_last;
		return m_match != NULL;
	}
	void Reset() { m_match = NULL; }
	void Prepend(T p_newobj);

	// TODO: Probably shouldn't exist
	void NextFragment()
	{
		if (m_match) {
			m_match = m_match->GetNext();
		}
	}

private:
	MxList<T>* m_list;       // 0x08
	MxListEntry<T>* m_match; // 0x0c
};

// SIZE 0x10
template <class T>
class MxPtrListCursor : public MxListCursor<T*> {
public:
	MxPtrListCursor(MxPtrList<T>* p_list) : MxListCursor<T*>(p_list){};
};

template <class T>
MxList<T>::~MxList()
{
	DeleteAll();
}

template <class T>
inline void MxList<T>::DeleteAll(MxBool p_destroy)
{
	for (MxListEntry<T>* t = m_first;;) {
		if (!t) {
			break;
		}

		MxListEntry<T>* next = t->GetNext();

		if (p_destroy) {
			this->m_customDestructor(t->GetValue());
		}

		delete t;
		t = next;
	}

	this->m_count = 0;
	m_last = NULL;
	m_first = NULL;
}

template <class T>
inline MxListEntry<T>* MxList<T>::InsertEntry(T p_newobj, MxListEntry<T>* p_prev, MxListEntry<T>* p_next)
{
	MxListEntry<T>* newEntry = new MxListEntry<T>(p_newobj, p_prev, p_next);

	if (p_prev) {
		p_prev->SetNext(newEntry);
	}
	else {
		this->m_first = newEntry;
	}

	if (p_next) {
		p_next->SetPrev(newEntry);
	}
	else {
		this->m_last = newEntry;
	}

	this->m_count++;
	return newEntry;
}

template <class T>
inline void MxList<T>::DeleteEntry(MxListEntry<T>* p_match)
{
	if (p_match->GetPrev()) {
		p_match->GetPrev()->SetNext(p_match->GetNext());
	}
	else {
		m_first = p_match->GetNext();
	}

	if (p_match->GetNext()) {
		p_match->GetNext()->SetPrev(p_match->GetPrev());
	}
	else {
		m_last = p_match->GetPrev();
	}

	delete p_match;
	this->m_count--;
}

template <class T>
inline MxBool MxListCursor<T>::Find(T p_obj)
{
	for (m_match = m_list->m_first; m_match && m_list->Compare(m_match->GetValue(), p_obj);
		 m_match = m_match->GetNext()) {
		;
	}

	return m_match != NULL;
}

template <class T>
inline void MxListCursor<T>::Detach()
{
	if (m_match) {
		m_list->DeleteEntry(m_match);
		m_match = NULL;
	}
}

template <class T>
inline void MxListCursor<T>::Destroy()
{
	if (m_match) {
		m_list->m_customDestructor(m_match->GetValue());
		m_list->DeleteEntry(m_match);
		m_match = NULL;
	}
}

template <class T>
inline MxBool MxListCursor<T>::Next()
{
	if (!m_match) {
		m_match = m_list->m_first;
	}
	else {
		m_match = m_match->GetNext();
	}

	return m_match != NULL;
}

template <class T>
inline MxBool MxListCursor<T>::Next(T& p_obj)
{
	if (!m_match) {
		m_match = m_list->m_first;
	}
	else {
		m_match = m_match->GetNext();
	}

	if (m_match) {
		p_obj = m_match->GetValue();
	}

	return m_match != NULL;
}

template <class T>
inline MxBool MxListCursor<T>::Prev()
{
	if (!m_match) {
		m_match = m_list->m_last;
	}
	else {
		m_match = m_match->GetPrev();
	}

	return m_match != NULL;
}

template <class T>
inline MxBool MxListCursor<T>::Prev(T& p_obj)
{
	if (!m_match) {
		m_match = m_list->m_last;
	}
	else {
		m_match = m_match->GetPrev();
	}

	if (m_match) {
		p_obj = m_match->GetValue();
	}

	return m_match != NULL;
}

template <class T>
inline MxBool MxListCursor<T>::Current(T& p_obj)
{
	if (m_match) {
		p_obj = m_match->GetValue();
	}

	return m_match != NULL;
}

template <class T>
inline MxBool MxListCursor<T>::First(T& p_obj)
{
	m_match = m_list->m_first;
	if (m_match) {
		p_obj = m_match->GetValue();
	}

	return m_match != NULL;
}

template <class T>
inline MxBool MxListCursor<T>::Last(T& p_obj)
{
	m_match = m_list->m_last;
	if (m_match) {
		p_obj = m_match->GetValue();
	}

	return m_match != NULL;
}

template <class T>
inline void MxListCursor<T>::SetValue(T p_obj)
{
	if (m_match) {
		m_match->SetValue(p_obj);
	}
}

template <class T>
inline void MxListCursor<T>::Prepend(T p_newobj)
{
	if (m_match) {
		m_list->InsertEntry(p_newobj, m_match->GetPrev(), m_match);
	}
}

#endif // MXLIST_H
