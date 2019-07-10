/*   RCDCap
 *   Copyright (C) 2012  Zdravko Velinov
 *
 *   This program is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 3 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef _RCDCAP_MEMORY_HH_
#define _RCDCAP_MEMORY_HH_

#include <memory>

#ifdef _WIN32
#   ifdef __MINGW32__
#       define _aligned_malloc __mingw_aligned_malloc
#       define _aligned_free __mingw_aligned_free
#   endif
#   include <malloc.h>
#   define RCDCAP_ALIGNED_ALLOC(ptr, nbytes, align) ptr = _aligned_malloc(nbytes, align)
#   define RCDCAP_ALIGNED_DEALLOC(ptr) _aligned_free(ptr)
#else
#   include <stdlib.h>
#   define  RCDCAP_ALIGNED_ALLOC(ptr, nbytes, align) if(posix_memalign(&ptr, align, nbytes)) ptr = 0;
#   define  RCDCAP_ALIGNED_DEALLOC(ptr) free(ptr)
#endif

namespace RCDCap
{
//! Returns next multiple of base.
inline size_t round(size_t n, size_t base)
{
    return ((n + base - 1)/base)*base;
}

/*! An aligned memory object allocator.
 *  \tparam T           the type of the object.
 *  \tparam alignment   the requested memory alignment.
 */
template<class T, int aligment>
struct ObjectAllocator
{
    //! Allocates enough memory to fit the object.
    static inline T* allocate()
    {
        void* ptr;
        RCDCAP_ALIGNED_ALLOC(ptr, sizeof(T), aligment);
        return reinterpret_cast<T*>(ptr);
    }

    //! Deallocates the already allocated memory.
    static inline void deallocate(T* ptr)
    {
        ptr->~T();
        RCDCAP_ALIGNED_DEALLOC(ptr);
    }
};

/*! \brief Deallocates an object aligned in the memory.
 *  \tparam T   the type of the object.
 */
template<class T>
struct AlignedDeleter
{
    //! Deallocates the memory.
    void operator()(T* p)
    {
        RCDCAP_ALIGNED_DEALLOC(p);
    }
};

template<typename T, typename... TArgs>
inline std::unique_ptr<T> make_unique(TArgs&&... args)
{
    return std::unique_ptr<T>(new T(std::forward<TArgs>(args)...));
}
}

#endif /* _RCDCAP_MEMORY_HH_ */