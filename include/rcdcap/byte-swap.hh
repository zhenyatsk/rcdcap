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

#ifndef _RCDCAP_BYTE_SWAP_HH_
#define _RCDCAP_BYTE_SWAP_HH_

#include "rcdcap/global.hh"
#include "rcdcap/types.hh"

#include <cstring>
#include <xmmintrin.h>
#include <tmmintrin.h>

namespace RCDCap
{
template<size_t s> struct ByteSwapImpl;

//! The specialization for 8-bit variable.
template<>
struct ByteSwapImpl<1>
{
    //! The type which is used when swapping the bytes.
    typedef uint8 swap_type;

    //! Swaps the bytes in the variable and returns the result.
    inline static swap_type exec(swap_type x) { return x; } 
    
    //! Converts the value given to this function to the proper swappable type.
    template<class T>
    inline static swap_type convert(const T& val)
    {
        return reinterpret_cast<const swap_type&>(val);
    }
};

//! The specialization for 16-bit variable.
template<>
struct ByteSwapImpl<2>
{
    //! The type which is used when swapping the bytes.
    typedef uint16 swap_type;

    //! Swaps the bytes in the variable and returns the result.
    inline static swap_type exec(swap_type x)
    {
    #if BYTE_ORDER == LITTLE_ENDIAN
    //#   ifdef __GNUC__
    //   return __builtin_bswap16(x);
    //#   else
        return ((x >> 8) & 0x00FF) |
               ((x << 8) & 0xFF00);
    //#   endif
    #endif
    }
    
    //! Converts the value given to this function to the proper swappable type.
    template<class T>
    inline static swap_type convert(const T& val)
    {
        return reinterpret_cast<const swap_type&>(val);
    }
};

//! The specialization for 32-bit variable.
template<>
struct ByteSwapImpl<4>
{
    //! The type which is used when swapping the bytes.
    typedef uint32 swap_type;

    //! Swaps the bytes in the variable and returns the result.
    inline static swap_type exec(swap_type x)
    {
    #if BYTE_ORDER == LITTLE_ENDIAN
    #   ifdef __GNUC__
        return __builtin_bswap32(x);
    #   else
        return ((x >> 24) & 0x000000FF) |
               ((x >> 8)  & 0x0000FF00) |
               ((x << 8)  & 0x00FF0000) |
               ((x << 24) & 0xFF000000);
    #   endif
    #endif
    }
    
    //! Converts the value given to this function to the proper swappable type.
    template<class T>
    inline static swap_type convert(const T& val)
    {
        return reinterpret_cast<const swap_type&>(val);
    }
};

//! The specialization for 64-bit variable.
template<>
struct ByteSwapImpl<8>
{
    //! The type which is used when swapping the bytes.
    typedef uint64 swap_type;

    //! Swaps the bytes in the variable and returns the result.
    inline static swap_type exec(swap_type x)
    {
    #if BYTE_ORDER == LITTLE_ENDIAN
    #   ifdef __GNUC__
        return __builtin_bswap64(x);
    #   else
        return ((x >> 56) & 0x00000000000000FFLL) |
               ((x >> 40) & 0x000000000000FF00LL) |
               ((x >> 24) & 0x0000000000FF0000LL) |
               ((x >> 8)  & 0x00000000FF000000LL) |
               ((x << 8)  & 0x000000FF00000000LL) |
               ((x << 24) & 0x0000FF0000000000LL) |
               ((x << 40) & 0x00FF000000000000LL) |
               ((x << 56) & 0xFF00000000000000LL);
    #   endif
    #endif
    }
    
    //! Converts the value given to this function to the proper swappable type.
    template<class T>
    inline static swap_type convert(const T& val)
    {
        return reinterpret_cast<const swap_type&>(val);
    }
};

//! The specialization for 64-bit variable.
template<>
struct ByteSwapImpl<16>
{
    //! The type which is used when swapping the bytes.
    typedef __m128i swap_type;

    //! Swaps the bytes in the variable and returns the result.
    inline static swap_type exec(swap_type x)
    {
    #if BYTE_ORDER == LITTLE_ENDIAN
        __m128i mask = _mm_set_epi8(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
        return _mm_shuffle_epi8(x, mask);
    #endif
    }
    
    //! Converts the value given to this function to the proper swappable type.
    template<class T>
    inline static swap_type convert(const T& val)
    {
        return _mm_loadu_si128((__m128i*)&val);
    }
    
    //! Converts the value given to this function to the proper swappable type.
    static swap_type convert(const __m128i& val)
    {
        return val;
    }
};

/*! \brief Swaps the bytes in the variable and returns the result
 *  \tparam T   the type of the variable.
 *  \param  a   the variable, which bytes must be swapped.
 */
template<class T>
inline T ByteSwap(T a)
{
    typedef ByteSwapImpl<sizeof(T)>             byte_swap_impl;
    typedef typename byte_swap_impl::swap_type  swap_type;
    swap_type swap_val = byte_swap_impl::convert(a);
    swap_type swap_result = byte_swap_impl::exec(swap_val);
    return reinterpret_cast<T&>(swap_result);
}
}

#endif /* _RCDCAP_BYTE_SWAP_HH_ */