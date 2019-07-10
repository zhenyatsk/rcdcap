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

#ifndef _RCDCAP_BYTE_ORDER_HH_
#define _RCDCAP_BYTE_ORDER_HH_

#include <cstring>
#include <cstdint>

#include "rcdcap/global.hh"
#include "rcdcap/byte-swap.hh"

namespace RCDCap
{
template<size_t... T> struct Sum;

/*! \brief Sums the parameters that were passed to the template.
 *  \tparam T       the last or the sole parameter in the list.
 */
template<size_t T>
struct Sum<T>
{
    static const size_t result = T; //!< The result of the operation.
};

/*! \brief Sums the parameters that were passed to the template.
 *  \tparam T       the parameters that are going to be summed.
 *  \tparam Tc      the current parameter from the list.
 */
template<size_t Tc, size_t... T>
struct Sum<Tc, T...>
{
    //! The result of the operation.
    static const size_t result = Tc + Sum<T...>::result;
};

template<size_t M, size_t N, size_t... TVal> struct SumMtoNTerm;

/*! \brief Sums the elements from M to N.
 * 
 *  It is used by SumN for doing the partial sum of the terms.
 *
 *  \tparam N       the number of the last term and for this case the current
 *                  element in the list.
 *  \tparam Tc      the value of the current element in the list.
 *  \tparam TVal    the values, starting from index M.
 */
template<size_t N, size_t Tc, size_t... TVal>
struct SumMtoNTerm<N, N, Tc, TVal...>
{
    static const size_t result = Tc; //!< The result of the operation.
};

/*! \brief Sums the elements from M to N.
 * 
 *  It is used by SumN for doing the partial sum of the terms.
 *
 *  \tparam N       the number of the last term.
 *  \tparam M       the number of the first term.
 *  \tparam Tc      the value of the current element in the list.
 *  \tparam TVal    the values, starting from index M.
 */
template<size_t M, size_t N, size_t Tc, size_t... TVal>
struct SumMtoNTerm<M, N, Tc, TVal...>
{
    //! The result of the operation.
    static const size_t result = Tc + SumMtoNTerm<M + 1, N, TVal...>::result;
};

/*! \brief Sums the first N elements from the list.
 *  \tparam N       the amount of elements that must be summed.
 *  \tparam TVal    the complete list of the values.
 */
template<size_t N, size_t... TVal>
struct SumN
{
    //! The result of the operation.
    static const size_t result = SumMtoNTerm<0, N, TVal...>::result;
};

template<size_t TcIdx, size_t TIndex, size_t... TSize> struct GetSizeOffset;

/*! \brief The class that contains the value that has been queried by GetSize.
 *  \note This template class specialization is for internal purposes. You
 *        should use GetSize instead.
 */
template<size_t TIndex, size_t TcSize, size_t... TSize>
struct GetSizeOffset<TIndex, TIndex, TcSize, TSize...>
{
    //! The value of parameter with the specified index in the list.
    static const size_t value = TcSize; 
};

/*! \brief Gets the size of the element with the specified index.
 *  \note This class is for internal purposes. You should use GetSize instead.
 * 
 *  Iterates through the values, that were passed, until it reaches the
 *  specified index and returns it as a static member variable, starting from
 *  the current index.
 *  \tparam TIndex  the index of the value that must be found in the list.
 *  \tparam TcIdx   the current index.
 *  \tparam TcSize  the size of the current element.
 *  \tparam TSize   the values after the value with the current index.
 */
template<size_t TcIdx, size_t TIndex, size_t TcSize, size_t... TSize>
struct GetSizeOffset<TcIdx, TIndex, TcSize, TSize...>
{
    //! The value of the parameter with the specified index in the list.
    static const size_t value = GetSizeOffset<TcIdx + 1,
                                              TIndex,  TSize...>::value;
};

/*! \brief Gets the size of the element with the specified index in the list.
 * 
 *  \tparam TIndex  the index of the value that must be found in the list.
 *  \tparam TSize   the values in the list.
 */
template<size_t TIndex, size_t... TSize>
struct GetSize
{
    //! The value of the element with the specified index.
    static const size_t value = GetSizeOffset<0, TIndex, TSize...>::value;
};

/*! \brief Used for specifying bit fields that must be arranged in a variable
 *         with the specified type in network byte order (big endian).
 *  \warning The total size of the bit fields must be equal to the size of the
 *           type that is used in bits.
 *  \tparam T       the specified type of variable in which the bit fields must
 *                  be arranged.
 *  \tparam TSize   the size of every individual bit field
 */
template<class T, size_t... TSize>
class NetworkByteOrderBitfield
{
    T   m_Value; //!< The variable in which the bit fields are arranged.
public:
    //! Constructor
    NetworkByteOrderBitfield();

    /*! \brief Gets the value of the specified bit field.
     *  \tparam TIdx    the index of the bit field.
     */
    template<size_t TIdx>
    T get() const
    {
        static const T  mask = (1 << GetSize<TIdx, TSize...>::value) - 1,
                        shift = sizeof(T)*8 - SumN<TIdx, TSize...>::result;
        T res = ByteSwap(m_Value);
        return (res >> shift) & mask;
    }

    /*! \brief Sets the value of the specified bit field to the one passed to
     *         this function.
     *  \tparam TIdx    the index of the bit field.
     *  \param t        the value that the bit field must be set to.
     */
    template<size_t TIdx>
    void set(T t)
    {
        static const T  shift = sizeof(T)*8 - SumN<TIdx, TSize...>::result,
                        pre_mask = ((1 << GetSize<TIdx, TSize...>::value) - 1),
                        mask = static_cast<T>(~(pre_mask << shift));
        T res = (ByteSwap(m_Value) & mask) | ((t & pre_mask) << shift);
        m_Value = ByteSwap(res);
    }
};

/*! \brief Used for specifying variables that must be stored in network byte
 *         order.
 *  \tparam T   the type of the variable.
 */
template<class T>
class DLL_EXPORT NetworkByteOrder
{
    T   m_Value; //!< The variable, stored in network byte order.
public:
    //! Default constructor.
    NetworkByteOrder();
    
    /*! \brief Constructor
     *  \param val  the initial value of the variable.
     */
    NetworkByteOrder(T val);
    
    /*! \brief Assigns the variable to specified value after converting it to 
     *         network byte order.
     *  \param val  the value to which the variable must be set to.
     */
    NetworkByteOrder& operator=(T val);

    //! Casts the variable to the host byte order.
    operator T() const;
};
}

#endif /* _RCDCAP_BYTE_ORDER_HH_ */
