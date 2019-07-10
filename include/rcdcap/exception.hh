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

#ifndef _RCDCAP_EXCEPTION_HH_
#define _RCDCAP_EXCEPTION_HH_

#include <exception>
#include <string>

namespace RCDCap
{
//! The exception type that is used by all RCDCap facilities.
class Exception: public std::exception
{
    std::string m_What; //!< The message that is being carried by the exception object.
public:
    /*! \brief Constructor.
     *  \param str  the message that must be carried by the exception object.
     */
    explicit Exception(const std::string& str) throw()
        :   m_What(str) {}
    //! Destructor.
    virtual ~Exception() throw() {}
    
    //! Returns the message that is being carried by the exception object.
    virtual const char* what() const throw()
    {
        return m_What.c_str();
    }
};
}

//! Convenience macro that helps out with structuring the message that is going to be carried by the exception object.
#define THROW_EXCEPTION(s) \
    throw RCDCap::Exception(__FILE__ ":" TO_STRING(__LINE__) ": " + (std::string)(s))

#endif /* _RCDCAP_EXCEPTION_HH_ */