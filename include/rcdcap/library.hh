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

#ifndef _RCDCAP_LIBRARY_HH_
#define _RCDCAP_LIBRARY_HH_

#include "rcdcap/global.hh"

#ifdef _WIN32
#   define WIN32_LEAN_AND_MEAN 1
#   include <windows.h>
#else
#   include <dlfcn.h>
#endif

#include <string>

namespace RCDCap
{

#ifdef _WIN32
    typedef HMODULE LibType;
#else
    typedef void* LibType;
#   define LoadLibrary(name) dlopen(name, RTLD_LAZY | RTLD_GLOBAL)
#   define GetProcAddress(lib, symb) dlsym(lib, symb)
#   define FreeLibrary(lib) dlclose(lib)
#   define GetError() dlerror()
#endif

//! A void function pointer type.
typedef void(*ProcType)(void);

//! Provides an interface for accessing dynamically loaded libraries.
class DLL_EXPORT Library
{
    //! A pointer to the object representing a dynamically loaded library.
    LibType m_Lib;
public:
    //! Default constructor.
    Library();
    
    /*! \brief Constructor.
     *  \param name     the name of the library that is going to be dynamically
     *                  loaded.
     */
    Library(const std::string& name);
    
    //! Destructor.
     ~Library();
    
    //! \warning Copy construction is forbidden by design.
    Library(const Library&)=delete;
    
    //! \warning Assignment is forbidden by design.
    Library& operator=(const Library&)=delete;

    //! Returns whether a dynamic library is actually loaded inside this object.
    bool loaded() const { return m_Lib != NULL; }
    
    //! Loads a dynamic library.
    bool load(const std::string& name);
    
    //! Unloads a dynamic library.
    void free();

    /*! \brief Returns a pointer to a function with the specified name inside the 
     *         dynamic library.
     *  \param name     the name of the function that must be found.
     *  \return on success returns a pointer to the function; otherwise, nullptr.
     */
    ProcType getProcAddress(const std::string& name);
};
}

#endif /* _RCDCAP_LIBRARY_HH_ */
