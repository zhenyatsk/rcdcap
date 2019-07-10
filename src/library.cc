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

#include "rcdcap/library.hh"
#include "rcdcap/exception.hh"
#include <cassert>

namespace RCDCap
{
Library::Library()
    :   m_Lib(0) {}

Library::Library(const std::string& name)
    :   m_Lib(LoadLibrary(name.c_str()))
{
    if(!m_Lib)
        THROW_EXCEPTION("could not load library: " + name);
}

Library::~Library()
{
    if(m_Lib)
        FreeLibrary(m_Lib);
}

bool Library::load(const std::string& name)
{
    this->free();
    m_Lib = LoadLibrary(name.c_str());
    return m_Lib != 0;
}

void Library::free()
{
    if(m_Lib)
        FreeLibrary(m_Lib);
    m_Lib = 0;
}

ProcType Library::getProcAddress(const std::string& str)
{
    if(!m_Lib)
        THROW_EXCEPTION("No library has been loaded");
    union
    {
        ProcType proc;
        void* symbol;
    } ptr;
#ifdef _WIN32
    ptr.proc = (ProcType)GetProcAddress(m_Lib, str.c_str());
#else
    ptr.symbol = GetProcAddress(m_Lib, str.c_str());
#endif
    return ptr.proc;
}
}