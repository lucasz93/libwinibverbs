/*
 * Copyright (c) 2005 SilverStorm Technologies.  All rights reserved.
 *
 * This software is available to you under the OpenIB.org BSD license
 * below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 * $Id$
 */


#include <windows.h>
#include <ntverp.h>

#define VER_FILEVERSION            VER_FILEMAJORVERSION,\
                                VER_FILEMINORVERSION,\
                                0,\
                                VER_FILEREV

#define VER_FILEVERSION_STR2(M,m,r)    #M "." #m ".0." #r
#define VER_FILEVERSION_STR1(M,m,r)    VER_FILEVERSION_STR2(M,m,r)
#define VER_FILEVERSION_STR        VER_FILEVERSION_STR1( VER_FILEMAJORVERSION, \
                                                    VER_FILEMINORVERSION, \
                                                    VER_FILEREV )

#undef __BUILDMACHINE__

#ifdef VER_COMPANYNAME_STR
#undef VER_COMPANYNAME_STR
#endif
#define VER_COMPANYNAME_STR        IB_COMPANYNAME

#ifdef VER_PRODUCTNAME_STR
#undef VER_PRODUCTNAME_STR
#endif
#define VER_PRODUCTNAME_STR        IB_PRODUCTNAME

#define VER_LEGALCOPYRIGHT_STR    "Copyright\xa9 2013 OpenFabrics Alliance"

