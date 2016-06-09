//  Copyright (c) 1997 Network Computing Technologies, Inc.
//  All rights reserved.
// 
//  Redistribution and use of executable software is never 
//  permitted without the express written permission of 
//  Network Computing Technologies, Inc.
// 
//  Distribution of the source is never permitted without 
//  the express written permission of 
//  Network Computing Technologies, Inc.
// 
//  THIS SOFTWARE IS PROVIDED "AS IS" AND WITHOUT ANY EXPRESS OR
//  IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
//  WARRANTIES OF MERCHANTIBILITY AND FITNESS FOR A PARTICULAR PURPOSE.


#ifndef __TRAPGENREGISTRY_H__
#define __TRAPGENREGISTRY_H__

#define KEY  HKEY_LOCAL_MACHINE
#define ROOT "SYSTEM\\CurrentControlSet\\Services\\SNMP\\Parameters\\TrapConfiguration"

class TrapGenRegistry
{


  private:

    HKEY           mKey;
    long           mR;
    char*          mNewKey;
    
    CString        GetRegSz(char* which);


  protected:



  public:

    TrapGenRegistry();
    ~TrapGenRegistry();

    void           ReOpen(char* which, BOOL add = FALSE);
    void           ReOpen(int which);

    unsigned long  getCount();

    CString        community();

    CString        ipAddress();

};
#endif



