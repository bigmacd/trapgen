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
#include "TrapGenRegistry.h"
#endif

#include "errno.h"


TrapGenRegistry::TrapGenRegistry()
         :mNewKey(NULL),
	  mKey(NULL)
{
  mR = 
    RegOpenKeyEx(KEY,
		 mNewKey,
		 (DWORD)0, 
		 KEY_ALL_ACCESS,
		 &mKey);

}

TrapGenRegistry::~TrapGenRegistry()
{
  if (mNewKey)
    delete [] mNewKey;
  RegCloseKey(mKey);
}

void
Registry::ReOpen(char* which, BOOL add)
{  
  int size = 0;
  if (add && mNewKey)
    size = strlen(mNewKey) + 1;
  else
    size = strlen(ROOT) + 1;

  if (which != NULL)
    size += (strlen(which) + 1);

  char* tempKey = NULL;
  if (add && mNewKey)
  {
    tempKey = new char [strlen(mNewKey) + 1];
    strcpy(tempKey, mNewKey);
  }

  if (mNewKey)
    delete [] mNewKey;

  mNewKey = new char [size];
  memset(mNewKey, 0, size);

  if (add && tempKey)
    strcpy(mNewKey, tempKey);
  else
    strcpy(mNewKey, ROOT);

  if (add && tempKey)
    delete [] tempKey;

  if (which != NULL)
  {
    strcat(mNewKey, "\\");
    strcat(mNewKey, which);
  }

  if (mKey)
  {
    RegCloseKey(mKey);
    mKey = NULL;
  }

  mR = 
    RegOpenKeyEx(KEY,
		 mNewKey,
		 (DWORD)0, 
		 KEY_ALL_ACCESS,
		 &mKey);
}

void
Registry::ReOpen(int which)
{
  CString number;
  CString format;
  CString leafKey;

  number = "\\";
  format.Format("%d", which);
  number += format;

  leafKey = mNewKey;
  leafKey += number;

  RegCloseKey(mKey);
  mKey = NULL;

  mR = 
    RegOpenKeyEx(KEY,
		 leafKey,
		 (DWORD)0, 
		 KEY_ALL_ACCESS,
		 &mKey);

  if (mR == ENOENT && mCreateFlag == TRUE)
  {
    DWORD dwDisp;
    
    mR = 
      RegCreateKeyEx(KEY,
		     leafKey,
		     (DWORD)0,
		     NULL,
		     REG_OPTION_NON_VOLATILE,
		     KEY_ALL_ACCESS,
		     NULL,
		     &mKey,
		     &dwDisp);  
  }
}

CString
Registry::GetRegSz(char* which)
{
  DWORD dwSize = 128;
  char buf[128];
  memset(buf, 0, 128);
  unsigned long type = REG_SZ;
  mR = 
  RegQueryValueEx(mKey, 
		  which,
		  (DWORD*)0,
		  &type,
		  (unsigned char*)&buf,
		  &dwSize);
  if (mR != ERROR_SUCCESS)
    throw(0);
  CString retVal = buf;
  return retVal;
}

CString        
Registry::community()
{
  return GetRegSz("");
}

CString        
Registry::ipAddress()
{
  return GetRegSz("");
}

unsigned long
Registry::getCount()
{
  unsigned long count = 0;
  mR = RegQueryInfoKey(mKey,
		       NULL,
		       NULL,
		       NULL,
		       &count,
		       NULL,
		       NULL,
		       NULL,
		       NULL,
		       NULL,
		       NULL,
		       NULL);
  return count;
}

BOOL           
Registry::find(int     inWatch, 
	       CString inValue, 
	       int& index)
{
  BOOL retVal = FALSE;
  ReOpen("Actions");
  unsigned long count = getCount();

  for (index = 0; index < (int)count;)
  {
    try 
    {
      ReOpen("Actions");
      char name[256];
      LONG result = RegEnumKey(mKey,
			       (unsigned long)index++,
			       name,
			       256);
      if (result == ERROR_SUCCESS)
      {
	ReOpen(name, TRUE);
	int alreadyWatch = watch();
	CString alreadyValue = value();
	if (inWatch == alreadyWatch && 
	    inValue == alreadyValue)
	{
	  retVal = TRUE;
	  break;
	}
      }
    }
    catch(...)
    {
    }
  }
  return retVal;
}

CString
Registry::IndexToName(int which)
{
  char name[256];
  memset(name, 0, 256);
  LONG result = RegEnumKey(mKey,
			   which,
			   name,
			   256);
  CString retVal = name;
  return retVal;
}


