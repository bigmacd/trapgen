
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



