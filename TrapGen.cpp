#include <iostream>
#include <fstream>
#include <stdio.h>
using namespace std;

#ifdef _WIN32
//#include <strstream>
#include "NtSysUpTime.h"
//#include <winsock.h>
#else

#if !defined(_SOLARIS)
#include <strstream>
#else
#include <strstream>
#endif

#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#define min(a, b) a < b ? a : b
#endif

#ifdef _LINUX
#include "LinuxSysUptime.h"
#endif

#ifdef _SOLARIS
#include "SolarisSysUpTime.h"
#endif

#ifdef _IRIX
#include "IrixSysUptime.h"
#endif

#ifdef _HPUX
#include "HpuxSysUpTime.h"
#endif

#ifdef _FREEBSD
#include "FreeBSDSysUptime.h"
#endif

#include "vbs.h"
#include "Packet.h"
#include "SnmpException.h"
#include "UdpClient.h"

#if !defined (_WIN32)
#define _strdup strdup
#endif

int  main(int argc, char** argv);
void CmdLineOpts(int argc, char** argv);
void FileOpts(char* filename);
void InitOption(char opt, 
		char* optionValue, 
		char* secondValue, 
		char* thirdValue);
void Usage();
int  Send();


Packet  gPacket;
char*   gIpAddress = NULL;
int     gPort = 162;
char*   gCommunity = "public";
char*   gSenderOID = "1.3.6.1.4.1.2854";
char*   gSenderIP = NULL;
int     gGenericTrapType = 6;
int     gSpecificTrapType = 1;
int     gTimeTicks = time(0);
int     gVersion = 0;
int     gInform = 0;
char    gDump = ' ';
int     gRequestId = time(0);
char*   gProgramVersion = "Version 2.93";
int     gTimeout = 5;
char*   gLogFileName = NULL;
BOOL    gDoLogging = FALSE;
#ifdef _WIN32
BOOL    gFreeConsole = FALSE;
int     width;
int     height;
int     topLeft;
int     topRight;
#endif
BOOL    gNoSubIds = FALSE;

ofstream gOfile;

int 
main(int argc, char** argv)
{

#ifdef _WIN32
  // save the size and other constraints
   char t[512];
   memset(t, 0, 512);
   GetConsoleTitle(t, 512);
   HWND h = FindWindow("ConsoleWindowClass", t);
   //  ShowWindow(h, SW_HIDE);
#endif   

  int retVal = 0;
  try
  {
    int limCount = min(argc, 4);
    for (int x = 1; x < limCount; x++) 
    {
      // check for an input file
      if (argv[x][0] == '-')
      {
	if (argv[x][1] == 'f' || argv[1][1] == 'F')
	  FileOpts(argv[x + 1]);
	else
	  // see if they need help
	  if (argv[x][1] == 'h')
	  {
#ifdef _WIN32
	    //	    ShowWindow(h, SW_SHOW);
#endif
	    Usage();
	    exit(0);
	  }
      }
      else
	// this is just for us
	if (!strcmp(argv[x], "dumpVer"))
	{
	  cout << "TrapGen from Network Computing Technologies, Inc.";
	  cout << endl << gProgramVersion << endl;
	  return 0;
	}
    } // for (int x = 1; x < limCount; x++) 

    // other command line arguments
    CmdLineOpts(argc, argv);

    if (gLogFileName != NULL)
    {
      gDoLogging = TRUE;
      gOfile.open(gLogFileName, ios::app);
    }

#ifdef _WIN32
    //    if (FALSE == gFreeConsole)
    //    {
    //      ShowWindow(h, SW_SHOW);
    if (TRUE == gFreeConsole)
    {
      ShowWindow(h, SW_HIDE);
    }
#endif


#ifdef _WIN32
    WSADATA wsaData;
    int err = WSAStartup(0x200, &wsaData);
    if (err == WSAVERNOTSUPPORTED)
      err = WSAStartup(0x101, &wsaData);
    if (gDoLogging)
      if (err)
	gOfile << "failed to initialize winsock, error is " << err << endl;
#endif

    ///////////////////////////////////////////////////
    // new to version 2.7
#ifdef _WIN32
    NtSysUpTime sysUpTime;
#endif
#ifdef _LINUX
    LinuxSysUpTime sysUpTime;
#endif
#ifdef _SOLARIS
    SolarisSysUpTime sysUpTime;
#endif
#ifdef _IRIX
    IrixSysUptime sysUpTime;
#endif
#ifdef _HPUX
    HpuxSysUpTime sysUpTime;
#endif
#ifdef _FREEBSD
    FreeBSDSysUptime sysUpTime;
#endif
    gTimeTicks = sysUpTime.SysUpTime();
    ///////////////////////////////////////////////////
    
    
    // figure out the ip address if not specified (V1 only)
    if (gSenderIP == NULL && gVersion == 0)
    {
      char buf[255];
      unsigned long len = 255;
      memset(buf, 0, len);
      if (gethostname(buf, len))
	if (gDoLogging)
	  gOfile << "gethostname failed with error " << WSAGetLastError() << endl;

      HOSTENT* h = gethostbyname(buf);
      if (h != NULL)
      {
	struct in_addr in;
	memcpy(&in.s_addr, *(h->h_addr_list), sizeof(in.s_addr));
	gSenderIP = inet_ntoa(in);
      }
      else
      {
	gSenderIP = "240.30.20.10";
	if (gDoLogging)
	  gOfile << "gethostbyname failed with error " << WSAGetLastError() << endl;
      }
    }

    // build the packet
    gPacket.Version(gVersion);
    gPacket.Community(gCommunity);
    if (gVersion == 0)
    {
      gPacket.Type(V1TRAP);
      gPacket.SenderOID(gSenderOID);
      gPacket.SenderIP(gSenderIP);
      gPacket.TimeTicks(gTimeTicks);
      gPacket.GenericTrapType(gGenericTrapType);
      gPacket.SpecificTrapType(gSpecificTrapType);
    }
    else
    {
      if (!gInform)
	gPacket.Type(V2TRAP);
      else
	gPacket.Type(INFORMPDU);

      gPacket.RequestId(gRequestId);
      gPacket.ErrorStatus(0);
      gPacket.ErrorIndex(0);
      gPacket.AddV2TrapVarbinds(gTimeTicks, 
				gSenderOID, 
				gGenericTrapType,
				gSpecificTrapType,
				gNoSubIds);
    }

    // send away
    retVal = Send();
    
  }
  catch (SnmpException* se)
  {
    retVal = -1;
  }
  catch (...)
  {
    retVal = -2;
  }

#ifdef _WIN32  
  WSACleanup();
#endif
  
  if (gDoLogging)
    gOfile.close();
  
  return retVal;
}

void
FileOpts(char* filename)
{
  ifstream    defaultsFile;
  char        lineBuf[1024];
  //  istrstream  lineStream(lineBuf, 1024);

//#if !defined (_HPUX) && !defined (_FREEBSD) && !defined (_WIN32) && !defined (_SOLARIS)
//  defaultsFile.open(filename, ios::in | ios::nocreate);
//#else
  defaultsFile.open(filename);
//#endif

  if (defaultsFile.good())
  {
    bool done = FALSE;
    while (!done)
    {
      memset(lineBuf, 0, 1024);
      defaultsFile.getline(lineBuf, 1023, '\n');
      if (defaultsFile.gcount() <= 0)
      {
	done = TRUE;
	continue;
      }

      char firstChar = lineBuf[0];
      if (firstChar != '-')
      {
	if (firstChar == 'v' || firstChar == 'V')
	{
	  if (lineBuf[1] == '2')
	    gVersion = 1;
	}
	else
	  if (!strcmp(lineBuf, "inform"))
	  {
	    gVersion = 1;
	    gInform = 1;
	  }
	continue;
      }
      else
	firstChar = lineBuf[1];

      char* lineIn = &lineBuf[2];
      lineBuf[ defaultsFile.gcount() ] = '\0';

      while (*lineIn == ' ')
	lineIn++;

      if (firstChar != 'v' && firstChar != 'V')
	InitOption(firstChar, lineIn, NULL, NULL);
      else
      {
	char* second = lineIn;
	char* third = NULL;
	char* forth = NULL;

	third = strchr(second, ' ');
	if (third != NULL)
	  *third++ = '\0';
	else
	  break;
	while (*third == ' ')
	  third++;
	
	forth = strchr(third, ' ');
	if (forth != NULL)
	  *forth++ = '\0';
	else
	  break;
	while (*forth == ' ')
	  forth++;
	InitOption(firstChar, second, third, forth);
      }
    } // while (defaultsFile.getline(lineBuf, 1023,'\n').good())
  } // if (defaultsFile.good())

  defaultsFile.close();
}

void 
CmdLineOpts(int argc, char** argv)
{
  char opt;
  for (int x = 1; (x + 1) <= argc; x++)
  {
    if (argv[x][0] == '-')
    {
      opt = argv[x][1];
      x++;
      if (opt == 'v' || opt == 'V')
      {
	InitOption(opt, argv[x], argv[x + 1], argv[x + 2]);
	x += 2;
      }
      else
      {
	InitOption(opt, argv[x], NULL, NULL);
      }
    }
    else
    {
      if (argv[x][0] == 'v' || argv[x][0] == 'V')
      {
	if (argv[x][1] == '2')
	  gVersion = 1;
      }
      else
	if (!strcmp(argv[x], "inform"))
	{
	  gVersion = 1;
	  gInform = 1;
	}
    }
  }
}

void
InitOption(char opt, 
   char* optionValue, 
   char* secondValue, 
   char* thirdValue)
{
  switch (opt)
  {
#ifdef _WIN32
    case 'z':
    case 'Z':
    {
      gFreeConsole = TRUE;
      break;
    }
#endif

    case 'x':
      gNoSubIds = TRUE;
      break;

    case 'd':
    case 'D':
    {
      char* colon = strchr(optionValue, ':');
      if (colon)
      {
	*colon++ = 0;
	gPort = atoi(colon);
      }
      gIpAddress = _strdup(optionValue);
      break;
    }
    
    case 'c':
    case 'C':
    {
      gCommunity = _strdup(optionValue);
      break;
    }
    
    case 'o':
    case 'O':
    {
      gSenderOID = _strdup(optionValue);
      break;
    }
    
    case 'i':
    case 'I':
    {
      gSenderIP = _strdup(optionValue);
      break;
    }

    case 'l':
    case 'L':
    {
      gLogFileName = _strdup(optionValue);
      break;
    }

    case 'm':
    case 'M':
    {
      gTimeout = atoi(optionValue);
      break;
    }
    
    case 'g':
    case 'G':
    {
      gGenericTrapType = atoi(optionValue);
      break;
    }
    
    case 'p':
    case 'P':
    {
      gDump = *optionValue;
      break;
    }

    case 'r':
    case 'R':
    {
      gRequestId = atoi(optionValue);
      break;
    }


    case 's':
    case 'S':
    {
      gSpecificTrapType = atoi(optionValue);
      break;
    }
    
    case 't':
    case 'T':
    {
      gTimeTicks = atoi(optionValue);
      break;
    }
    
    case 'v':
    case 'V':
    {
      OidVarbind* oid = new OidVarbind(optionValue);
      Varbind* vb;
      if (secondValue != NULL && thirdValue != NULL)
      {
	switch (secondValue[0])
	{
	  case 'S':
	  case 's':
	  {
	    vb = new StringVarbind(thirdValue);
	    break;
	  }
	  
	  case 'A':
	  case 'a':
	  {
	    vb = new IpAddrVarbind(thirdValue);
	    break;
	  }
  
  	  case 'O':
	  case 'o':
	  {
	    vb = new OidVarbind(thirdValue); 
	    break;
	  }
	  
	  case 'C':
	  case 'c':
	  {
	    vb = new CounterVarbind(atoi(thirdValue));
	    break;
	  }

	  case 'G':
	  case 'g':
	  {
	    vb = new GaugeVarbind(atoi(thirdValue));
	    break;
	  }

	  case 'H':
	  case 'h':
	  { 
	    vb = new StringVarbind(thirdValue, 0);
	    break;
	  }

	  case 'I':
	  case 'i':
	  {
	    vb = new IntVarbind(atoi(thirdValue));
	    break;
	  }

	  case 'T':
	  case 't':
	  { 
	    vb = new TimetickVarbind(atoi(thirdValue));
	    break;
	  }
	} // switch (argv[x+1])
	VbPair* vbp = new VbPair();                                 
	vbp->OIDVarbind(oid);
	vbp->VarBind(vb);
	//	gPacket->Add(vbp);
	gPacket.Add(vbp);
      } // if ((x + 1) < argc)
      break;
    }
  } // switch (opt)
}

int
Send()
{
  int retVal = 1;

  if (gIpAddress == NULL)
  {
    cout << "Must specify at least a -d \"destination IP Address\"" << endl;
    cout << "e.g., trapgen -d 244.0.2.43" << endl;
    return 0;
  }
    
  if (gDump == ' ')
  {
    UdpClient udp(gPort, gIpAddress);
    if (gDoLogging)
      if (!udp.IsReady())
	gOfile << "udp failed to initialize with error " << udp.ErrorCode() << endl;
    udp.Send(&gPacket);
    if (gInform)
    {
      udp.Timeout(gTimeout);
      Packet* p = udp.Receive(0);

      if (p != NULL && 
	  (p->RequestId() == gRequestId) && 
	  (p->Type() == V1RESPONSE))
	retVal = 0;
      else
	if (gDoLogging)
	  gOfile << "Sent INFORM but response timed out (timeout = " << gTimeout << ')' << endl;
    }
    else
      retVal = 0;
  }
  else
  {
    if (gDump == 'a' || gDump == 'b')
    {
      cout << "Length: " << gPacket.TotalLength() << endl;
      int version = gPacket.Version();
      cout << "Version: ";
      if (version == 0)
	cout << "SNMPv1";
      else
	if (version == 1)
	  cout << "SNMPv2";
      cout << endl;

      cout << "Community: " << gPacket. Community() << endl;

      if (version == 0)
      {
	cout << "Generic: " << gPacket.GenericTrapType() << endl;
	cout << "Specific: " << gPacket.SpecificTrapType() << endl;
	////////////////////////////////////////////////////////
	int tTime = gPacket.TimeTicks();
	tTime /= 100;
	int days = tTime/(60*60*24);
	tTime -= days * (60*60*24);
	int hrs = tTime/(60*60);
	tTime -= hrs*(60*60);
	int mins = tTime/(60);
	tTime -= mins*(60);
	char newcTime[128];
#ifdef _WIN32
	sprintf_s(newcTime, 128, "%d days %02dh:%02dm:%02ds", days, hrs, mins, tTime);
#else
	sprintf(newcTime, "%d days %02dh:%02dm:%02ds", days, hrs, mins, tTime);
#endif
	cout << "TimeStamp: " << newcTime << " (" << gPacket.TimeTicks() << ")" << endl;
	// cout << "TimeStamp: " << gPacket.TimeTicks() << endl;
	////////////////////////////////////////////////////////
	cout << "SenderIP: " << gPacket.SenderIP() << endl;
      }

      if (version == 0)
	cout << "SenderOID: " << gPacket.SenderOID() << endl;

      int vblen = gPacket.VbListLength();
      for (int x = 1; x <= vblen; x++)
      {
	cout << "Varbind Number " << x << ' ' << endl;
	cout << '\t' << "Oid: " << gPacket.VbOID(x) << endl;
	cout << '\t' << "Type: " << gPacket.VbType(x) << endl;
	cout << '\t' << "Data: " << gPacket.VbData(x) << endl;
      }
      cout << endl;
    }

    if (gDump == 'h' || gDump == 'b')
    {
      unsigned int l = gPacket.TotalLength();
      unsigned char* pdu = new unsigned char[l];
      gPacket.Build(pdu);
      for (unsigned int asdf = 0; asdf < l; asdf++)
      {
	if (asdf && !(asdf % 10))
	  printf("\n");
	printf("%02x ", pdu[asdf]);
      }
      printf("\n");
    }
  }
  return retVal;
}

void
Usage()
{
  cout << "TrapGen " << gProgramVersion << " options:" << endl;
  cout << "\t[v[1|2] | inform] - specifies the \"type\" of trap" << endl;
  cout << "\t-f <filename> - file containing command line parameters" << endl;
  cout << "\t-h - Output this help message" << endl;
  cout << "\t-c <community string>" << endl;
  cout << "\t-d <destinationIpOrHost[:portnumber]>" << endl;
  cout << "\t-v <varbind OID> <varbind type> <varbind data>" << endl;
  cout << "\t\t where <varbind type> is one of:" << endl;
  cout << "\t\t\tS|s - for string varbind" << endl;
  cout << "\t\t\tA|a - for Ip Address varbind" << endl;
  cout << "\t\t\tO|o - for OID varbind" << endl;
  cout << "\t\t\tC|c - for counter varbind" << endl;
  cout << "\t\t\tG|g - for gauge varbind" << endl;
  cout << "\t\t\tI|i - for integer varbind" << endl;
  cout << "\t\t\tT|t - for timetick varbind" << endl;
  cout << "\t\t\tH|h - for Octet varbind" << endl;
  cout << "\t-o <sender's OID>" << endl;
  cout << "\t-i <sender's IP address - V1 only>" << endl;
  cout << "\t-l <log file name>" << endl;
  cout << "\t-g <generic type>" << endl;
  cout << "\t-s <specific type>" << endl;
  cout << "\t-r <request Id> - for V2 or informs" << endl;
  cout << "\t-m <timeout> - for receiving inform response" << endl;
  cout << "\t-t <timestamp>" << endl;
  cout << "\t-p <a | h | b> - dump packet in (a) ascii, (h) hex, or (b) both" << endl;
  cout << "\t-x - suppress specific type sub-oid addition" << endl;
  cout << "\t-z to prevent a windows console window from appearing" << endl;
 
  cout << "Notes:" << endl;
  cout << "\tThe -p option does not send the packet, only displays it." << endl;
  cout << "\tConflicts like -i and V2 are ignored.  The objective is to get the trap out." << endl;
  cout << "\tCommand line options supercede options specified in the input file." << endl;
  cout << "\tThe following default values are used if not specified:" << endl;
  cout << "\t\tCommunity = public" << endl;
  cout << "\t\tportnumber = 162" << endl;
  cout << "\t\tsender's OID = 1.3.6.1.4.1.2854" << endl;
  cout << "\t\tgeneric type = 6" << endl;
  cout << "\t\tspecific type = 1" << endl;
  cout << "\t\ttimeticks = current system time (a la time(0))" << endl;
  cout << "\t\tversion = v1" << endl;
  cout << "\t\ttimeout = 5" << endl;
  cout << "\t\trequest id = time(0)" << endl << endl;
  cout << "TrapGen returns the following values:" << endl;
  cout << "\t-1 on an SNMP failure" << endl;
  cout << "\t-2 on a generic failure" << endl;
  cout << "\t1 on an inform response timeout" << endl;
  cout << "\t0 on a success" << endl;
  cout << "Use \"-l <logfilename>\" to capture errors and warnings encountered while trying to execute" << endl;

}

