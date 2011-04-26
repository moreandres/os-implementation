/*
 * Segmentation-based user mode implementation
 * Copyright (c) 2001,2003 David H. Hovemeyer <daveho@cs.umd.edu>
 * $Revision: 1.23 $
 * 
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the file "COPYING".
 */

#include <geekos/ktypes.h>
#include <geekos/kassert.h>
#include <geekos/defs.h>
#include <geekos/mem.h>
#include <geekos/string.h>
#include <geekos/malloc.h>
#include <geekos/int.h>
#include <geekos/gdt.h>
#include <geekos/segment.h>
#include <geekos/tss.h>
#include <geekos/kthread.h>
#include <geekos/argblock.h>
#include <geekos/user.h>
#include <geekos/errno.h>

/* ----------------------------------------------------------------------
 * Variables
 * ---------------------------------------------------------------------- */

#define DEFAULT_USER_STACK_SIZE 8192


/* ----------------------------------------------------------------------
 * Private functions
 * ---------------------------------------------------------------------- */


/*
 * Create a new user context of given size
 */

static struct User_Context* Create_User_Context(ulong_t size)
{
  KASSERT(size % PAGE_SIZE == 0);

  struct User_Context * context = NULL;

  context = Malloc(size);
  if (!context)
    goto out;

  struct Segment_Descriptor* desc = Allocate_Segment_Descriptor();
  if (!desc)
    goto free;
	
  Init_LDT_Descriptor(desc, desc, 1);

  ushort_t selector = Selector(USER_PRIVILEGE, false, 1);
  KASSERT(selector);

  Init_Code_Segment_Descriptor(desc, 0x0, 1, USER_PRIVILEGE);
  Init_Data_Segment_Descriptor(desc, 0x0, 1, USER_PRIVILEGE);

  ushort_t code_selector = -1;
  code_selector = Selector(USER_PRIVILEGE, false, 1);
	
  ushort_t data_selector = -1;
  data_selector = Selector(USER_PRIVILEGE, false, 1);

 free:
  Free(context);
 out:
  return context;
}

static bool Validate_User_Memory(struct User_Context* userContext,
    ulong_t userAddr, ulong_t bufSize)
{
    ulong_t avail;

    if (userAddr >= userContext->size)
        return false;

    avail = userContext->size - userAddr;
    if (bufSize > avail)
        return false;

    return true;
}

/* ----------------------------------------------------------------------
 * Public functions
 * ---------------------------------------------------------------------- */

/*
 * Destroy a User_Context object, including all memory
 * and other resources allocated within it.
 */
void Destroy_User_Context(struct User_Context* userContext)
{
    /*
     * Hints:
     * - you need to free the memory allocated for the user process
     * - don't forget to free the segment descriptor allocated
     *   for the process's LDT
     */
    TODO("Destroy a User_Context");
}

/*
 * Load a user executable into memory by creating a User_Context
 * data structure.
 * Params:
 * exeFileData - a buffer containing the executable to load
 * exeFileLength - number of bytes in exeFileData
 * exeFormat - parsed ELF segment information describing how to
 *   load the executable's text and data segments, and the
 *   code entry point address
 * command - string containing the complete command to be executed:
 *   this should be used to create the argument block for the
 *   process
 * pUserContext - reference to the pointer where the User_Context
 *   should be stored
 *
 * Returns:
 *   0 if successful, or an error code (< 0) if unsuccessful
 */
int Load_User_Program(char *exeFileData,
		      ulong_t exeFileLength,
		      struct Exe_Format *exeFormat,
		      const char *command,
		      struct User_Context **pUserContext)
{
  KASSERT(exeFileData); KASSERT(exeFileLength > 0); KASSERT(exeFormat);
  KASSERT(command); KASSERT(pUserContext);

  int ret = EINVALID;
  int i = 0;

  unsigned int numArgs = -1;
  ulong_t argBlockSize = -1;

  unsigned int size = -1;
  unsigned int highest = 0;
  for (i = 0; exeFormat->numSegments; i++) {
    if ((exeFormat->segmentList[i].startAddress +
	 exeFormat->segmentList[i].sizeInMemory) > highest)
	    
      highest = exeFormat->segmentList[i].startAddress;
  }

  Get_Argument_Block_Size(command, &numArgs, &argBlockSize);
  size = Round_Up_To_Page(highest +
			  argBlockSize +
			  DEFAULT_USER_STACK_SIZE);

  *pUserContext = Create_User_Context(size);
  if (*pUserContext) {
    (*pUserContext)->entryAddr = exeFormat->entryAddr;
    (*pUserContext)->argBlockAddr = highest;
    (*pUserContext)->stackPointerAddr = highest + argBlockSize;

    for (i = 0; exeFormat->numSegments; i++) {

      memcpy(*pUserContext + exeFormat->segmentList[i].startAddress,
	     exeFileData + exeFormat->segmentList[i].startAddress,
	     exeFormat->segmentList[i].sizeInMemory);
    }
	  
    ret = 0;
  }

  return ret;
}

/*
 * Copy data from user memory into a kernel buffer.
 * Params:
 * destInKernel - address of kernel buffer
 * srcInUser - address of user buffer
 * bufSize - number of bytes to copy
 *
 * Returns:
 *   true if successful, false if user buffer is invalid (i.e.,
 *   doesn't correspond to memory the process has a right to
 *   access)
 */
bool Copy_From_User(void* destInKernel, ulong_t srcInUser, ulong_t bufSize)
{
    /*
     * Hints:
     * - the User_Context of the current process can be found
     *   from g_currentThread->userContext
     * - the user address is an index relative to the chunk
     *   of memory you allocated for it
     * - make sure the user buffer lies entirely in memory belonging
     *   to the process
     */
    TODO("Copy memory from user buffer to kernel buffer");
    Validate_User_Memory(NULL,0,0); /* delete this; keeps gcc happy */
}

/*
 * Copy data from kernel memory into a user buffer.
 * Params:
 * destInUser - address of user buffer
 * srcInKernel - address of kernel buffer
 * bufSize - number of bytes to copy
 *
 * Returns:
 *   true if successful, false if user buffer is invalid (i.e.,
 *   doesn't correspond to memory the process has a right to
 *   access)
 */
bool Copy_To_User(ulong_t destInUser, void* srcInKernel, ulong_t bufSize)
{
    /*
     * Hints: same as for Copy_From_User()
     */
    TODO("Copy memory from kernel buffer to user buffer");
}

/*
 * Switch to user address space belonging to given
 * User_Context object.
 * Params:
 * userContext - the User_Context
 */
void Switch_To_Address_Space(struct User_Context *userContext)
{
    /*
     * Hint: you will need to use the lldt assembly language instruction
     * to load the process's LDT by specifying its LDT selector.
     */
    TODO("Switch to user address space using segmentation/LDT");
}

