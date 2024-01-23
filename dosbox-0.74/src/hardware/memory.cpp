/*
 *  Copyright (C) 2002-2010  The DOSBox Team
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

/* $Id: memory.cpp,v 1.56 2009-05-27 09:15:41 qbix79 Exp $ */

#include "dosbox.h"
#include "mem.h"
#include "inout.h"
#include "setup.h"
#include "paging.h"
#include "regs.h"

#include <string.h>

#define PAGES_IN_BLOCK	((1024*1024)/MEM_PAGE_SIZE)
#define SAFE_MEMORY	32
#define MAX_MEMORY	64
#define MAX_PAGE_ENTRIES (MAX_MEMORY*1024*1024/4096)
#define LFB_PAGES	512
#define MAX_LINKS	((MAX_MEMORY*1024/4)+4096)		//Hopefully enough

struct LinkBlock {
	Bitu used;
	Bit32u pages[MAX_LINKS];
};

static struct MemoryBlock {
	Bitu pages;
	PageHandler * * phandlers;
	MemHandle * mhandles;
	LinkBlock links;
	struct	{
		Bitu		start_page;
		Bitu		end_page;
		Bitu		pages;
		PageHandler *handler;
		PageHandler *mmiohandler;
	} lfb;
	struct {
		bool enabled;
		Bit8u controlport;
	} a20;
} memory;

HostPt MemBase;

class IllegalPageHandler : public PageHandler {
public:
	IllegalPageHandler() {
		flags=PFLAG_INIT|PFLAG_NOCODE;
	}
	Bitu readb(PhysPt addr) {
#if C_DEBUG
		LOG_MSG("Illegal read from %x, CS:IP %8x:%8x",addr,SegValue(cs),reg_eip);
#else
		static Bits lcount=0;
		if (lcount<1000) {
			lcount++;
			LOG_MSG("Illegal read from %x, CS:IP %8x:%8x",addr,SegValue(cs),reg_eip);
		}
#endif
		return 0;
	} 
	void writeb(PhysPt addr,Bitu val) {
#if C_DEBUG
		LOG_MSG("Illegal write to %x, CS:IP %8x:%8x",addr,SegValue(cs),reg_eip);
#else
		static Bits lcount=0;
		if (lcount<1000) {
			lcount++;
			LOG_MSG("Illegal write to %x, CS:IP %8x:%8x",addr,SegValue(cs),reg_eip);
		}
#endif
	}
};

class RAMPageHandler : public PageHandler {
public:
	RAMPageHandler() {
		flags=PFLAG_READABLE|PFLAG_WRITEABLE;
	}
	HostPt GetHostReadPt(Bitu phys_page) {
		return MemBase+phys_page*MEM_PAGESIZE;
	}
	HostPt GetHostWritePt(Bitu phys_page) {
		return MemBase+phys_page*MEM_PAGESIZE;
	}
};

class ROMPageHandler : public RAMPageHandler {
public:
	ROMPageHandler() {
		flags=PFLAG_READABLE|PFLAG_HASROM;
	}
	void writeb(PhysPt addr,Bitu val){
		LOG(LOG_CPU,LOG_ERROR)("Write %x to rom at %x",val,addr);
	}
	void writew(PhysPt addr,Bitu val){
		LOG(LOG_CPU,LOG_ERROR)("Write %x to rom at %x",val,addr);
	}
	void writed(PhysPt addr,Bitu val){
		LOG(LOG_CPU,LOG_ERROR)("Write %x to rom at %x",val,addr);
	}
};



static IllegalPageHandler illegal_page_handler;
static RAMPageHandler ram_page_handler;
static ROMPageHandler rom_page_handler;

void MEM_SetLFB(Bitu page, Bitu pages, PageHandler *handler, PageHandler *mmiohandler) {
	memory.lfb.handler=handler;
	memory.lfb.mmiohandler=mmiohandler;
	memory.lfb.start_page=page;
	memory.lfb.end_page=page+pages;
	memory.lfb.pages=pages;
	PAGING_ClearTLB();
}

PageHandler * MEM_GetPageHandler(Bitu phys_page) {
	if (phys_page<memory.pages) {
		return memory.phandlers[phys_page];
	} else if ((phys_page>=memory.lfb.start_page) && (phys_page<memory.lfb.end_page)) {
		return memory.lfb.handler;
	} else if ((phys_page>=memory.lfb.start_page+0x01000000/4096) &&
				(phys_page<memory.lfb.start_page+0x01000000/4096+16)) {
		return memory.lfb.mmiohandler;
	}
	return &illegal_page_handler;
}

void MEM_SetPageHandler(Bitu phys_page,Bitu pages,PageHandler * handler) {
	for (;pages>0;pages--) {
		memory.phandlers[phys_page]=handler;
		phys_page++;
	}
}

void MEM_ResetPageHandler(Bitu phys_page, Bitu pages) {
	for (;pages>0;pages--) {
		memory.phandlers[phys_page]=&ram_page_handler;
		phys_page++;
	}
}

Bitu mem_strlen(PhysPt pt) {
	Bitu x=0;
	while (x<1024) {
		if (!mem_readb_inline(pt+x)) return x;
		x++;
	}
	return 0;		//Hope this doesn't happen
}

void mem_strcpy(PhysPt dest,PhysPt src) {
	Bit8u r;
	while ( (r = mem_readb(src++)) ) mem_writeb_inline(dest++,r);
	mem_writeb_inline(dest,0);
}

void mem_memcpy(PhysPt dest,PhysPt src,Bitu size) {
	while (size--) mem_writeb_inline(dest++,mem_readb_inline(src++));
}

void MEM_BlockRead(PhysPt pt,void * data,Bitu size) {
	Bit8u * write=reinterpret_cast<Bit8u *>(data);
	while (size--) {
		*write++=mem_readb_inline(pt++);
	}
}

void MEM_BlockWrite(PhysPt pt,void const * const data,Bitu size) {
	Bit8u const * read = reinterpret_cast<Bit8u const * const>(data);
	while (size--) {
		mem_writeb_inline(pt++,*read++);
	}
}

void MEM_BlockCopy(PhysPt dest,PhysPt src,Bitu size) {
	mem_memcpy(dest,src,size);
}

void MEM_StrCopy(PhysPt pt,char * data,Bitu size) {
	while (size--) {
		Bit8u r=mem_readb_inline(pt++);
		if (!r) break;
		*data++=r;
	}
	*data=0;
}

Bitu MEM_TotalPages(void) {
	return memory.pages;
}

Bitu MEM_FreeLargest(void) {
	Bitu size=0;Bitu largest=0;
	Bitu index=XMS_START;	
	while (index<memory.pages) {
		if (!memory.mhandles[index]) {
			size++;
		} else {
			if (size>largest) largest=size;
			size=0;
		}
		index++;
	}
	if (size>largest) largest=size;
	return largest;
}

Bitu MEM_FreeTotal(void) {
	Bitu free=0;
	Bitu index=XMS_START;	
	while (index<memory.pages) {
		if (!memory.mhandles[index]) free++;
		index++;
	}
	return free;
}

Bitu MEM_AllocatedPages(MemHandle handle) 
{
	Bitu pages = 0;
	while (handle>0) {
		pages++;
		handle=memory.mhandles[handle];
	}
	return pages;
}

//TODO Maybe some protection for this whole allocation scheme

INLINE Bitu BestMatch(Bitu size) {
	Bitu index=XMS_START;	
	Bitu first=0;
	Bitu best=0xfffffff;
	Bitu best_first=0;
	while (index<memory.pages) {
		/* Check if we are searching for first free page */
		if (!first) {
			/* Check if this is a free page */
			if (!memory.mhandles[index]) {
				first=index;	
			}
		} else {
			/* Check if this still is used page */
			if (memory.mhandles[index]) {
				Bitu pages=index-first;
				if (pages==size) {
					return first;
				} else if (pages>size) {
					if (pages<best) {
						best=pages;
						best_first=first;
					}
				}
				first=0;			//Always reset for new search
			}
		}
		index++;
	}
	/* Check for the final block if we can */
	if (first && (index-first>=size) && (index-first<best)) {
		return first;
	}
	return best_first;
}

MemHandle MEM_AllocatePages(Bitu pages,bool sequence) {
	MemHandle ret;
	if (!pages) return 0;
	if (sequence) {
		Bitu index=BestMatch(pages);
		if (!index) return 0;
		MemHandle * next=&ret;
		while (pages) {
			*next=index;
			next=&memory.mhandles[index];
			index++;pages--;
		}
		*next=-1;
	} else {
		if (MEM_FreeTotal()<pages) return 0;
		MemHandle * next=&ret;
		while (pages) {
			Bitu index=BestMatch(1);
			if (!index) E_Exit("MEM:corruption during allocate");
			while (pages && (!memory.mhandles[index])) {
				*next=index;
				next=&memory.mhandles[index];
				index++;pages--;
			}
			*next=-1;		//Invalidate it in case we need another match
		}
	}
	return ret;
}

MemHandle MEM_GetNextFreePage(void) {
	return (MemHandle)BestMatch(1);
}

void MEM_ReleasePages(MemHandle handle) {
	while (handle>0) {
		MemHandle next=memory.mhandles[handle];
		memory.mhandles[handle]=0;
		handle=next;
	}
}

bool MEM_ReAllocatePages(MemHandle & handle,Bitu pages,bool sequence) {
	if (handle<=0) {
		if (!pages) return true;
		handle=MEM_AllocatePages(pages,sequence);
		return (handle>0);
	}
	if (!pages) {
		MEM_ReleasePages(handle);
		handle=-1;
		return true;
	}
	MemHandle index=handle;
	MemHandle last;Bitu old_pages=0;
	while (index>0) {
		old_pages++;
		last=index;
		index=memory.mhandles[index];
	}
	if (old_pages == pages) return true;
	if (old_pages > pages) {
		/* Decrease size */
		pages--;index=handle;old_pages--;
		while (pages) {
			index=memory.mhandles[index];
			pages--;old_pages--;
		}
		MemHandle next=memory.mhandles[index];
		memory.mhandles[index]=-1;
		index=next;
		while (old_pages) {
			next=memory.mhandles[index];
			memory.mhandles[index]=0;
			index=next;
			old_pages--;
		}
		return true;
	} else {
		/* Increase size, check for enough free space */
		Bitu need=pages-old_pages;
		if (sequence) {
			index=last+1;
			Bitu free=0;
			while ((index<(MemHandle)memory.pages) && !memory.mhandles[index]) {
				index++;free++;
			}
			if (free>=need) {
				/* Enough space allocate more pages */
				index=last;
				while (need) {
					memory.mhandles[index]=index+1;
					need--;index++;
				}
				memory.mhandles[index]=-1;
				return true;
			} else {
				/* Not Enough space allocate new block and copy */
				MemHandle newhandle=MEM_AllocatePages(pages,true);
				if (!newhandle) return false;
				MEM_BlockCopy(newhandle*4096,handle*4096,old_pages*4096);
				MEM_ReleasePages(handle);
				handle=newhandle;
				return true;
			}
		} else {
			MemHandle rem=MEM_AllocatePages(need,false);
			if (!rem) return false;
			memory.mhandles[last]=rem;
			return true;
		}
	}
	return 0;
}

MemHandle MEM_NextHandle(MemHandle handle) {
	return memory.mhandles[handle];
}

MemHandle MEM_NextHandleAt(MemHandle handle,Bitu where) {
	while (where) {
		where--;	
		handle=memory.mhandles[handle];
	}
	return handle;
}


/* 
	A20 line handling, 
	Basically maps the 4 pages at the 1mb to 0mb in the default page directory
*/
bool MEM_A20_Enabled(void) {
	return memory.a20.enabled;
}

void MEM_A20_Enable(bool enabled) {
	Bitu phys_base=enabled ? (1024/4) : 0;
	for (Bitu i=0;i<16;i++) PAGING_MapPage((1024/4)+i,phys_base+i);
	memory.a20.enabled=enabled;
}


/* Memory access functions */
Bit16u mem_unalignedreadw(PhysPt address) {
	return mem_readb_inline(address) |
		mem_readb_inline(address+1) << 8;
}

Bit32u mem_unalignedreadd(PhysPt address) {
	return mem_readb_inline(address) |
		(mem_readb_inline(address+1) << 8) |
		(mem_readb_inline(address+2) << 16) |
		(mem_readb_inline(address+3) << 24);
}


void mem_unalignedwritew(PhysPt address,Bit16u val) {
	mem_writeb_inline(address,(Bit8u)val);val>>=8;
	mem_writeb_inline(address+1,(Bit8u)val);
}

void mem_unalignedwrited(PhysPt address,Bit32u val) {
	mem_writeb_inline(address,(Bit8u)val);val>>=8;
	mem_writeb_inline(address+1,(Bit8u)val);val>>=8;
	mem_writeb_inline(address+2,(Bit8u)val);val>>=8;
	mem_writeb_inline(address+3,(Bit8u)val);
}


bool mem_unalignedreadw_checked(PhysPt address, Bit16u * val) {
	Bit8u rval1,rval2;
	if (mem_readb_checked(address+0, &rval1)) return true;
	if (mem_readb_checked(address+1, &rval2)) return true;
	*val=(Bit16u)(((Bit8u)rval1) | (((Bit8u)rval2) << 8));
	return false;
}

bool mem_unalignedreadd_checked(PhysPt address, Bit32u * val) {
	Bit8u rval1,rval2,rval3,rval4;
	if (mem_readb_checked(address+0, &rval1)) return true;
	if (mem_readb_checked(address+1, &rval2)) return true;
	if (mem_readb_checked(address+2, &rval3)) return true;
	if (mem_readb_checked(address+3, &rval4)) return true;
	*val=(Bit32u)(((Bit8u)rval1) | (((Bit8u)rval2) << 8) | (((Bit8u)rval3) << 16) | (((Bit8u)rval4) << 24));
	return false;
}

bool mem_unalignedwritew_checked(PhysPt address,Bit16u val) {
	if (mem_writeb_checked(address,(Bit8u)(val & 0xff))) return true;val>>=8;
	if (mem_writeb_checked(address+1,(Bit8u)(val & 0xff))) return true;
	return false;
}

bool mem_unalignedwrited_checked(PhysPt address,Bit32u val) {
	if (mem_writeb_checked(address,(Bit8u)(val & 0xff))) return true;val>>=8;
	if (mem_writeb_checked(address+1,(Bit8u)(val & 0xff))) return true;val>>=8;
	if (mem_writeb_checked(address+2,(Bit8u)(val & 0xff))) return true;val>>=8;
	if (mem_writeb_checked(address+3,(Bit8u)(val & 0xff))) return true;
	return false;
}

Bit8u mem_readb(PhysPt address) {
	return mem_readb_inline(address);
}

Bit16u mem_readw(PhysPt address) {
	return mem_readw_inline(address);
}

Bit32u mem_readd(PhysPt address) {
	return mem_readd_inline(address);
}

void mem_writeb(PhysPt address,Bit8u val) {
	mem_writeb_inline(address,val);
}

void mem_writew(PhysPt address,Bit16u val) {
	mem_writew_inline(address,val);
}

void mem_writed(PhysPt address,Bit32u val) {
	mem_writed_inline(address,val);
}

static void write_p92(Bitu port,Bitu val,Bitu iolen) {	
	// Bit 0 = system reset (switch back to real mode)
	if (val&1) E_Exit("XMS: CPU reset via port 0x92 not supported.");
	memory.a20.controlport = val & ~2;
	MEM_A20_Enable((val & 2)>0);
}

static Bitu read_p92(Bitu port,Bitu iolen) {
	return memory.a20.controlport | (memory.a20.enabled ? 0x02 : 0);
}

void RemoveEMSPageFrame(void) {
	/* Setup rom at 0xe0000-0xf0000 */
	for (Bitu ct=0xe0;ct<0xf0;ct++) {
		memory.phandlers[ct] = &rom_page_handler;
	}
}

void PreparePCJRCartRom(void) {
	/* Setup rom at 0xd0000-0xe0000 */
	for (Bitu ct=0xd0;ct<0xe0;ct++) {
		memory.phandlers[ct] = &rom_page_handler;
	}
}

#include <unistd.h>
#include <stdio.h>

unsigned char *wayne_memory = NULL;
size_t wayne_length = 0;

void wayne_dump(char *buffer) {
  FILE *fp = fopen(buffer, "wb");
  fwrite(wayne_memory, 1, wayne_length, fp);
  fclose(fp);
  LOG_MSG("WAYNE: %s written", buffer);
}

void wayne_set(int offset, unsigned char b) {
  unsigned char *ptr = wayne_memory + offset;
  *ptr = b;
  LOG_MSG("WAYNE: Set %p to %x", ptr, b);
}

void wayne_read(char *buffer) {
  FILE *fp = fopen(buffer, "rb");
  fread(wayne_memory, 1, wayne_length, fp);
  fclose(fp);
  LOG_MSG("WAYNE: %s read", buffer);
}

int hack_locations[] = {
#include "../hacks.h"
};

void *wayne_thread(void *args) {
  LOG_MSG("WAYNE: sleep(1)");
  sleep(1);
  char buffer[4096];
  int idx = 79;
  int idx_limit = sizeof(hack_locations)/sizeof(int);
  LOG_MSG("MAX ARRAY SIZE IS %d", idx_limit);
  while(1) {
    char *str = fgets(buffer, 4096, stdin);
    LOG_MSG("Received string %s", buffer);
    if (idx < idx_limit) {
      LOG_MSG("Patching value at index %d which is mem location %d 0x%x", idx, hack_locations[idx], hack_locations[idx]);
      *(wayne_memory+hack_locations[idx]) = 0xFF;
      idx++;
    } else {
      LOG_MSG("REACHED END! DONE!");
    }
  }
}

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

#define error_string() strerror(errno)
#define gen_fatal(...) LOG_MSG(__VA_ARGS__),exit(1)


int UDPopen (const char *dest_host, int port, int block)
{
  int fd;
  
  /* Create the socket for datagrams on IP */
  fd = socket (AF_INET, SOCK_DGRAM, 0);
  if (fd < 0)
    gen_fatal ("Could not create new socket with AF_INET and SOCK_DGRAM - %s", error_string ());
  
  /* Setup and clear the socket structure */
  struct sockaddr_in socket_info;
  memset (&socket_info, 0x0, sizeof (struct sockaddr_in));
  
  /* Setup a socket on our machine, if we are listening then we need to specify a port,
     otherwise we leave it set to the default values */
  socket_info.sin_family = AF_INET;
  socket_info.sin_addr.s_addr = htonl (INADDR_ANY);
  if (dest_host == NULL)
    socket_info.sin_port = htons (port);
  
  /* Bind the socket info to the file descriptor */
  if (bind (fd, (struct sockaddr *)&socket_info, sizeof (socket_info)) < 0)
    gen_fatal ("Could not bind source address to the socket on fd %d - %s", fd, error_string ());
  
  /* Enable broadcasting mode on this socket, just in case we need it */
  int boolean_var = 1;
  if (setsockopt (fd, SOL_SOCKET, SO_BROADCAST, &boolean_var, sizeof (boolean_var)))
    gen_fatal ("setsockopt() failed to set broadcast flag on the new socket fd %d - %s", fd, error_string());
  
  /* Now, if we want to transmit from this socket, we need to do a connect() to set up
     for read and write calls */
  if (dest_host != NULL)
    {
      /* Lookup the host name to get its IP address, etc */
      struct hostent *host_info = gethostbyname (dest_host);
      if (host_info == NULL)
        gen_fatal ("Could not retrieve host name for %s with gethostbyname - %s", dest_host, error_string());
      
      /* Store the host and port info into the socket structure */
      memset (&socket_info, 0x0, sizeof (socket_info));
      bcopy (host_info->h_addr, (char *)&socket_info.sin_addr, host_info->h_length);
      socket_info.sin_family = host_info->h_addrtype;
      socket_info.sin_port = htons ((u_short)port);
      
      /* Do the connect() call to make it happen */
      if (connect (fd, (struct sockaddr *)&socket_info, sizeof (socket_info)) < 0)
        gen_fatal ("Could not connect destination address to the socket on fd %d - %s", fd, error_string ());
    }
  
  /* Make the socket non-blocking so we can do select() operations on it */
  if (block == 0)
    {
      int flags = fcntl (fd, F_GETFL, 0);
      if (flags < 0)
        gen_fatal ("fcntl() failed to retrieve file descriptor flags on the new socket fd %d - %s", fd, error_string ());
      if (fcntl (fd, F_SETFL, flags | O_NONBLOCK) < 0)
        gen_fatal ("fcntl() failed to set the non-blocking mode flag on the new socket fd %d - %s", fd, error_string ()); 
    }
  else if (block == 1)
    {
      /* Do nothing */
    }
  else
    gen_fatal ("The UDP blocking mode flag %d is not valid - the argument is invalid", block);
  
  /* Debug message */
  if (dest_host == NULL)
    LOG_MSG("Opened the UDP listener socket on port %d, on fd %d", port, fd);
  else
    LOG_MSG("Opened the UDP transmitter socket for host %s:%d, on fd %d", dest_host, port, fd);
  
  /* Return back the file descriptor */
  return (fd);
}


void *wayne_udp(void *args) {
  char *server = getenv("SERVER");
  char *left = getenv("LEFT");
  char *right = getenv("RIGHT");
  int magic_ofs = 0x28d0;
  size_t magic_bytes = 4 + 4 + 4 + 2 + 2 + 2; // East, Alt, North, Pitch, Roll, Heading
  if ((server != NULL) && (strlen(server) != 0)) {
    LOG_MSG("Detected SERVER configuration, will send UDP packets");
    int fd1 = UDPopen("127.0.0.1", 7777, 1); // Use blocking send
    if (fd1 < 0)
      gen_fatal("Could not open sender for 7777 - %s", error_string());
    int fd2 = UDPopen("127.0.0.1", 7778, 1); // Use blocking send
    if (fd2 < 0)
      gen_fatal("Could not open sender for 7778 - %s", error_string());
    while(1) {
      char buffer[magic_bytes];
      memcpy(buffer, wayne_memory+magic_ofs, magic_bytes);
      // LOG_MSG("Sending %zu bytes to socket", magic_bytes);
      int result;
      if ((result = send(fd1, buffer, magic_bytes, 0)) != magic_bytes) {
	if (errno == ECONNREFUSED) {
	  // LOG_MSG("Send1 failed with ECONNREFUSED, but this can happen if there is no process listening");
	} else {
	  gen_fatal("Send1 failed fd=%d, result=%d but expected %d - %s", fd1, result, magic_bytes, error_string());
	}
      }
      if ((result = send(fd2, buffer, magic_bytes, 0)) != magic_bytes) {
	if (errno == ECONNREFUSED) {
	  // LOG_MSG("Send1 failed with ECONNREFUSED, but this can happen if there is no process listening");
	} else {
	  gen_fatal("Send2 failed fd=%d, result=%d but expected %d - %s", fd2, result, magic_bytes, error_string());
	}
      }
      usleep(10*1000); // 10 msec refresh
    }
  } else if ((left != NULL) && (strlen(left) != 0)) {
    LOG_MSG("Detected LEFT configuration, will receive UDP packets");
    int fd = UDPopen(NULL, 7777, 1); // Use blocking receive
    while(1) {
      char buffer[magic_bytes];
      if (recv(fd, buffer, magic_bytes, 0) != magic_bytes)
	gen_fatal("Receive failed");
      // LOG_MSG("Received %zu bytes from socket", magic_bytes);
      memcpy(wayne_memory+magic_ofs, buffer, magic_bytes);
    }
  } else if ((right != NULL) && (strlen(right) != 0)) {
    LOG_MSG("Detected RIGHT configuration, will receive UDP packets");
    int fd = UDPopen(NULL, 7778, 1); // Use blocking receive
    while(1) {
      char buffer[magic_bytes];
      if (recv(fd, buffer, magic_bytes, 0) != magic_bytes)
	gen_fatal("Receive failed");
      // LOG_MSG("Received %zu bytes from socket", magic_bytes);
      memcpy(wayne_memory+magic_ofs, buffer, magic_bytes);
    }
  } else {
    LOG_MSG("Detected default configuration, will not implement UDP");
  }
}

#include "keyboard.h"

void btechmap() {
  LOG_MSG("BTECHMAP: Starting");
  while(1) {
    LOG_MSG("BTECHMAP: LEFT");
    KEYBOARD_AddKey(KBD_left, true);
    KEYBOARD_AddKey(KBD_left, false);
    sleep(1);
    LOG_MSG("BTECHMAP: UP");
    KEYBOARD_AddKey(KBD_up, true);
    KEYBOARD_AddKey(KBD_up, false);
    unsigned char *coords = wayne_memory+0x2852B;
    LOG_MSG("BTECHMAP: COORDS X = %.2X %.2X, Y = %.2X %.2X", *(coords+1), *(coords+0), *(coords+3), *(coords+2));
    sleep(1);
  }
}

void btechxy() {
  while(1) {
    unsigned char *coords = wayne_memory+0x2852B;
    LOG_MSG("BTECHMAP: COORDS X = %.2X %.2X, Y = %.2X %.2X", *(coords+1), *(coords+0), *(coords+3), *(coords+2));
    sleep(1);
  }
}

#include "vga.h"
#include "lodepng/lodepng.h"
#include "lodepng/lodepng.cpp"

inline Bit32u GetAddress(Bit16u seg, Bit32u offset)
{
  return (seg<<4)+offset;
}

void btechsave(char *filename) {
  const int width = 216;
  const int height = 200;
  // Crop the framebuffer to ignore pixels 0-104 on the left, just export 105,0 - 320,200
  unsigned char pixels[height][width];
  Bit8u val;
  Bitu seg = 0xA000;
  for (int row = 0; row < height; row++) {
    for (int col = 0; col < width; col++) {
      Bitu ofs = row*320 + col + 104;
      // You cannot read the A000 framebuffer from the wayne_memory pointer, it isn't visible there
      // for some reason, it is just blank 0x00 bytes. So we use mem_readb_checked() to get each
      // byte, which is how MEMDUMPBIN works.
      mem_readb_checked(GetAddress(seg,ofs),&val);
      pixels[row][col] = val;
    }
  }
  // Capture the VGA palette
  unsigned char* rgbpalette = (unsigned char*)&vga.dac.rgb;
  lodepng::State state;
  for (int i = 0; i < 256; i++) {
    unsigned char r = rgbpalette[i*3+0]*4;
    unsigned char g = rgbpalette[i*3+1]*4;
    unsigned char b = rgbpalette[i*3+2]*4;
    unsigned char a = 0xFF;
    lodepng_palette_add(&state.info_png.color, r, g, b, a);
    lodepng_palette_add(&state.info_raw, r, g, b, a);
    //fprintf(stderr, "Palette %d = (R%d,G%d,B%d,A%d)\n", i, r, g, b, a);
  }
  state.info_png.color.colortype = LCT_PALETTE;
  state.info_png.color.bitdepth = 8;
  state.info_raw.colortype = LCT_PALETTE;
  state.info_raw.bitdepth = 8;
  state.encoder.auto_convert = 0;

  std::vector<unsigned char> buffer;
  fprintf(stderr, "Dumping entire framebuffer\n");
  unsigned error = lodepng::encode(buffer, &pixels[0][0], width, height, state);
  if(error) {
    fprintf(stderr, "PNG encoder error %d: %s\n", error, lodepng_error_text(error));
    exit(1);
  }
  lodepng::save_file(buffer, filename);
  fprintf(stderr, "Saved btech cropped framebuffer PNG to %s\n", filename);
}

void *wayne_debugger(void *args) {
  LOG_MSG("WAYNE: DEBUGGER START - USE HEX VALUES HERE!");
  sleep(1);
  char buffer[4096];
  char last[4096];
  sprintf(last, "");
  while(1) {
    char *str = fgets(buffer, 4096, stdin);
    str[strlen(str)-1] = '\0';
    char cmd[64];
    int ofs;
    int val;
    LOG_MSG("Received string [%s] strlen=%d", str, strlen(str));
    if (!strcmp(str,"")) {
      strcpy(buffer, last);
      LOG_MSG("Reusing last string [%s] strlen=%d", str, strlen(str));
    } else {
      strcpy(last, buffer);
    }
    int wrep;
    int args = sscanf(str, "%s %x %x %x", cmd, &ofs, &val, &wrep);
    // LOG_MSG("CMD=[%s]", cmd);
    if (!strcasecmp(cmd, "w")) {
      if (args < 4) {
	LOG_MSG("Writing to ofs=%x with value=%x", ofs, val);
	*(wayne_memory+ofs) = val;
      } else {
	LOG_MSG("Writing to ofs=%x with value=%x for repeats=%x", ofs, val, wrep);
	for(int c = 0; c < wrep; c++) {
	  *(wayne_memory+ofs+c) = val;
	}
      }
    } else if (!strcasecmp(cmd, "r")) {
      if (args < 3) {
	val = 1;
      }
      for(int c = 0; c < val; c++) {
	unsigned char ret = *(wayne_memory+ofs+c);
	LOG_MSG ("Read start=%x ofs=%x value=%.2x", ofs, c, ret);
      }
    } else if (!strcasecmp(cmd, "save")) {
      char buf [256];
      sprintf (buf, "dump-%d.log", ofs);
      wayne_dump(buf);
    } else if (!strcasecmp(cmd, "btechmap")) {
      btechmap();
    } else if (!strcasecmp(cmd, "btechxy")) {
      btechxy();
    } else if (!strcasecmp(cmd, "btechsave")) {
      btechsave("btechsave.png");
    } else {
      LOG_MSG("UNKNOWN! CMD[%s] OFS[0x%x] VAL[0x%x]", cmd, ofs, val);
    }    
  }
}

void wayne_start_thread() {
  pthread_t thread;
  LOG_MSG("Starting thread");
  pthread_create(&thread, NULL, wayne_debugger, NULL);

  pthread_t udp;
  pthread_create(&udp, NULL, wayne_udp, NULL);

}

HostPt GetMemBase(void) { return MemBase; }

class MEMORY:public Module_base{
private:
	IO_ReadHandleObject ReadHandler;
	IO_WriteHandleObject WriteHandler;
public:	
	MEMORY(Section* configuration):Module_base(configuration){
		Bitu i;
		Section_prop * section=static_cast<Section_prop *>(configuration);
	
		/* Setup the Physical Page Links */
		Bitu memsize=section->Get_int("memsize");
	
		if (memsize < 1) memsize = 1;
		/* max 63 to solve problems with certain xms handlers */
		if (memsize > MAX_MEMORY-1) {
			LOG_MSG("Maximum memory size is %d MB",MAX_MEMORY - 1);
			memsize = MAX_MEMORY-1;
		}
		if (memsize > SAFE_MEMORY-1) {
			LOG_MSG("Memory sizes above %d MB are NOT recommended.",SAFE_MEMORY - 1);
			LOG_MSG("Stick with the default values unless you are absolutely certain.");
		}
		MemBase = new Bit8u[memsize*1024*1024];
		wayne_memory = (unsigned char *)MemBase;
		wayne_length = memsize*1024*1024;
		LOG_MSG("WAYNE: Allocated %zu (0x%x) bytes of memory from %p to %p\n", wayne_length, wayne_length, wayne_memory, wayne_memory+wayne_length);
		wayne_start_thread();

		if (!MemBase) E_Exit("Can't allocate main memory of %d MB",memsize);
		/* Clear the memory, as new doesn't always give zeroed memory
		 * (Visual C debug mode). We want zeroed memory though. */
		memset((void*)MemBase,0,memsize*1024*1024);
		memory.pages = (memsize*1024*1024)/4096;
		/* Allocate the data for the different page information blocks */
		memory.phandlers=new  PageHandler * [memory.pages];
		memory.mhandles=new MemHandle [memory.pages];
		for (i = 0;i < memory.pages;i++) {
			memory.phandlers[i] = &ram_page_handler;
			memory.mhandles[i] = 0;				//Set to 0 for memory allocation
		}
		/* Setup rom at 0xc0000-0xc8000 */
		for (i=0xc0;i<0xc8;i++) {
			memory.phandlers[i] = &rom_page_handler;
		}
		/* Setup rom at 0xf0000-0x100000 */
		for (i=0xf0;i<0x100;i++) {
			memory.phandlers[i] = &rom_page_handler;
		}
		if (machine==MCH_PCJR) {
			/* Setup cartridge rom at 0xe0000-0xf0000 */
			for (i=0xe0;i<0xf0;i++) {
				memory.phandlers[i] = &rom_page_handler;
			}
		}
		/* Reset some links */
		memory.links.used = 0;
		// A20 Line - PS/2 system control port A
		WriteHandler.Install(0x92,write_p92,IO_MB);
		ReadHandler.Install(0x92,read_p92,IO_MB);
		MEM_A20_Enable(false);
	}
	~MEMORY(){
		delete [] MemBase;
		delete [] memory.phandlers;
		delete [] memory.mhandles;
	}
};	

	
static MEMORY* test;	
	
static void MEM_ShutDown(Section * sec) {
	delete test;
}

void MEM_Init(Section * sec) {
	/* shutdown function */
	test = new MEMORY(sec);
	sec->AddDestroyFunction(&MEM_ShutDown);
}
