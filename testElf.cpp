//#define _GNU_SOURCE
#include <link.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>



#if (__SIZEOF_POINTER__ == 8)
#define Elf_Ehdr Elf64_Ehdr
#define Elf_Shdr Elf64_Shdr
#define Elf_Sym Elf64_Sym
#define Elf_Rel Elf64_Rela
#define ELF_R_SYM ELF64_R_SYM
#define REL_DYN ".rela.dyn"
#define REL_PLT ".rela.plt"

#else
#define Elf_Ehdr Elf32_Ehdr 
#define Elf_Shdr Elf32_Shdr
#define Elf_Sym Elf32_Sym
#define Elf_Rel Elf32_Rela
#define ELF_R_SYM ELF32_R_SYM
#define REL_DYN ".rel.dyn"
#define REL_PLT ".rel.plt"
#endif

/*
typedef struct {
unsigned char e_ident[EI_NIDENT];
uint16_t      e_type;
uint16_t      e_machine;
uint32_t      e_version;
ElfN_Addr     e_entry;
ElfN_Off      e_phoff;
ElfN_Off      e_shoff;
uint32_t      e_flags;
uint16_t      e_ehsize;
uint16_t      e_phentsize;
uint16_t      e_phnum;
uint16_t      e_shentsize;
uint16_t      e_shnum;
uint16_t      e_shstrndx;
} ElfN_Ehdr;

typedef struct {
	uint32_t   sh_name;
	uint32_t   sh_type;
	uint32_t   sh_flags;
	Elf32_Addr sh_addr;
	Elf32_Off  sh_offset;
	uint32_t   sh_size;
	uint32_t   sh_link;
	uint32_t   sh_info;
	uint32_t   sh_addralign;
	uint32_t   sh_entsize;
} Elf32_Shdr;

typedef struct {
	uint32_t      st_name;
	Elf32_Addr    st_value;
	uint32_t      st_size;
	unsigned char st_info;
	unsigned char st_other;
	uint16_t      st_shndx;
} Elf32_Sym;

typedef struct {
	Elf32_Addr r_offset;
	Elf32_Word r_info;
} Elf32_Rel;

*/

// return < 0 失败
static int read_elf_header(int fd, Elf_Ehdr *header)
{
	int ret = 0;

	if (NULL == header || fd < 0)
	{
		return -1;
	}
	//*header = (Elf_Ehdr *) malloc(sizeof(Elf_Ehdr));
	//if (NULL == *header)
	//{
	//	return -1;
	//}

	ret = lseek(fd, 0, SEEK_SET);
	if (ret < 0)
	{
		return -1;;
	}

	ret = read(fd, header, sizeof(Elf_Ehdr));
	if (sizeof(Elf_Ehdr) != ret)
	{
		return -1;
	}

	return 0;
}

// return < 0 失败
// 当返回成功后，需调用者释放*table内存
static int read_section_table(int fd, const Elf_Ehdr *header, Elf_Shdr **table)
{
	int ret = 0;
	size_t size;

	if (NULL == header || fd < 0)
	{
		return -1;
	}

	size = header->e_shnum * sizeof(Elf_Shdr);
	*table = (Elf_Shdr *)malloc(size);
	if (NULL == *table)
	{
		return -1;
	}

	ret = lseek(fd, header->e_shoff, SEEK_SET);
	if (ret < 0)
	{
		free(*table);
		return -1;
	}

	ret = read(fd, *table, size);
	if (ret != size)
	{
		free(*table);
		return -1;
	}

	return 0;
}

// return < 0 失败
// 当返回成功后，需调用者释放*table内存
static int read_symbol_table(int fd, const Elf_Shdr *section, Elf_Sym **table)
{
	int ret;
	if (NULL == section || fd < 0 || NULL == table)
	{
		return -1;
	}

	*table = (Elf_Sym *)malloc(section->sh_size);
	if (NULL == *table)
	{
		return -1;
	}

	ret = lseek(fd, section->sh_offset, SEEK_SET);
	if (ret < 0)
	{
		free(*table);
		return -1;
	}

	ret = read(fd, *table, section->sh_size);
	if (ret != section->sh_size)
	{
		free(*table);
		return -1;
	}

	return 0;
}


// return < 0 失败
// 当返回成功后，需调用者释放*table内存
static int read_string_table(int fd, const Elf_Shdr *section, const char **table)
{
	int ret;
	if (fd < 0 || NULL == section || NULL == table)
	{
		return -1;
	}

	*table = (char*)malloc(section->sh_size);
	if (NULL == *table)
	{
		return -1;
	}

	ret = lseek(fd, section->sh_offset, SEEK_SET);
	if (ret < 0)
	{
		free((void*)*table);
		return -1;
	}
	ret = read(fd, (void*)*table, section->sh_size);
	if (ret != section->sh_size)
	{
		free((void*)*table);
		return -1;
	}

	return 0;
}

static int get_section_by_name(int fd, const char *section_name, Elf_Shdr *section)
{
	Elf_Ehdr header;
	Elf_Shdr *sections = NULL;
	const char *strings = NULL;
	int ret = -1;
	size_t i = 0;

	if (read_elf_header(fd, &header)
		|| read_section_table(fd, &header, &sections)
		|| read_string_table(fd, &sections[header.e_shstrndx], &strings))
	{
		return -1;
	}

	for (i = 0; i < header.e_shnum; ++i)
	{
		// sh_name给出节区名称。是节区头部字符串表节区
		//（Section Header StringTable Section）的索引
		if (!strcmp(section_name, &strings[sections[i].sh_name]))
		{
			if (NULL != section)
			{
				memcpy(section, sections+i, sizeof(Elf_Shdr));
				ret = 0;
			}
		}
	}

	free(sections);
	free((void*)strings);

	return ret;
}

static int get_section_by_type(int fd, const size_t section_type, Elf_Shdr *section)
{
	Elf_Ehdr header;
	Elf_Shdr *sections = NULL;
	const char *strings = NULL;
	int ret = -1;
	size_t i = 0;

	if (read_elf_header(fd, &header)
		|| read_section_table(fd, &header, &sections)
		|| read_string_table(fd, &sections[header.e_shstrndx], &strings))
	{
		return -1;
	}

	for (i = 0; i < header.e_shnum; ++i)
	{
		if (section_type == sections[i].sh_type)
		{
			if (NULL != section)
			{
				memcpy(section, sections+i, sizeof(Elf_Shdr));
				ret = 0;
			}
		}
	}

	free(sections);
	free((void*)strings);

	return ret;
}

static int get_section_by_index(int fd, const size_t index, Elf_Shdr *section)
{
	Elf_Ehdr header;
	Elf_Shdr *sections = NULL;
	const char *strings = NULL;
	int ret = -1;
	size_t i = 0;

	if (read_elf_header(fd, &header)
		|| read_section_table(fd, &header, &sections)
		|| read_string_table(fd, &sections[header.e_shstrndx], &strings))
	{
		return -1;
	}

	if (index < header.e_shnum)
	{
		memcpy(section, sections+index, sizeof(Elf_Shdr));
		ret = 0;
	}

	free(sections);
	free((void*)strings);

	return ret;
}

hook()
{

}

static int
callback(struct dl_phdr_info *info, size_t size, void *data)
{
	int j;

	printf("name=%s (%d segments)\n", info->dlpi_name,
		info->dlpi_phnum);

	for (j = 0; j < info->dlpi_phnum; j++)
		printf("\t\t header %2d: type=%d, address=%10p\n", j, info->dlpi_phdr[j].p_type,
		(void *) (info->dlpi_addr + info->dlpi_phdr[j].p_vaddr));
	return 0;
}

int
main(int argc, char *argv[])
{
	dl_iterate_phdr(callback, NULL);

	Elf_Ehdr header;
	int fd = open("/home/sqq/samba/a.out", O_RDONLY);

	read_elf_header(fd, &header);

	printf("elf.type:%d\n", header.e_type);

	exit(EXIT_SUCCESS);
}