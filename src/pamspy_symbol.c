#include <stdlib.h>
#include <stdio.h>
#include <gelf.h>
#include <string.h>
#include "pamspy_symbol.h"

/******************************************************************************/
/*!
 *  \brief  loop on symbol in the file by parsing the ELF
 *  \param  file    elf file opened
 *  \param  symname name of the symbol
 *  \return -1 if not found or offset of the symbol
 */
static int _find_symbol_address(FILE* file, const char* symname)
{
    int result = -1;

    Elf *e;
    if (elf_version(EV_CURRENT) == EV_NONE)
        return -1;

    e = elf_begin(fileno(file), ELF_C_READ, 0);

    if (e == NULL)
        return -1;

    Elf_Scn *section = NULL;

    while ((section = elf_nextscn(e, section)) != 0)
    {
        GElf_Shdr header;

        if (!gelf_getshdr(section, &header))
            continue;

        if (header.sh_type != SHT_SYMTAB && header.sh_type != SHT_DYNSYM)
            continue;

        Elf_Data *data = NULL;
        while ((data = elf_getdata(section, data)) != 0)
        {
            size_t i, symcount = data->d_size / header.sh_entsize;

            if (data->d_size % header.sh_entsize)
            {
                break;
            }

            for (i = 0; i < symcount; ++i)
            {
                GElf_Sym sym;
                const char *name;

                if (!gelf_getsym(data, (int)i, &sym))
                    continue;

                if ((name = elf_strptr(e, header.sh_link, sym.st_name)) == NULL)
                    continue;

                if(strcmp(name, symname) == 0)
                {
                    result = sym.st_value;
                    break;
                }
            }
        }
    }

    elf_end(e);
    return result;
}

/******************************************************************************/
int pamspy_find_symbol_address(const char *path, const char* symname)
{

    FILE* fd = fopen(path, "r");
    if(!fd)
        return -1;

    int result = _find_symbol_address(fd, symname);

    fclose(fd);
    return result;
}