#include <iostream>
#include <string>
#include <vector>
#include <fstream>
#include <stdlib.h>

struct section_header
{
    uint64_t name;
    uint32_t v_size;
    uint32_t v_addr;
    uint32_t r_size;
    uint32_t r_addr;
    uint32_t p_reloc;
    uint32_t p_lines;
    uint16_t num_reloc;
    uint16_t num_lines;
    uint32_t characteristics;
};