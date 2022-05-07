#include "Flattener.h"

template <typename V, typename T, typename U>
constexpr auto fill_primitive(T&& src, U offset)
{
    V dest;

    memcpy(&dest, &src[offset], sizeof(V));

    return dest;
}

template <typename T>
void copy_to_vector(T&& value, std::vector<char>& buffer, uint32_t offset)
{
    if (sizeof(T) + offset > buffer.size())
    {
        std::cout << "Could not copy file to buffer - max length exceeded" << std::endl;
        return;
    }

    memcpy(buffer.data() + offset, &value, sizeof(T));
}

int 
main(
    int argc,
    char *argv[]
)
{
    if (argc < 3)
    {
        std::cout << "Usage: ./program <pe> <flatten_base>" << std::endl;
        return 1;
    }

    auto flatten_base = static_cast<uint32_t>(atoi(argv[2]));

    auto fd = std::fstream(argv[1], std::ios::in | std::ios::binary | std::ios::ate);

    if (!fd.is_open())
    {
        std::cout << "Could not open file" << std::endl;
        return 1;
    }

    const auto file_name = std::string(argv[1]);

    const auto file_size = static_cast<uint64_t>(fd.tellg());

    // Check if the file has any contents
    if (file_size == 0)
    {
        std::cout << "Empty file" << std::endl;
    }

    fd.seekg(0);

    // Read file into a byte stream
    std::vector<char> file_contents(file_size, 0);

    fd.read(file_contents.data(), file_size);

    auto mz_signature = fill_primitive<uint16_t>(file_contents, 0);

    // Check to see if the file has a valid MZ header
    if (mz_signature != 'ZM')
    {
        std::cout << argv[1] << " not a valid PE (No MZ header)" << std::endl;
        return 1;
    }

    // Grab pointer to PE header from DOS header
    constexpr uint32_t pe_header_offset = 0x3c;

    auto pe_pointer = fill_primitive<uint32_t>(file_contents, pe_header_offset);

    const auto pe_header = std::vector<char>(file_contents.begin() + pe_pointer, file_contents.end());

    // Verify the file has a valid PE header
    auto pe_signature = fill_primitive<uint32_t>(pe_header, 0);

    if (pe_signature != 'EP')
    {
        std::cout << argv[1] << " not a valid PE (No PE signature)" << std::endl;
        return 1;
    }

    // Grab magic
    // Ensure file as a PE32 (not PE32+)
    constexpr auto magic_offset = 0x18u;
    const auto magic = fill_primitive<uint16_t>(pe_header, magic_offset);

    if (magic != 0x10b)
    {
        std::cout << argv[1] << " not a valid PE32 (Magic is not 0x10b)" << std::endl;
        return 1;
    }

    // Grab the size of optional header
    constexpr auto optional_header_size_offset = 0x14;

    auto optional_header_size = fill_primitive<uint16_t>(pe_header, optional_header_size_offset);

    constexpr auto pe_header_size = 0x18u;

    auto section_header_start = pe_header_size + optional_header_size;

    constexpr auto section_count_offset = 0x6u;

    auto section_count = fill_primitive<uint16_t>(pe_header, section_count_offset);

    std::cout << "PE file contains : " << section_count << " sections" << std::endl;

    // Generate intermediate buffer
    std::vector<char> intermediate_binary;

    // Get relocation information
    // The relocation table rva is most likely going to be a section (.reloc)
    // And we are parsing sections right after this
    constexpr auto relocation_table_offset       = 0xa0u;
    constexpr auto relocation_table_size_offset  = relocation_table_offset + sizeof uint32_t;

    // Relocation table RVA is equal to the virtual address in the section
    auto relocation_table_rva  = fill_primitive<uint32_t>(pe_header, relocation_table_offset);
    auto relocation_table_size = fill_primitive<uint32_t>(pe_header, relocation_table_size_offset);

    std::vector<char> relocation_section;

    // First section RVA is required when applying relocations after
    auto first_section_rva = 0u;

    // Generate output file
    std::fstream fd_output("output.bin", std::ios::binary | std::ios::out);

    // Enumerate the sections
    // Grab the names for debug information
    for (uint32_t section = 0; section < section_count; section++)
    {
        auto header_item = fill_primitive<section_header>(pe_header, section_header_start + section * sizeof section_header);

        if (section == 0)
        {
            first_section_rva = header_item.v_addr;
        }

        // Traverse the bytes of header_item.name 
        // Check for a 0
        // If a 0 does not exist, then the name is 8 bytes long
        const auto& section_name_raw = header_item.name;

        char section_name[9];

        uint8_t name_end = 8;

        for (uint8_t i = 0u; i < sizeof(section_name_raw); i++)
        {
            const auto char_val = static_cast<char>((section_name_raw >> (i * 8)) & (0xff));

            if (char_val == 0)
            {
                name_end = i;
                break;
            }

            section_name[i] = char_val;
        }

        section_name[name_end] = 0;

        if (name_end == 0)
        {
            std::cout << "Section header at offset " << section << "had no name?" << std::endl;
            return 1;
        }

        std::cout << "Section " << section << " has name: " << section_name << std::endl;

        // Write section out to file
        // Align to the next page
        const auto& virtual_size = (header_item.v_size + 0x1000) & ~0xfffu;
        auto intermediate_section = std::vector<char>(virtual_size, 0);

        // So the virtual size of a section is typically SMALLER than that of the raw size
        // It is counter-intuitive because you would expect the virtual size to be page-aligned and the raw size to be section-aligned
        // BUT the virtual size is NOT aligned (byte granularity) while the raw size is file-aligned

        // Just use virtual size as it should contain all the information we want
        memcpy(intermediate_section.data(), &file_contents[header_item.r_addr], header_item.v_size);

        // Add it to the intermediate binary
        intermediate_binary.insert(intermediate_binary.end(), intermediate_section.begin(), intermediate_section.end());

        if (header_item.v_addr == relocation_table_rva)
        {
            relocation_section = intermediate_section;
            relocation_section.resize(header_item.v_size);
        }
    }

    // Get image base, which we will use in our relocation calculation
    constexpr auto image_base_offset = 0x34u;

    auto image_base = fill_primitive<uint32_t>(pe_header, image_base_offset);
    __debugbreak();

    // Apply relocations to the intermediate binary
    uint32_t table_offset = 0;

    while(table_offset < relocation_table_size)
    {
        // First DWORD contains the page RVA to apply the relocation to
        auto page_rva = fill_primitive<uint32_t>(relocation_section, table_offset);

        table_offset += sizeof page_rva;

        // Second DWORD contains the number of bytes in the base relocation block
        auto page_block_size = fill_primitive<uint32_t>(relocation_section, table_offset);

        table_offset += sizeof page_block_size;

        // Get relocations and apply them to our intermediate buffer

        constexpr auto entry_size = sizeof uint16_t;

        // The page_block_size value contains the size of the RVA, block size and the variable length entries
        // So to get the size of just the size of the block of relocations we need to subtract the size of the page_rva and page_block_size variables
        const auto entry_block_size = page_block_size - sizeof page_rva - sizeof page_block_size;

        std::cout << std::hex;

        for (uint32_t i = 0; i < entry_block_size; i += entry_size)
        {
            auto relocation_entry = fill_primitive<uint16_t>(relocation_section, table_offset + i);

            // The high nibble indicates the relocation type
            // For 32 bit binaries on x86 arch -- This value should be 3
            constexpr auto image_rel_based_high_low = 3u;

            // So it turns out it can also be 0
            // Check syswow64/ntdll.dll -> 0x26000
            // Value of 0 indicates **do nothing** - so why have it in the relocation table...?
            // Truly "based"
            constexpr auto image_rel_based_absolute = 0u;

            const auto relocation_type = static_cast<uint8_t>(((relocation_entry >> 12) & 0xf));

            // Continue if absolute
            if (relocation_type == image_rel_based_absolute)
            {
                std::cout << "Found absolute at page: " << page_rva << " entry: " << relocation_entry << std::endl;
                continue;
            }

            if (relocation_type != image_rel_based_high_low && relocation_type != image_rel_based_absolute)
            {
                std::cout << "Non-expected relocation type identified: " << (char)relocation_type << std::endl;
                __debugbreak();
                return 1;
            }

            // The low 12 bits indicate the offset from the page rva to apply the relocation type to
            // We also want to subtract by the value of the virtual address of the first section
            const auto relocation_offset = page_rva + (relocation_entry & 0xfff) - first_section_rva;

            auto value = fill_primitive<uint32_t>(intermediate_binary, relocation_offset);

            // We have to also account for the first_section_rva to the relocation itself
            // As the image is shifted by the first_section_rva, we have to subtract by first_section_rva to get the real offset
            value = value - image_base + flatten_base - first_section_rva;

            copy_to_vector(value, intermediate_binary, relocation_offset);
        }
        
        // We need to increment the table offset by the size of the base relocation block
        table_offset += entry_block_size;
    }

    // Write the flattened binary out!
    fd_output.write(intermediate_binary.data(), intermediate_binary.size());

    std::cout << "Wrote flattened binary!" << std::endl;

    return 0;
}