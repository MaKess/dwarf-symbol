#include <cstdlib>
#include <cstddef>
#include <cstdio>
#include <map>
#include <vector>
#include <string>
#include <stdexcept>

#include <fmt/format.h>

#include <inttypes.h>
#include <string.h>
#include <elf.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>

struct Symbol {
	const char *name;
	uint64_t size;
};

struct Line {
	const char *file;
	const char *directory;
	uint64_t line;
	uint64_t column;
};

class MapParser {
	public:
		MapParser(const void * const data, const size_t size);
		void parse_map(std::map<uint64_t, Symbol> &symbols, char *strbuf);

	private:
		char head() const;
		bool next();

		const void *data;
		const size_t size;
		size_t offset;
};

class DwarfParser {
	public:
		DwarfParser(const void * const data, const size_t size);
		void parse(std::map<uint64_t, Line> &output);
	private:
		void parse_header();
		void parse_state_machine(std::map<uint64_t, Line> &output);

		const char * get_data(size_t consume=0);
		template<typename T> T get_int();
		uint64_t get_int(unsigned size);
		uint64_t get_uleb128();
		int64_t get_sleb128();
		const char * get_string();

		void reset_state_machine();
		void emit_state_machine(std::map<uint64_t, Line> &output);

		struct source_file {
			const char *file_name;
			const char *include_directory;
			uint64_t time;
			uint64_t size;
		};
		std::vector<const char *> include_directories;
		std::vector<struct source_file> file_names;

		struct {
			uint64_t address;
			uint64_t op_index; // DWARF4
			uint64_t file;
			uint64_t line;
			uint64_t column;
			bool is_stmt;
			bool basic_block;
			bool end_sequence;
			bool prologue_end; // DWARF3
			bool epilogue_begin; // DWARF3
			uint64_t isa; // DWARF3
			uint64_t discriminator; // DWARF4
		} state_machine;

		struct {
			uint64_t unit_end;
			uint64_t header_end;

			uint64_t unit_length;
			uint16_t version;
			uint64_t header_length;
			uint8_t minimum_instruction_length;
			uint8_t maximum_operations_per_instruction;
			bool default_is_stmt;
			int8_t line_base;
			uint8_t line_range;
			uint8_t opcode_base;
			const uint8_t *standard_opcode_lengths;
		} header;

		const void * const data;
		const size_t size;
		size_t offset;

		enum DW_LNS : uint8_t {
			DW_LNS_extended_op = 0,
			DW_LNS_copy = 1,
			DW_LNS_advance_pc = 2,
			DW_LNS_advance_line = 3,
			DW_LNS_set_file = 4,
			DW_LNS_set_column = 5,
			DW_LNS_negate_stmt = 6,
			DW_LNS_set_basic_block = 7,
			DW_LNS_const_add_pc = 8,
			DW_LNS_fixed_advance_pc = 9,
			DW_LNS_set_prologue_end = 10,
			DW_LNS_set_epilogue_begin = 11,
			DW_LNS_set_isa = 12,
		};
		enum DW_LNE : uint8_t {
			DW_LNE_end_sequence = 1,
			DW_LNE_set_address = 2,
			DW_LNE_define_file = 3,
			DW_LNE_set_discriminator = 4,
		};
};

template<typename ElfHeader, typename SectionHeader, typename SymbolEntry>
class ElfParser {
	public:
		ElfParser(const void * const data);
		void parse_symbols(std::map<uint64_t, Symbol> &symbols);
		void parse_lines(std::map<uint64_t, Line> &lines);

	private:
		const ElfHeader * get_header() const;
		const SectionHeader * get_section_table() const;
		const SectionHeader * get_section(const char * const section_name) const;
		template<typename T> T get_section_content(const SectionHeader * const section) const;

		std::map<std::string, const SectionHeader *> sections;
		const void *base;
};

typedef ElfParser<Elf64_Ehdr, Elf64_Shdr, Elf64_Sym> Elf64Parser;
typedef ElfParser<Elf32_Ehdr, Elf32_Shdr, Elf32_Sym> Elf32Parser;

class DebugInfo {
	public:
		DebugInfo();
		~DebugInfo();
		bool load(const char * const file_name);
		void print_symbols() const;
		bool find_symbol(uint64_t address, const char **name, uint64_t *offset) const;
		bool find_line(uint64_t address, const char **file, const char **directory, uint64_t *line, uint64_t *column) const;
	private:
		const void * data;
		char *strbuf;
		size_t size;
		int fd;
		std::map<uint64_t, Symbol> symbols;
		std::map<uint64_t, Line> lines;
};

MapParser::MapParser(const void * const data, const size_t size) :
	data(data),
	size(size),
	offset(0) {
}

void MapParser::parse_map(std::map<uint64_t, Symbol> &symbols, char *strbuf) {
	for (;;) {
		// get the symbol value
		uint64_t value(0);
		for (;;) {
			int c = head();
			unsigned d;
			if (c >= '0' && c <= '9') {
				d = c - '0';
			} else {
				c |= 32;
				if (c >= 'a' && c <= 'f')
					d = c - 'a' + 10;
				else
					break;
			}
			value = (value * 16) + d;

			if (next())
				break;
		}

		// skip whitespace
		while ((head() == ' ' || head() == '\t') && !next());

		// get the symbol type
		const char type(head());
		next();

		// skip whitespace
		while ((head() == ' ' || head() == '\t') && !next());

		// get the symbol name
		const char * const name_start(static_cast<const char *>(data) + offset);
		size_t name_len(0);
		while (head() >= 21 && head() <= 126) {
			if (next())
				break;
			name_len++;
		}

		// skip end-of-line
		while ((head() == '\n' || head() == '\r') && !next());

		// stop if we are at the end
		if ((offset + 1) >= size)
			break;

		if ((type | 32) == 't' && name_start[0] != '$') {
			memcpy(strbuf, name_start, name_len);
			strbuf[name_len] = '\0';
			Symbol sym = {strbuf, 0};
			strbuf += name_len + 1;
			symbols[value] = sym;
		}
	}
}

char MapParser::head() const {
	return static_cast<const char*>(data)[offset];
}

bool MapParser::next() {
	const size_t next_offset(offset + 1);
	if (next_offset >= size) {
		return true;
	} else {
		offset = next_offset;
		return false;
	}
}

DwarfParser::DwarfParser(const void * const data, const size_t size) :
	data(static_cast<const char *>(data)),
	size(size),
	offset(0) {
}

const char * DwarfParser::get_data(size_t consume) {
	const size_t new_offset(offset + consume);
	if (new_offset > size)
		throw std::runtime_error(fmt::format("reading past end of buffer! ({} >= {})", new_offset, size));

	const char * ret(static_cast<const char *>(data) + offset);
	offset = new_offset;
	return ret;
}

template<typename T> T DwarfParser::get_int() {
	T ret;
	memcpy(&ret, get_data(sizeof(T)), sizeof(T));
	return ret;
}

uint64_t DwarfParser::get_int(unsigned size) {
	uint64_t ret(0);
	memcpy(&ret, get_data(size), size);
	return ret;
}

uint64_t DwarfParser::get_uleb128() {
	uint64_t ret(0);
	unsigned shift(0);
	uint8_t byte;
	do {
		byte = get_int<uint8_t>();
		ret |= (byte & 0x7f) << shift;
		shift += 7;
	} while (byte & 0x80);
	return ret;
}

int64_t DwarfParser::get_sleb128() {
	int64_t ret(0);
	unsigned shift(0);
	uint8_t byte;
	do {
		byte = get_int<uint8_t>();
		ret |= (byte & 0x7f) << shift;
		shift += 7;
	} while(byte & 0x80);
	if (byte & 0x40)
		ret |= ~0 << shift;
	return ret;
}

const char * DwarfParser::get_string() {
	const char *ret(get_data());
	const size_t length(strlen(ret)), new_offset(offset + length + 1);
	if (new_offset > size)
		throw std::runtime_error(fmt::format("string starting at offset {:#x} is not properly null-terminated!", offset));
	offset = new_offset;
	return ret;
}

void DwarfParser::parse(std::map<uint64_t, Line> &output) {
	while (offset < size) {
		parse_header();

		if (offset != header.header_end)
			throw std::runtime_error(fmt::format("offset is {}, but header should end at {}", offset, header.header_end));

		parse_state_machine(output);
	}
}

void DwarfParser::parse_header() {
	const uint32_t initial_length(get_int<uint32_t>());
	const bool dwarf32_not_64 = initial_length < UINT32_C(0xffffff00);
	header.unit_length = dwarf32_not_64 ? initial_length : get_int<uint64_t>();
	header.unit_end = offset + header.unit_length;
	header.version = get_int<uint16_t>();

	if (header.version < 2 || header.version > 4)
		throw std::runtime_error(fmt::format("unsupported DWARF version {}", header.version));

	header.header_length = dwarf32_not_64 ? get_int<uint32_t>() : get_int<uint64_t>();
	header.header_end = offset + header.header_length;
	header.minimum_instruction_length = get_int<uint8_t>();
	if (header.version >= 4)
		header.maximum_operations_per_instruction = get_int<uint8_t>();
	else
		header.maximum_operations_per_instruction = 1;

	if (header.maximum_operations_per_instruction == 0)
		throw std::runtime_error("maximum_operations_per_instruction must not be 0");
	else if (header.maximum_operations_per_instruction != 1)
		throw std::runtime_error("TODO: implement support for maximum_operations_per_instruction");

	header.default_is_stmt = get_int<uint8_t>();
	header.line_base = get_int<int8_t>();
	header.line_range = get_int<uint8_t>();
	header.opcode_base = get_int<uint8_t>();
	// TODO: check if "opcode_base" is invalid (what is its minimum value?)
	header.standard_opcode_lengths = reinterpret_cast<const uint8_t *>(get_data(header.opcode_base - 1));

	include_directories.clear();
	for (;;) {
		const char * const include_directory(get_string());
		if (!*include_directory)
			break;
		include_directories.push_back(include_directory);
	}

	file_names.clear();
	for (;;) {
		const char * const file_name(get_string());
		if (!*file_name)
			break;
		const uint64_t directory_index(get_uleb128());
		const uint64_t time(get_uleb128());
		const uint64_t size(get_uleb128());

		source_file file = {
			file_name,
			directory_index ? include_directories[directory_index - 1] : nullptr,
			time,
			size,
		};
		file_names.push_back(file);
	}

}

void DwarfParser::reset_state_machine() {
	state_machine.address = 0;
	state_machine.op_index = 0;
	state_machine.file = 1;
	state_machine.line = 1;
	state_machine.column = 0;
	state_machine.is_stmt = header.default_is_stmt;
	state_machine.basic_block = false;
	state_machine.end_sequence = false;
	state_machine.prologue_end = false;
	state_machine.epilogue_begin = false;
	state_machine.isa = 0;
	state_machine.discriminator = 0;
}

void DwarfParser::emit_state_machine(std::map<uint64_t, Line> &output) {
	Line line = {
		state_machine.file ? file_names[state_machine.file - 1].file_name : nullptr,
		state_machine.file ? file_names[state_machine.file - 1].include_directory : nullptr,
		state_machine.line,
		state_machine.column
	};
	output[state_machine.address] = line;
}

void DwarfParser::parse_state_machine(std::map<uint64_t, Line> &output) {
	reset_state_machine();
	while (offset < header.unit_end) {
		const uint8_t opcode = get_int<uint8_t>();
		switch (opcode) {
			case DW_LNS_extended_op: {
				const uint64_t extended_opcode_length(get_uleb128());
				const size_t offset_old(offset);
				const uint8_t extended_opcode(get_int<uint8_t>());
				switch (extended_opcode) {
					case DW_LNE_end_sequence:
						state_machine.end_sequence = true;
						emit_state_machine(output);
						reset_state_machine();
						break;
					case DW_LNE_set_address:
						state_machine.address = get_int(extended_opcode_length - (offset - offset_old));
						break;
					case DW_LNE_define_file: {
						const char * file_name = get_string();
						const uint64_t directory_index = get_uleb128();
						const uint64_t time = get_uleb128();
						const uint64_t size = get_uleb128();

						source_file file = {
							file_name,
							directory_index ? include_directories[directory_index - 1] : nullptr,
							time,
							size,
						};
						file_names.push_back(file);
					}
					case DW_LNE_set_discriminator:
						state_machine.discriminator = get_uleb128();
						break;
				}
				offset = offset_old + extended_opcode_length;
				break;
			}
			case DW_LNS_copy:
				emit_state_machine(output);
				state_machine.basic_block = false;
				state_machine.prologue_end = false;
				state_machine.epilogue_begin = false;
				state_machine.discriminator = 0;
				break;
			case DW_LNS_advance_pc:
				state_machine.address += get_uleb128() * header.minimum_instruction_length;
				break;
			case DW_LNS_advance_line:
				state_machine.line += get_sleb128();
				break;
			case DW_LNS_set_file:
				state_machine.file = get_uleb128();
				break;
			case DW_LNS_set_column:
				state_machine.column = get_uleb128();
				break;
			case DW_LNS_negate_stmt:
				state_machine.is_stmt = !state_machine.is_stmt;
				break;
			case DW_LNS_set_basic_block:
				state_machine.basic_block = true;
				break;
			case DW_LNS_const_add_pc:
				state_machine.address += (255 - header.opcode_base) / header.line_range * header.minimum_instruction_length;
				break;
			case DW_LNS_fixed_advance_pc:
				state_machine.address += get_int<uint16_t>();
				break;
			case DW_LNS_set_prologue_end:
				state_machine.prologue_end = true;
				break;
			case DW_LNS_set_epilogue_begin:
				state_machine.epilogue_begin = true;
				break;
			case DW_LNS_set_isa:
				state_machine.isa = get_uleb128();
				break;
			default: {
				if (opcode < header.opcode_base) {
					static_cast<void>(get_data(header.standard_opcode_lengths[opcode - 1]));
					break;
				}
				const uint8_t special_opcode(opcode - header.opcode_base);
				state_machine.address += special_opcode / header.line_range * header.minimum_instruction_length;
				state_machine.line += header.line_base + special_opcode % header.line_range;
				emit_state_machine(output);
				state_machine.basic_block = false;
				state_machine.prologue_end = false;
				state_machine.epilogue_begin = false;
				state_machine.discriminator = 0;
				break;
			}
		}
	}
}

template<typename ElfHeader, typename SectionHeader, typename SymbolEntry>
ElfParser<ElfHeader, SectionHeader, SymbolEntry>::ElfParser(const void * const data) :
	base(data) {
	const SectionHeader * const section_table(get_section_table());
	const char * const string_table = get_section_content<const char *>(section_table + get_header()->e_shstrndx);

	const uint16_t section_count(get_header()->e_shnum);
	for (int section_index(0); section_index < section_count; ++section_index) {
		const SectionHeader * const section(section_table + section_index);
		sections[string_table + section->sh_name] = section;
	}
}

template<typename ElfHeader, typename SectionHeader, typename SymbolEntry>
void ElfParser<ElfHeader, SectionHeader, SymbolEntry>::parse_symbols(std::map<uint64_t, Symbol> &symbols) {
	const SectionHeader *symbol_section(get_section(".symtab"));
	if (!symbol_section)
		return;

	if (symbol_section->sh_entsize != sizeof(SymbolEntry))
		return;

	const SymbolEntry *symbol_table(get_section_content<const SymbolEntry *>(symbol_section));
	const SectionHeader *section_table(get_section_table());
	const char *symbol_string_table(get_section_content<const char *>(section_table + symbol_section->sh_link));
	const int symbol_count(symbol_section->sh_size / sizeof(SymbolEntry));
	for (int symbol_index(0); symbol_index < symbol_count; ++symbol_index) {
		const SymbolEntry *symbol(symbol_table + symbol_index);
		const unsigned char type(ELF32_ST_TYPE(symbol->st_info));
		if (type == STT_FUNC || type == STT_NOTYPE) {
			Symbol sym = {symbol_string_table + symbol->st_name, symbol->st_size};
			symbols[symbol->st_value] = sym;
		}
	}
}

template<typename ElfHeader, typename SectionHeader, typename SymbolEntry>
void ElfParser<ElfHeader, SectionHeader, SymbolEntry>::parse_lines(std::map<uint64_t, Line> &lines) {
	const SectionHeader *line_section(get_section(".debug_line"));
	if (!line_section)
		return;

	DwarfParser(get_section_content<const void *>(line_section), line_section->sh_size).parse(lines);
}

template<typename ElfHeader, typename SectionHeader, typename SymbolEntry>
const ElfHeader * ElfParser<ElfHeader, SectionHeader, SymbolEntry>::get_header() const {
	return static_cast<const ElfHeader *>(base);
}

template<typename ElfHeader, typename SectionHeader, typename SymbolEntry>
const SectionHeader * ElfParser<ElfHeader, SectionHeader, SymbolEntry>::get_section_table() const {
	return reinterpret_cast<const SectionHeader *>(static_cast<const char *>(base) + get_header()->e_shoff);
}

template<typename ElfHeader, typename SectionHeader, typename SymbolEntry>
const SectionHeader * ElfParser<ElfHeader, SectionHeader, SymbolEntry>::get_section(const char * const section_name) const {
	typename std::map<std::string, const SectionHeader *>::const_iterator it(sections.find(section_name));
	return it == sections.end() ? nullptr : it->second;
}

template<typename ElfHeader, typename SectionHeader, typename SymbolEntry>
template<typename T>
T ElfParser<ElfHeader, SectionHeader, SymbolEntry>::get_section_content(const SectionHeader * const section) const {
	return reinterpret_cast<T>(static_cast<const char *>(base) + section->sh_offset);
}

DebugInfo::DebugInfo() :
	data(nullptr),
	strbuf(nullptr),
	size(0),
	fd(-1) {
}

bool DebugInfo::load(const char * const file_name) {
	fd = open(file_name, O_RDONLY);
	if (fd < 0) {
		perror("open");
		return true;
	}

	struct stat sb;
	if (fstat(fd, &sb) == -1) {
		perror("fstat");
		return true;
	}
	size = sb.st_size;

	data = mmap(nullptr, size, PROT_READ, MAP_SHARED, fd, 0);
	if (data == MAP_FAILED) {
		perror("mmap");
		return true;
	}

	if (memcmp(data, ELFMAG, 4) != 0) {
		// assume the file to be a MAP file
		strbuf = static_cast<char *>(malloc(size));
		MapParser(data, size).parse_map(symbols, strbuf);
	} else {
		// assume the file to be an ELF file
		const unsigned char *elf_ident(static_cast<const unsigned char*>(data));
		if (elf_ident[EI_CLASS] == ELFCLASS32) {
			Elf32Parser elf_parser(data);
			elf_parser.parse_symbols(symbols);
			elf_parser.parse_lines(lines);
		} else if (elf_ident[EI_CLASS] == ELFCLASS64) {
			Elf64Parser elf_parser(data);
			elf_parser.parse_symbols(symbols);
			elf_parser.parse_lines(lines);
		}
	}

	return false;
}

DebugInfo::~DebugInfo() {
	if (data && data != MAP_FAILED) {
		munmap(const_cast<void *>(data), size);
		data = nullptr;
	}
	if (fd >= 0) {
		close(fd);
		fd = -1;
	}
	if (strbuf) {
		free(strbuf);
		strbuf = nullptr;
	}
}

void DebugInfo::print_symbols() const {
	for (std::map<uint64_t, Symbol>::const_iterator it(symbols.begin()); it != symbols.end(); ++it)
		fmt::print("{:#x} ({}) -> {}\n", it->first, it->second.size, it->second.name);
}

bool DebugInfo::find_symbol(uint64_t address, const char **name, uint64_t *offset) const {
	if (symbols.empty())
		return false;

	std::map<uint64_t, Symbol>::const_iterator it(symbols.upper_bound(address));
	do {
		--it;
		if (it == symbols.end())
			return false;
		*name = it->second.name;
		*offset = address - it->first;
	} while(it->second.size && *offset >= it->second.size);
	return true;
}

bool DebugInfo::find_line(uint64_t address, const char **file, const char **directory, uint64_t *line, uint64_t *column) const {
	if (lines.empty())
		return false;

	std::map<uint64_t, Line>::const_iterator it(lines.upper_bound(address));
	--it;
	if (it == lines.end())
		return false;
	*file = it->second.file;
	*directory = it->second.directory;
	*line = it->second.line;
	*column = it->second.column;
	return true;
}

int main(int argc, const char *argv[]) {
	if (argc < 2) {
		fmt::print("usage: {} <file> [<address 1> [<address 2> [...]]]\n", argv[0]);
		return EXIT_FAILURE;
	}

	DebugInfo debug_info;
	debug_info.load(argv[1]);

	if (argc >= 3) {
		for (int argi(2); argi < argc; ++argi) {
			const uint64_t address = strtoull(argv[argi], nullptr, 16);
			const char *name, *file, *directory;
			uint64_t offset, line, column;
			fmt::print("address: {:#x}\n", address);
			if (debug_info.find_symbol(address, &name, &offset))
				fmt::print("label: {}\noffset: {}\n", name, offset);
			else
				fmt::print("label not found\n");
			if (debug_info.find_line(address, &file, &directory, &line, &column))
				fmt::print("file: {}\ndirectory: {}\nline: {}\ncolumn: {}\n", file, directory ?: "<none>", line, column);
		}
	} else {
		debug_info.print_symbols();
	}

	return EXIT_SUCCESS;
}
