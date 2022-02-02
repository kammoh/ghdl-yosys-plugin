/*
  Copyright (C) 2020  Ryan Lee <rlee287@yahoo.com>

  This program is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program.  If not, see <https://www.gnu.org/licenses/>.

*/

/*
 * A VHDL backend based on the Verilog backend.
 * Code structure here is regularly synced with the Verilog backend, except
 * where noted Last synced against Yosys 871fc34a The commit above references
 * the last commit that changed the Verilog backend
 */

#include "kernel/celltypes.h"
#include "kernel/ff.h"
#include "kernel/log.h"
#include "kernel/mem.h"
#include "kernel/register.h"
#include "kernel/sigtools.h"

#include <map>
#include <set>
#include <sstream>
#include <string>

USING_YOSYS_NAMESPACE
PRIVATE_NAMESPACE_BEGIN

bool std08, verbose, norename, noattr, attr2comment, noexpr, nodec, nohex, nostr, extmem, siminit,
    nosimple_lhs, unisim;
int auto_name_counter, auto_name_offset, auto_name_digits, extmem_counter;
std::map<RTLIL::IdString, int> auto_name_map;
std::set<RTLIL::IdString> reg_wires;
std::string auto_prefix, extmem_prefix;

RTLIL::Module *active_module;
dict<RTLIL::SigBit, RTLIL::State> active_initdata;
std::set<unsigned int> memory_array_types;
SigMap active_sigmap;

inline std::string NEXT_INDENT(const std::string &indent) { return indent + "  "; }

// Automatically increase indent inside a code-block
// At the end of the block, the inner 'indent' will go out of scope and
//   the (unmodified) outer indent will be available
#define INDENT                                                                                     \
    std::string __prev_indent__ = indent;                                                          \
    std::string indent = NEXT_INDENT(__prev_indent__);

enum VhdlType : unsigned char {
    VHDL_UNKNOWN = 0,
    VHDL_BIT = 1,
    VHDL_VECTOR = 2,
    VHDL_NUMERIC = 4,
};

// TODO map for type of external instance (e.g. FPGA lib) generics
auto inst_generic_types = std::map<std::pair<std::string, std::string>, VhdlType>();

// ASCII control character mapping
const char *const ctrl_char_array[] = { "NUL", "SOH", "STX", "ETX", "EOT", "ENQ", "ACK", "BEL",
    "BS", "HT", "LF", "VT", "FF", "CR", "SO", "SI", "DLE", "DC1", "DC2", "DC3", "DC4", "NAK", "SYN",
    "ETB", "CAN", "EM", "SUB", "ESC", "FSP", "GSP", "RSP", "USP" };

std::set<RTLIL::SigChunk> get_sensitivity_set(RTLIL::SigSpec sigspec)
{
    std::set<RTLIL::SigChunk> wire_chunks;
    for (RTLIL::SigChunk chunk : sigspec.chunks()) {
        // Copied from const checks in SigChunk
        // TODO: call pack()?
        if (chunk.width > 0 && chunk.wire != NULL) {
            wire_chunks.emplace(chunk);
        }
    }
    return wire_chunks;
}

std::set<RTLIL::SigChunk> get_sensitivity_set(std::set<RTLIL::SigSpec> sigspecs)
{
    std::set<RTLIL::SigChunk> wire_chunks;
    for (RTLIL::SigSpec sigspec : sigspecs) {
        std::set<RTLIL::SigChunk> wires_in_chunk;
        wires_in_chunk = get_sensitivity_set(sigspec);
        wire_chunks.insert(wires_in_chunk.begin(), wires_in_chunk.end());
    }
    return wire_chunks;
}

// Takes precedence for braced initialization
std::set<RTLIL::SigChunk> get_sensitivity_set(std::initializer_list<RTLIL::SigSpec> sigspecs)
{
    std::set<RTLIL::SigChunk> wire_chunks;
    for (RTLIL::SigSpec sigspec : sigspecs) {
        std::set<RTLIL::SigChunk> wires_in_chunk;
        wires_in_chunk = get_sensitivity_set(sigspec);
        wire_chunks.insert(wires_in_chunk.begin(), wires_in_chunk.end());
    }
    return wire_chunks;
}

// TODO: void dump_sensitivity_set(std::set<RTLIL::SigChunk>)?

void reset_auto_counter_id(RTLIL::IdString id, bool may_rename)
{ // NO PORTING REQUIRED
    const char *str = id.c_str();

    if (*str == '$' && may_rename && !norename)
        auto_name_map[id] = auto_name_counter++;

    if (str[0] != '\\' || str[1] != '_' || str[2] == 0)
        return;

    for (int i = 2; str[i] != 0; i++) {
        if (str[i] == '_' && str[i + 1] == 0)
            continue;
        if (str[i] < '0' || str[i] > '9')
            return;
    }

    int num = atoi(str + 2);
    if (num >= auto_name_offset)
        auto_name_offset = num + 1;
}

void reset_auto_counter(RTLIL::Module *module)
{ // PORTING NEEDS TESTING
    auto_name_map.clear();
    auto_name_counter = 0;
    auto_name_offset = 0;

    reset_auto_counter_id(module->name, false);

    for (auto w : module->wires())
        reset_auto_counter_id(w->name, true);

    for (auto cell : module->cells()) {
        reset_auto_counter_id(cell->name, true);
        reset_auto_counter_id(cell->type, false);
    }

    for (auto it = module->processes.begin(); it != module->processes.end(); ++it)
        reset_auto_counter_id(it->second->name, false);

    auto_name_digits = 1;
    for (size_t i = 10; i < auto_name_offset + auto_name_map.size(); i = i * 10)
        auto_name_digits++;

    if (verbose)
        for (auto it = auto_name_map.begin(); it != auto_name_map.end(); ++it)
            log("  renaming `%s' to `%s%0*d'.\n", it->first.c_str(), auto_prefix.c_str(),
                auto_name_digits, auto_name_offset + it->second);
}

std::string next_auto_id()
{ // PORTING NEEDS TESTING
    return stringf(
        "%s%0*d", auto_prefix.c_str(), auto_name_digits, auto_name_offset + auto_name_counter++);
}

std::string id(RTLIL::IdString internal_id, bool may_rename = true)
{ // PORTING NEEDS TESTING
    const char *str = internal_id.c_str();
    bool do_escape = false;

    if (may_rename && auto_name_map.count(internal_id) != 0)
        return stringf("%s%0*d", auto_prefix.c_str(), auto_name_digits,
            auto_name_offset + auto_name_map[internal_id]);

    if (*str == '\\')
        str++;

    if ('0' <= *str && *str <= '9')
        do_escape = true;

    for (int i = 0; str[i]; i++) {
        if ('0' <= str[i] && str[i] <= '9')
            continue;
        if ('a' <= str[i] && str[i] <= 'z')
            continue;
        if ('A' <= str[i] && str[i] <= 'Z')
            continue;
        if (str[i] == '_')
            continue;
        do_escape = true;
        break;
    }

    /*
     * This backend outputs VHDL-93 but maximize compatibility with 08
     * This includes catching all the PSL keywords as well
     */
    const pool<string> vhdl_keywords = { // IEEE 1076-2008 Section 15.10
        "abs", "access", "after", "alias", "all", "and", "architecture", "array", "assert",
        "assume", "assume_guarantee", "attribute", "begin", "block", "body", "buffer", "bus",
        "case", "component", "configuration", "constant", "context", "cover", "default",
        "disconnect", "downto", "else", "elsif", "end", "entity", "exit", "fairness", "file", "for",
        "force", "function", "generate", "generic", "group", "guarded", "if", "impure", "in",
        "inertial", "inout", "is", "label", "library", "linkage", "literal", "loop", "map", "mod",
        "nand", "new", "next", "nor", "not", "null", "of", "on", "open", "or", "others", "out",
        "package", "parameter", "port", "postponed", "procedure", "process", "property",
        "protected", "pure", "range", "record", "register", "reject", "release", "rem", "report",
        "restrict", "restrict_guarantee", "return", "rol", "ror", "select", "sequence", "severity",
        "shared", "signal", "sla", "sll", "sra", "srl", "strong", "subtype", "then", "to",
        "transport", "type", "unaffected", "units", "until", "use", "variable", "vmode", "vprop",
        "vunit", "wait", "when", "while", "with", "xnor", "xor"
    };
    const pool<string> psl_keywords = { // IEEE 1076-2008 Section 15.10
        "assert", "assume", "assume_guarantee", "cover", "default", "fairness", "property",
        "restrict", "restrict_guarantee", "sequence", "strong", "vmode", "vprop", "vunit"
    };
    if (vhdl_keywords.count(str) || psl_keywords.count(str))
        do_escape = true;
    // TODO: check for numbers afterwards, but regex is overkill here
    // array_type_(width) is used by the memory dump pass
    if (strncmp(str, "array_type_", strlen("array_type_")) == 0)
        do_escape = true;
    if (strncmp(str, "ivar_", strlen("ivar_")) == 0)
        do_escape = true;

    if (do_escape)
        // VHDL extended identifier
        return "\\" + std::string(str) + "\\";
    return std::string(str);
}

void dump_sigchunk(std::ostream &f, const RTLIL::SigChunk &chunk, bool no_decimal = false);

void dump_sig_equal_bool(std::ostream &f, RTLIL::SigSpec sig, bool const_compare)
{
    if (sig.is_chunk()) {
        dump_sigchunk(f, sig.as_chunk(), false);
    }
    else {
        f << id(sig.as_bit().wire->name);
    }
    f << stringf(" = '%c'", const_compare ? '1' : '0');
}
/*
 * Generate common syntax of comparing std_logic to a constant
 * Bit conversion function (for conversion from SigSpecs) has width assertion
 */
// std::string sigbit_equal_bool(RTLIL::SigBit sigBit, bool const_compare)
// {
//     // Assert that sigBit is not const
//     log_assert(sigBit.wire != NULL);
//     // TODO: Internal testing, delete
//     // log_assert(sigSpec.as_chunk().wire->name =)
//     return stringf("%s = '%c'", id(sigBit.wire->name).c_str(), const_compare ? '1' : '0');
// }

bool is_reg_wire(RTLIL::SigSpec sig, std::string &reg_name)
{ // PORTING NEEDS TESTING
    if (!sig.is_chunk() || sig.as_chunk().wire == NULL)
        return false;

    RTLIL::SigChunk chunk = sig.as_chunk();

    if (reg_wires.count(chunk.wire->name) == 0)
        return false;

    reg_name = id(chunk.wire->name);
    if (sig.size() != chunk.wire->width) {
        if (sig.size() == 1)
            reg_name += stringf("(%d)", chunk.wire->start_offset + chunk.offset);
        else if (chunk.wire->upto)
            reg_name += stringf("(%d to %d)",
                (chunk.wire->width - (chunk.offset + chunk.width - 1) - 1) +
                    chunk.wire->start_offset,
                (chunk.wire->width - chunk.offset - 1) + chunk.wire->start_offset);
        else
            reg_name +=
                stringf("(%d downto %d)", chunk.wire->start_offset + chunk.offset + chunk.width - 1,
                    chunk.wire->start_offset + chunk.offset);
    }

    return true;
}

// convert Const::bits to a vector of char representations
inline std::vector<char> bits_to_binary(const RTLIL::Const &data)
{
    std::vector<char> bin_digits;
    for (auto bit : data.bits) {
        switch (bit) {
        case State::S0:
            bin_digits.push_back('0');
            break;
        case State::S1:
            bin_digits.push_back('1');
            break;
        case RTLIL::Sx:
            bin_digits.push_back('X');
            break;
        case RTLIL::Sz:
            bin_digits.push_back('Z');
            break;
        case RTLIL::Sa:
            bin_digits.push_back('-');
            break;
        case RTLIL::Sm:
            log_error("Found marker state in final netlist.");
        }
    }
    return bin_digits;
}

void dump_const(std::ostream &f, const RTLIL::Const &const_data, int width = -1, int offset = 0,
    bool no_decimal = false, VhdlType vhdl_type = VhdlType::VHDL_UNKNOWN)
{ // PORTING NEEDS TESTING
    if (width == 0) {
        f << "(others => '0')"; // "" ? TODO
        return;
    }

    RTLIL::Const data = const_data;

    if (vhdl_type == VhdlType::VHDL_UNKNOWN) {
        if ((data.flags == RTLIL::CONST_FLAG_NONE) && (width == 1)) {
            vhdl_type = VhdlType::VHDL_BIT; // ????
        }
        else if (!no_decimal && !nodec && (data.size() == 32) && (width == -1)) {
            vhdl_type = VhdlType::VHDL_NUMERIC;
        }
    }
    //  width=-1 -> infer width from data.size
    if (width == -1) {
        width = data.size() - offset;
    }

    if (offset > 0 || width != data.size()) {
        data = data.extract(offset, width); // 0 pads if width > size
    }

    if (data.flags & RTLIL::CONST_FLAG_REAL) {
        log_error("unhandled CONST_FLAG_REAL");
        return;
    }

    if (data.flags & RTLIL::CONST_FLAG_STRING) {
        f << stringf("\"");
        std::string str = data.decode_string();
        for (size_t i = 0; i < str.size(); i++) {
            unsigned char current_char_unsigned = (unsigned char)str[i];
            /*
             * See the following IEEE 1076-2008 sections:
             * 15.7 "Character Set"
             * 15.9 "String Literals"
             * 16.3 "Package STANDARD"
             */
            if (current_char_unsigned < 32)
                f << stringf("\" & %s & \"", ctrl_char_array[current_char_unsigned]);
            else if (current_char_unsigned >= 128 && current_char_unsigned <= 159)
                f << stringf("\" & C%d & \"", current_char_unsigned);
            else if (str[i] == '"')
                f << stringf("\"\"");
            else
                f << str[i];
        }
        f << stringf("\"");
        return;
    }

    if (vhdl_type == VhdlType::VHDL_NUMERIC) {
        f << data.as_int(data.flags & RTLIL::CONST_FLAG_SIGNED);
        return;
    }

    bool dump_bin = nohex;

    std::vector<char> hex_digits;
    std::vector<char> bin_digits = bits_to_binary(data);
    if (vhdl_type == VhdlType::VHDL_BIT) {
        log_assert(GetSize(bin_digits) == 1);
        f << "'" << bin_digits[0] << "'";
        return;
    }
    int leftovers = bin_digits.size() % 4;
    if (std08) { // extend with zeros and add width prefix
        for (int i = 0; i < leftovers; i++) {
            bin_digits.push_back('0');
        }
        leftovers = 0;
    }

    for (int i = 0; !dump_bin && (i < GetSize(bin_digits) - leftovers); i += 4) {
        char bit_3 = bin_digits[i + 3];
        char bit_2 = bin_digits[i + 2];
        char bit_1 = bin_digits[i + 1];
        char bit_0 = bin_digits[i + 0];
        if (bit_3 == 'X' || bit_2 == 'X' || bit_1 == 'X' || bit_0 == 'X') {
            if (bit_3 != 'X' || bit_2 != 'X' || bit_1 != 'X' || bit_0 != 'X')
                dump_bin = true;
            hex_digits.push_back('X');
            continue;
        }
        if (bit_3 == 'Z' || bit_2 == 'Z' || bit_1 == 'Z' || bit_0 == 'Z') {
            if (bit_3 != 'Z' || bit_2 != 'Z' || bit_1 != 'Z' || bit_0 != 'Z')
                dump_bin = true;
            hex_digits.push_back('Z');
            continue;
        }
        if (bit_3 == '-' || bit_2 == '-' || bit_1 == '-' || bit_0 == '-') {
            if (bit_3 != '-' || bit_2 != '-' || bit_1 != '-' || bit_0 != '-')
                dump_bin = true;
            hex_digits.push_back('-');
            continue;
        }
        int val = 8 * (bit_3 - '0') + 4 * (bit_2 - '0') + 2 * (bit_1 - '0') + (bit_0 - '0');
        hex_digits.push_back(val < 10 ? '0' + val : 'a' + val - 10);
    }

    if (dump_bin || hex_digits.size() == 0) {
        f << "\"" << std::string(bin_digits.rbegin(), bin_digits.rend()) << "\"";
        return;
    }
    if (std08) { // extend with zeros and add width prefix
        f << data.bits.size();
    }
    else if (leftovers) {
        f << "(";
        f << "\"" << std::string(bin_digits.rbegin(), bin_digits.rbegin() + leftovers) << "\" & ";
    }
    f << "x\"" << std::string(hex_digits.rbegin(), hex_digits.rend()) << "\"";
    if (leftovers) {
        f << ")";
    }
}

void dump_reg_init(std::ostream &f, SigSpec sig)
{ // PORTING NEEDS TESTING
    Const initval;
    bool gotinit = false;

    for (auto bit : active_sigmap(sig)) {
        if (active_initdata.count(bit)) {
            initval.bits.push_back(active_initdata.at(bit));
            gotinit = true;
        }
        else {
            initval.bits.push_back(State::Sx);
        }
    }

    if (gotinit) {
        f << " := ";
        dump_const(f, initval);
    }
}

void dump_sigchunk(std::ostream &f, const RTLIL::SigChunk &chunk, bool no_decimal)
{ // PORTING NEEDS TESTING
    if (chunk.wire == NULL) {
        dump_const(f, chunk.data, chunk.width, chunk.offset, no_decimal);
    }
    else {
        if (chunk.width == chunk.wire->width && chunk.offset == 0) {
            f << id(chunk.wire->name);
        }
        else if (chunk.width == 1) {
            if (chunk.wire->upto)
                f << stringf("%s(%d)", id(chunk.wire->name).c_str(),
                    (chunk.wire->width - chunk.offset - 1) + chunk.wire->start_offset);
            else
                f << stringf("%s(%d)", id(chunk.wire->name).c_str(),
                    chunk.offset + chunk.wire->start_offset);
        }
        else {
            if (chunk.wire->upto)
                f << stringf("%s(%d to %d)", id(chunk.wire->name).c_str(),
                    (chunk.wire->width - (chunk.offset + chunk.width - 1) - 1) +
                        chunk.wire->start_offset,
                    (chunk.wire->width - chunk.offset - 1) + chunk.wire->start_offset);
            else
                f << stringf("%s(%d downto %d)", id(chunk.wire->name).c_str(),
                    (chunk.offset + chunk.width - 1) + chunk.wire->start_offset,
                    chunk.offset + chunk.wire->start_offset);
        }
    }
}

void dump_sigspec(std::ostream &f, const RTLIL::SigSpec &sig, bool lhs_mode = false)
{ // PORTING NEEDS TESTING
    if (sig.size() == 0) {
        // TODO this is a null range that may not be handled correctly
        f << "\"\"";
        return;
    }
    if (sig.is_chunk()) {
        dump_sigchunk(f, sig.as_chunk());
    }
    else {
        // LHS mode is for the LHS of expressions like (a, b) <= c in VHDL-2008
        // mode
        if (lhs_mode && !std08) {
            // TODO: this is only a warning because other codegen stuff is still
            // generating 2008 syntax outside of VHDL-2008 mode This should be
            // converted into an error once that is fixed
            log_warning("%s", "dump_sigspec called for multi-chunk LHS output when "
                              "not in VHDL-2008 mode\n");
        }
        if (lhs_mode) {
            f << "(";
        }
        for (auto it = sig.chunks().rbegin(); it != sig.chunks().rend(); ++it) {
            if (it != sig.chunks().rbegin())
                f << stringf(lhs_mode ? ", " : " & ");
            dump_sigchunk(f, *it, true);
        }
        if (lhs_mode) {
            f << ")";
        }
    }
}

std::string wire_typestr(RTLIL::Wire *wire)
{
    if (wire->width != 1) {
        if (wire->upto)
            return stringf("std_logic_vector(%d to %d)", wire->start_offset,
                wire->width - 1 + wire->start_offset);
        else
            return stringf("std_logic_vector(%d downto %d)", wire->width - 1 + wire->start_offset,
                wire->start_offset);
    }
    return stringf("std_logic");
}

std::string sig_decl_type(std::string &name, int width, bool is_var)
{
    std::ostringstream ss;
    ss << (is_var ? "variable " : "signal ") << name << " : ";

    if (width > 1) {
        ss << "std_logic_vector(" << width - 1 << " downto 0)";
    }
    else {
        ss << "std_logic";
    }
    return ss.str();
}

/*
 * Returns a string of the form "chunk_1, chunk_2, chunk_3"
 * Intended use is populating process sensitivity lists
 * Assumes that set is from get_sensitivity_set, i.e. no constant chunks
 */
std::string process_sensitivity_str(std::set<RTLIL::SigChunk> chunks)
{
    bool is_first_element = true;
    std::stringstream result_gather;
    for (RTLIL::SigChunk sigchunk : chunks) {
        if (is_first_element) {
            is_first_element = false;
        }
        else {
            result_gather << ", ";
        }
        dump_sigchunk(result_gather, sigchunk);
    }
    return result_gather.str();
}

void dump_attributes(std::ostream &f, std::string indent,
    dict<RTLIL::IdString, RTLIL::Const> &attributes, bool modattr = false, bool regattr = false,
    bool as_comment = false)
{ // PORTING REQUIRED
    if (noattr)
        return;
    if (attr2comment)
        as_comment = true;
    for (auto it = attributes.begin(); it != attributes.end(); ++it) {
        if (it->first == ID::init && regattr)
            continue;
        f << indent << "-- ATTRIBUTE " << id(it->first) << " = "; // TODO actual VHDL attributes?
        if (modattr && (it->second == State::S0 || it->second == Const(0)))
            f << stringf(" 0 ");
        else if (modattr && (it->second == State::S1 || it->second == Const(1)))
            f << stringf(" 1 ");
        else
            dump_const(f, it->second, -1, 0, false);
        // f << stringf(" %s\n", as_comment ? "*/" : "*)");
        f << stringf("\n");
    }
}

void dump_wire(std::ostream &f, std::string indent, RTLIL::Wire *wire)
{ // PORTING NEEDS TESTING
    // Ports are dumped earlier in entity declaration, so ignore them here
    dump_attributes(f, indent, wire->attributes, /*modattr=*/false,
        /*regattr=*/reg_wires.count(wire->name));
    std::string typestr = wire_typestr(wire);

    if (!wire->port_input && !wire->port_output) {
        f << indent << "signal " << id(wire->name) << ": " << typestr;
        if (reg_wires.count(wire->name) && wire->attributes.count(ID::init)) {
            f << " := ";
            dump_const(f, wire->attributes.at(ID::init));
        }
        f << ";\n";
    }
}

// We split Verilog backend's dump_memory into two functions
void dump_memory_types(std::ostream &f, std::string indent, Mem &mem)
{ // PORTING COMPLETE
    size_t is_element_present = memory_array_types.count(mem.width);
    std::string memory_type_name = stringf("array_type_%d", mem.width);
    if (!is_element_present) {
        memory_array_types.insert(mem.width);
        f << stringf("%s"
                     "type %s is array (natural range <>) of std_logic_vector(%d "
                     "downto 0)\n",
            indent.c_str(), memory_type_name.c_str(), mem.width - 1);
    }
    dump_attributes(f, indent, mem.attributes);
    // TODO: if memory->size is always positive then this is unnecessary
    std::string range_str = stringf("(%d %s %d)", mem.start_offset + mem.size - 1,
        mem.size >= 0 ? "downto" : "to", mem.start_offset);
    // TODO: memory initialization?
    f << stringf("%s"
                 "signal %s: %s %s;\n",
        indent.c_str(), id(mem.memid).c_str(), memory_type_name.c_str(), range_str.c_str());
}

// Function signature will change when porting
void dump_memory(std::ostream &f, std::string indent, Mem &mem)
{ // PORTING REQUIRED
    std::string mem_id = id(mem.memid);
    f << stringf("-- Memory cell %s\n", mem_id.c_str());

    // for memory block make something like:
    //  reg [7:0] memid [3:0];
    //  initial begin
    //    memid[0] = ...
    //  end
    if (!mem.inits.empty()) {
        if (extmem) {
            std::string extmem_filename =
                stringf("%s-%d.mem", extmem_prefix.c_str(), extmem_counter++);

            std::string extmem_filename_esc;
            for (auto c : extmem_filename) {
                if (c == '\n')
                    extmem_filename_esc += "\\n";
                else if (c == '\t')
                    extmem_filename_esc += "\\t";
                else if (c < 32)
                    extmem_filename_esc += stringf("\\%03o", c);
                else if (c == '"')
                    extmem_filename_esc += "\\\"";
                else if (c == '\\')
                    extmem_filename_esc += "\\\\";
                else
                    extmem_filename_esc += c;
            }
            f << stringf("%s"
                         "initial $readmemb(\"%s\", %s);\n",
                indent.c_str(), extmem_filename_esc.c_str(), mem_id.c_str());

            std::ofstream extmem_f(extmem_filename, std::ofstream::trunc);
            if (extmem_f.fail())
                log_error("Can't open file `%s' for writing: %s\n", extmem_filename.c_str(),
                    strerror(errno));
            else {
                Const data = mem.get_init_data();
                for (int i = 0; i < mem.size; i++) {
                    RTLIL::Const element = data.extract(i * mem.width, mem.width);
                    for (int j = 0; j < element.size(); j++) {
                        switch (element[element.size() - j - 1]) {
                        case State::S0:
                            extmem_f << '0';
                            break;
                        case State::S1:
                            extmem_f << '1';
                            break;
                        case State::Sx:
                            extmem_f << 'x';
                            break;
                        case State::Sz:
                            extmem_f << 'z';
                            break;
                        case State::Sa:
                            extmem_f << '_';
                            break;
                        case State::Sm:
                            log_error("Found marker state in final netlist.");
                        }
                    }
                    extmem_f << '\n';
                }
            }
        }
        else {
            f << stringf("%s"
                         "initial begin\n",
                indent.c_str());
            for (auto &init : mem.inits) {
                int words = GetSize(init.data) / mem.width;
                int start = init.addr.as_int();
                for (int i = 0; i < words; i++) {
                    f << stringf("%s"
                                 "  %s[%d] = ",
                        indent.c_str(), mem_id.c_str(), i + start);
                    dump_const(f, init.data.extract(i * mem.width, mem.width));
                    f << ";\n";
                }
            }
            f << stringf("%s"
                         "end\n",
                indent.c_str());
        }
    }

    // create a map : "edge clk" -> expressions within that clock domain
    dict<std::string, std::vector<std::string>> clk_to_lof_body;
    clk_to_lof_body[""] = std::vector<std::string>();
    std::string clk_domain_str;
    // create a list of reg declarations
    std::vector<std::string> lof_reg_declarations;

    // read ports
    for (auto &port : mem.rd_ports) {
        if (port.clk_enable) {
            {
                std::ostringstream os;
                dump_sigspec(os, port.clk);
                clk_domain_str =
                    stringf("%sedge %s", port.clk_polarity ? "pos" : "neg", os.str().c_str());
                if (clk_to_lof_body.count(clk_domain_str) == 0)
                    clk_to_lof_body[clk_domain_str] = std::vector<std::string>();
            }
            bool transparent = false;
            for (int j = 0; j < GetSize(mem.wr_ports); j++) {
                if (port.transparency_mask[j]) {
                    // Our implementation of transparent read ports reads en,
                    // addr and data from every write port the read port is
                    // transparent with.
                    transparent = true;
                }
            }
            if (!transparent) {
                // for clocked read ports make something like:
                //   reg [..] temp_id;
                //   always @(posedge clk)
                //      if (rd_en) temp_id <= array_reg[r_addr];
                //   assign r_data = temp_id;
                std::string temp_id = next_auto_id();
                lof_reg_declarations.push_back(
                    stringf("reg [%d:0] %s;\n", port.data.size() - 1, temp_id.c_str()));
                {
                    std::ostringstream os;
                    if (port.en != RTLIL::SigBit(true)) {
                        os << stringf("if (");
                        dump_sigspec(os, port.en);
                        os << stringf(") ");
                    }
                    os << stringf("%s <= %s[", temp_id.c_str(), mem_id.c_str());
                    dump_sigspec(os, port.addr);
                    os << stringf("];\n");
                    clk_to_lof_body[clk_domain_str].push_back(os.str());
                }
                {
                    std::ostringstream os;
                    dump_sigspec(os, port.data);
                    std::string line =
                        stringf("assign %s = %s;\n", os.str().c_str(), temp_id.c_str());
                    clk_to_lof_body[""].push_back(line);
                }
            }
            else {
                // for rd-transparent read-ports make something like:
                //   reg [..] temp_id;
                //   always @(posedge clk)
                //     temp_id <= r_addr;
                //   assign r_data = array_reg[temp_id];
                std::string temp_id = next_auto_id();
                lof_reg_declarations.push_back(
                    stringf("reg [%d:0] %s;\n", port.addr.size() - 1, temp_id.c_str()));
                {
                    std::ostringstream os;
                    dump_sigspec(os, port.addr);
                    std::string line = stringf("%s <= %s;\n", temp_id.c_str(), os.str().c_str());
                    clk_to_lof_body[clk_domain_str].push_back(line);
                }
                {
                    std::ostringstream os;
                    dump_sigspec(os, port.data);
                    std::string line = stringf(
                        "assign %s = %s[%s];\n", os.str().c_str(), mem_id.c_str(), temp_id.c_str());
                    clk_to_lof_body[""].push_back(line);
                }
            }
        }
        else {
            // for non-clocked read-ports make something like:
            //   assign r_data = array_reg[r_addr];
            std::ostringstream os, os2;
            dump_sigspec(os, port.data);
            dump_sigspec(os2, port.addr);
            std::string line = stringf(
                "assign %s = %s[%s];\n", os.str().c_str(), mem_id.c_str(), os2.str().c_str());
            clk_to_lof_body[""].push_back(line);
        }
    }

    // write ports
    for (auto &port : mem.wr_ports) {
        {
            std::ostringstream os;
            dump_sigspec(os, port.clk);
            clk_domain_str =
                stringf("%sedge %s", port.clk_polarity ? "pos" : "neg", os.str().c_str());
            if (clk_to_lof_body.count(clk_domain_str) == 0)
                clk_to_lof_body[clk_domain_str] = std::vector<std::string>();
        }
        //   make something like:
        //   always @(posedge clk)
        //      if (wr_en_bit) memid[w_addr][??] <= w_data[??];
        //   ...
        for (int i = 0; i < GetSize(port.en); i++) {
            int start_i = i, width = 1;
            SigBit wen_bit = port.en[i];

            while (
                i + 1 < GetSize(port.en) && active_sigmap(port.en[i + 1]) == active_sigmap(wen_bit))
                i++, width++;

            if (wen_bit == State::S0)
                continue;

            std::ostringstream os;
            if (wen_bit != State::S1) {
                os << stringf("if (");
                dump_sigspec(os, wen_bit);
                os << stringf(") ");
            }
            os << stringf("%s[", mem_id.c_str());
            dump_sigspec(os, port.addr);
            if (width == GetSize(port.en))
                os << stringf("] <= ");
            else
                os << stringf("][%d:%d] <= ", i, start_i);
            dump_sigspec(os, port.data.extract(start_i, width));
            os << stringf(";\n");
            clk_to_lof_body[clk_domain_str].push_back(os.str());
        }
    }
    // Output Verilog that looks something like this:
    // reg [..] _3_;
    // always @(posedge CLK2) begin
    //   _3_ <= memory[D1ADDR];
    //   if (A1EN)
    //     memory[A1ADDR] <= A1DATA;
    //   if (A2EN)
    //     memory[A2ADDR] <= A2DATA;
    //   ...
    // end
    // always @(negedge CLK1) begin
    //   if (C1EN)
    //     memory[C1ADDR] <= C1DATA;
    // end
    // ...
    // assign D1DATA = _3_;
    // assign D2DATA <= memory[D2ADDR];

    // the reg ... definitions
    for (auto &reg : lof_reg_declarations) {
        f << stringf("%s"
                     "%s",
            indent.c_str(), reg.c_str());
    }
    // the block of expressions by clock domain
    for (auto &pair : clk_to_lof_body) {
        std::string clk_domain = pair.first;
        std::vector<std::string> lof_lines = pair.second;
        if (clk_domain != "") {
            f << stringf("%s"
                         "always @(%s) begin\n",
                indent.c_str(), clk_domain.c_str());
            for (auto &line : lof_lines)
                f << stringf("%s%s"
                             "%s",
                    indent.c_str(), indent.c_str(), line.c_str());
            f << stringf("%s"
                         "end\n",
                indent.c_str());
        }
        else {
            // the non-clocked assignments
            for (auto &line : lof_lines)
                f << stringf("%s"
                             "%s",
                    indent.c_str(), line.c_str());
        }
    }
}

// TODO: document results of gen_signed, gen_unsigned
void dump_cell_expr_port(std::ostream &f, RTLIL::Cell *cell, std::string port,
    bool gen_signed = true, bool gen_unsigned = false)
{ // PORTING NEEDS TESTING
    SigSpec signal_spec = cell->getPort("\\" + port);
    bool signal_is_const = signal_spec.is_fully_const();
    bool signal_is_chunk = signal_spec.is_chunk();
    if (gen_signed && !signal_is_const && cell->parameters.count("\\" + port + "_SIGNED") > 0 &&
        cell->parameters["\\" + port + "_SIGNED"].as_bool()) {
        // TODO check how signed arithmetic interacts with x"blah" constants
        f << stringf("signed(");
        dump_sigspec(f, signal_spec);
        f << stringf(")");
    }
    else if (gen_unsigned && !signal_is_const) {
        f << stringf("unsigned(");
        dump_sigspec(f, signal_spec);
        f << stringf(")");
    }
    else {
        // Put parentheses around concatenation of nets
        // Prevent operator precedence things, and make code more readable
        if (!signal_is_chunk) {
            f << stringf("(");
        }
        dump_sigspec(f, signal_spec);
        if (!signal_is_chunk) {
            f << stringf(")");
        }
    }
}

std::string cellname(RTLIL::Cell *cell)
{ // PORTING NEEDS TESTING
    if (!norename && cell->name[0] == '$' && RTLIL::builtin_ff_cell_types().count(cell->type) &&
        cell->hasPort(ID::Q) && !cell->type.in(ID($ff), ID($_FF_))) {
        RTLIL::SigSpec sig = cell->getPort(ID::Q);
        if (GetSize(sig) != 1 || sig.is_fully_const())
            goto no_special_reg_name;

        RTLIL::Wire *wire = sig[0].wire;

        if (wire->name[0] != '\\')
            goto no_special_reg_name;

        std::string cell_name = wire->name.str();

        size_t pos = cell_name.find('[');
        if (pos != std::string::npos)
            cell_name = cell_name.substr(0, pos) + "_reg" + cell_name.substr(pos);
        else
            cell_name = cell_name + "_reg";

        if (wire->width != 1)
            cell_name += stringf("(%d)", wire->start_offset + sig[0].offset);

        if (active_module && active_module->count_id(cell_name) > 0)
            goto no_special_reg_name;

        return id(cell_name);
    }
    else {
    no_special_reg_name:
        return id(cell->name).c_str();
    }
}

void dump_cell_expr_uniop(std::ostream &f, std::string indent, RTLIL::Cell *cell, std::string op,
    bool is_arith_op = false)
{ // PORTING NEEDS TESTING
    f << indent;
    dump_sigspec(f, cell->getPort(ID::Y), true);
    f << stringf(" <= ");
    if (is_arith_op) {
        f << stringf("std_logic_vector(");
    }
    f << stringf("%s ", op.c_str());
    dump_attributes(f, "", cell->attributes, ' ');
    dump_cell_expr_port(f, cell, "A", is_arith_op, is_arith_op);
    if (is_arith_op) {
        f << stringf(")");
    }
    f << ";\n";
}

void dump_binop_expr(std::ostream &f, RTLIL::Cell *cell, std::string op, bool is_arith_op)
{
    auto dest = cell->getPort(ID::Y);
    bool boolean_to_stdlogic = false;
    if ((cell->type == ID($eq)) || (cell->type == ID($neq))) {
        if (dest.size() == 1) { // TODO ???
            boolean_to_stdlogic = true;
        }
    }

    if (is_arith_op) {
        f << stringf("std_logic_vector(");
    }
    else {
        if (boolean_to_stdlogic) {
            f << stringf("'1' when ");
        }
    }
    dump_cell_expr_port(f, cell, "A", is_arith_op, is_arith_op);
    f << stringf(" %s ", op.c_str());
    dump_attributes(f, "", cell->attributes, ' '); // FIXME!
    dump_cell_expr_port(f, cell, "B", is_arith_op, is_arith_op);
    if (is_arith_op) {
        f << stringf(")");
    }
    else {
        if (boolean_to_stdlogic) {
            f << stringf(" else '0'");
        }
    }
}

void dump_cell_expr_binop(std::ostream &f, std::string indent, RTLIL::Cell *cell, std::string op,
    bool is_arith_op = false)
{ // PORTING NEEDS TESTING

    f << indent;
    dump_sigspec(f, cell->getPort(ID::Y), true);
    f << stringf(" <= ");
    dump_binop_expr(f, cell, op, is_arith_op);
    f << ";\n";
}

bool dump_cell_expr(std::ostream &f, std::string indent, RTLIL::Cell *cell)
{ // PORTING IN PROGRESS
    f << stringf("-- Cell type is %s\n", cell->type.c_str());
    if (cell->type == ID($_NOT_)) {
        f << indent;
        dump_sigspec(f, cell->getPort(ID::Y), true);
        f << stringf(" <= ");
        f << stringf("not ");
        dump_attributes(f, "", cell->attributes, ' ');
        dump_cell_expr_port(f, cell, "A", false);
        f << ";\n";
        return true;
    }

    if (cell->type.in(ID($_AND_), ID($_NAND_), ID($_OR_), ID($_NOR_), ID($_XOR_), ID($_XNOR_),
            ID($_ANDNOT_), ID($_ORNOT_))) {
        f << indent;
        dump_sigspec(f, cell->getPort(ID::Y), true);
        f << stringf(" <= ");
        if (cell->type.in(ID($_NAND_), ID($_NOR_), ID($_XNOR_)))
            f << stringf("not (");
        dump_cell_expr_port(f, cell, "A", false);
        f << stringf(" ");
        if (cell->type.in(ID($_AND_), ID($_NAND_), ID($_ANDNOT_)))
            f << stringf("and");
        if (cell->type.in(ID($_OR_), ID($_NOR_), ID($_ORNOT_)))
            f << stringf("or");
        if (cell->type.in(ID($_XOR_), ID($_XNOR_)))
            f << stringf("xor");
        dump_attributes(f, "", cell->attributes, ' ');
        f << stringf(" ");
        if (cell->type.in(ID($_ANDNOT_), ID($_ORNOT_)))
            f << stringf("not (");
        dump_cell_expr_port(f, cell, "B", false);
        if (cell->type.in(ID($_NAND_), ID($_NOR_), ID($_XNOR_), ID($_ANDNOT_), ID($_ORNOT_)))
            f << stringf(")");
        f << ";\n";
        return true;
    }

    if (cell->type == ID($_MUX_)) {
        // TODO: attribute dumping was on B
        dump_attributes(f, "", cell->attributes, ' ');
        f << indent;
        dump_sigspec(f, cell->getPort(ID::Y), true);
        f << stringf(" <= ");
        dump_cell_expr_port(f, cell, "B", false);
        f << stringf(" when ");
        dump_cell_expr_port(f, cell, "S", false);
        f << stringf(" = '1' else ");
        dump_cell_expr_port(f, cell, "A", false);
        f << ";\n";
        return true;
    }

    if (cell->type == ID($_NMUX_)) {
        // TODO: attribute dumping was on B
        dump_attributes(f, "", cell->attributes, ' ');
        f << stringf("%s"
                     "assign ",
            indent.c_str());
        dump_sigspec(f, cell->getPort(ID::Y), true);
        f << stringf(" <= !(");
        dump_cell_expr_port(f, cell, "B", false);
        f << stringf(" when ");
        dump_cell_expr_port(f, cell, "S", false);
        f << stringf(" = '1' else ");
        dump_cell_expr_port(f, cell, "A", false);
        f << stringf(");\n");
        return true;
    }

    if (cell->type.in(ID($_AOI3_), ID($_OAI3_))) {
        f << indent;
        dump_sigspec(f, cell->getPort(ID::Y), true);
        f << stringf(" <= not ((");
        dump_cell_expr_port(f, cell, "A", false);
        f << stringf(cell->type == ID($_AOI3_) ? " and " : " or ");
        dump_cell_expr_port(f, cell, "B", false);
        f << stringf(cell->type == ID($_AOI3_) ? ") or" : ") and");
        dump_attributes(f, "", cell->attributes, ' ');
        f << stringf(" ");
        dump_cell_expr_port(f, cell, "C", false);
        f << stringf(");\n");
        return true;
    }

    if (cell->type.in(ID($_AOI4_), ID($_OAI4_))) {
        f << indent;
        dump_sigspec(f, cell->getPort(ID::Y), true);
        f << stringf(" <= not ((");
        dump_cell_expr_port(f, cell, "A", false);
        f << stringf(cell->type == ID($_AOI4_) ? " and " : " or ");
        dump_cell_expr_port(f, cell, "B", false);
        f << stringf(cell->type == ID($_AOI4_) ? ") or" : ") and");
        dump_attributes(f, "", cell->attributes, ' ');
        f << stringf(" (");
        dump_cell_expr_port(f, cell, "C", false);
        f << stringf(cell->type == ID($_AOI4_) ? " and " : " or ");
        dump_cell_expr_port(f, cell, "D", false);
        f << stringf("));\n");
        return true;
    }

#define HANDLE_UNIOP(_type, _operator, _is_arith)                                                  \
    if (cell->type == _type) {                                                                     \
        dump_cell_expr_uniop(f, indent, cell, _operator, _is_arith);                               \
        return true;                                                                               \
    }
#define HANDLE_BINOP(_type, _operator, _is_arith)                                                  \
    if (cell->type == _type) {                                                                     \
        dump_cell_expr_binop(f, indent, cell, _operator, _is_arith);                               \
        return true;                                                                               \
    }

    // UNIOP/BINOP symbols partly ported
    // TODO: verify casts to unsigned/signed
    HANDLE_UNIOP(ID($not), "not", false)
    HANDLE_UNIOP(ID($pos), "+", true)
    HANDLE_UNIOP(ID($neg), "-", true)

    HANDLE_BINOP(ID($and), "and", false)
    HANDLE_BINOP(ID($or), "or", false)
    HANDLE_BINOP(ID($xor), "xor", false)
    HANDLE_BINOP(ID($xnor), "xnor", false)

    if (std08) {
        HANDLE_UNIOP(ID($reduce_and), "and", false)
        HANDLE_UNIOP(ID($reduce_or), "or", false)
        HANDLE_UNIOP(ID($reduce_xor), "xor", false)
        HANDLE_UNIOP(ID($reduce_xnor), "xnor", false)
        HANDLE_UNIOP(ID($reduce_bool), "or", false)
    }
    else {
        if (cell->type == ID($reduce_and)) {
            f << indent;
            dump_sigspec(f, cell->getPort(ID::Y), true);
            f << stringf(" <= ");
            f << stringf("'1' when ");
            dump_attributes(f, "", cell->attributes, ' ');
            dump_cell_expr_port(f, cell, "A", false, false);
            // TODO: is "others" legal here?
            f << stringf(" = (others => '1') else '0';\n");
            return true;
        }
        if (cell->type.in(ID($reduce_or), ID($reduce_bool))) {
            f << indent;
            dump_sigspec(f, cell->getPort(ID::Y), true);
            f << stringf(" <= ");
            f << stringf("'0' when ");
            dump_attributes(f, "", cell->attributes, ' ');
            dump_cell_expr_port(f, cell, "A", false, false);
            // TODO: is "others" legal here?
            f << stringf(" = (others => '0') else '1';\n");
            return true;
        }
        if (cell->type.in(ID($reduce_xor), ID($reduce_xnor))) {
            f << indent;
            dump_sigspec(f, cell->getPort(ID::Y), true);
            f << stringf(" <= ");
            if (cell->type == ID($reduce_xnor)) {
                f << stringf("not (");
            }
            SigSpec port_A_sig = cell->getPort(ID::A);
            dump_sigspec(f, port_A_sig);
            for (auto it = port_A_sig.begin(); it != port_A_sig.end(); ++it) {
                if (it != port_A_sig.begin()) {
                    f << stringf(" xor ");
                }
                dump_sigspec(f, *it);
            }
            if (cell->type == ID($reduce_xnor)) {
                f << stringf(")");
            }
            f << ";\n";
            return true;
        }
    }

    // TODO: These will break for nonconstant shifts in B
    // Alternate {} aggregate: use always, or only for nonconstant B?

    // TODO: cell attributes on B(?)
    /*
     * Shift operator cells follow the Verilog behavior
     *
     * Avoid using built-in operators sll, sla, srl, sra, rol, and rar
     * See https://jdebp.eu/FGA/bit-shifts-in-vhdl.html for explanation
     * New link via Wayback Machine as webpage is now down:
     * http://web.archive.org/web/20200214191101/https://jdebp.eu/FGA/bit-shifts-in-vhdl.html
     */

    // IEEE 1364-2005: no sign extension done on either of the left shifts
    if (cell->type.in(ID($shl), ID($sshl))) {
        f << indent;
        dump_sigspec(f, cell->getPort(ID::Y), true);
        f << stringf(" <= ");
        f << stringf("std_logic_vector(");
        f << stringf("shift_left(");
        dump_cell_expr_port(f, cell, "A", true, true);
        f << stringf(", ");
        dump_cell_expr_port(f, cell, "B", true, true);
        f << stringf("));\n");
        return true;
    }
    /*
     * Verilog: sign extension determined by >> vs >>>
     * VHDL: sign extension determined by type of input
     */
    if (cell->type.in(ID($shr), ID($sshr))) {
        // Force cast to unsigned when not sign extending
        bool sign_extend = (cell->type == ID($sshr));
        f << indent;
        dump_sigspec(f, cell->getPort(ID::Y), true);
        f << stringf(" <= ");
        f << stringf("std_logic_vector(");
        f << stringf("shift_right(");
        dump_cell_expr_port(f, cell, "A", sign_extend, true);
        f << stringf(", ");
        dump_cell_expr_port(f, cell, "B", sign_extend, true);
        f << stringf("));\n");
        return true;
    }

    /*
     * TODO: port $eqx and $nex
     * "=" and "/=" return BIT, not std_logic, so check what type conversions
     * are needed
     * ?= and friends are a VHDL-2008 addition
     * TODO: use "?<" instead of "<" (and analogous) for others in 2008 mode?
     * TODO: Find a way to create ?= behavior in VHDL-1993
     * = and /= for $eq and $ne are wrong (though hitting the cases where the
     * differ in real code is unlikely)
     *
     * TODO: misc unported elements
     */
    HANDLE_BINOP(ID($lt), "<", true)
    HANDLE_BINOP(ID($le), "<=", true)
    if (std08) {
        HANDLE_BINOP(ID($eq), "?=", false)
        HANDLE_BINOP(ID($ne), "?/=", false)
    }
    else {
        HANDLE_BINOP(ID($eq), "=", false)
        HANDLE_BINOP(ID($ne), "/=", false)
    }
    HANDLE_BINOP(ID($eqx), "=", false)
    HANDLE_BINOP(ID($nex), "/=", false)
    HANDLE_BINOP(ID($ge), ">=", true)
    HANDLE_BINOP(ID($gt), ">", true)

    HANDLE_BINOP(ID($add), "+", true)
    HANDLE_BINOP(ID($sub), "-", true)
    HANDLE_BINOP(ID($mul), "*", true)
    HANDLE_BINOP(ID($div), "/", true)
    HANDLE_BINOP(ID($mod), "mod", true)
    HANDLE_BINOP(ID($pow), "**", true)

    if (cell->type == ID($logic_not)) {
        // TODO: use VHDL-93 compliant syntax
        // TODO: attributes were on port "A"
        f << indent;
        dump_sigspec(f, cell->getPort(ID::Y), true);
        f << stringf(" <= ");
        // Unary or only if signal is a vector
        bool need_unary_or = cell->getPort(ID::A).as_wire()->width > 1;
        if (need_unary_or) {
            f << stringf("not (or ");
        }
        else {
            f << stringf("not ");
        }
        // dump_attributes(f, "", cell->attributes, ' ');
        dump_cell_expr_port(f, cell, "A", false, false);
        f << stringf("%s;\n", need_unary_or ? ")" : "");
        return true;
    }
    HANDLE_BINOP(ID($logic_and), "and", false)
    HANDLE_BINOP(ID($logic_or), "or", false)

#undef HANDLE_UNIOP
#undef HANDLE_BINOP

    if (cell->type == ID($divfloor)) { // unported for now
        // wire [MAXLEN+1:0] _0_, _1_, _2_;
        // assign _0_ = $signed(A);
        // assign _1_ = $signed(B);
        // assign _2_ = (A[-1] == B[-1]) || A == 0 ? _0_ : $signed(_0_ - (B[-1]
        // ? _1_ + 1 : _1_ - 1)); assign Y = $signed(_2_) / $signed(_1_);

        if (cell->getParam(ID::A_SIGNED).as_bool() && cell->getParam(ID::B_SIGNED).as_bool()) {
            SigSpec sig_a = cell->getPort(ID::A);
            SigSpec sig_b = cell->getPort(ID::B);

            std::string buf_a = next_auto_id();
            std::string buf_b = next_auto_id();
            std::string buf_num = next_auto_id();
            int size_a = GetSize(sig_a);
            int size_b = GetSize(sig_b);
            int size_y = GetSize(cell->getPort(ID::Y));
            int size_max = std::max(size_a, std::max(size_b, size_y));

            // intentionally one wider than maximum width
            f << stringf("%s"
                         "wire [%d:0] %s, %s, %s;\n",
                indent.c_str(), size_max, buf_a.c_str(), buf_b.c_str(), buf_num.c_str());
            f << stringf("%s"
                         "assign %s = ",
                indent.c_str(), buf_a.c_str());
            dump_cell_expr_port(f, cell, "A", true);
            f << ";\n";
            f << stringf("%s"
                         "assign %s = ",
                indent.c_str(), buf_b.c_str());
            dump_cell_expr_port(f, cell, "B", true);
            f << ";\n";

            f << stringf("%s"
                         "assign %s = ",
                indent.c_str(), buf_num.c_str());
            f << stringf("(");
            dump_sigspec(f, sig_a.extract(sig_a.size() - 1));
            f << stringf(" == ");
            dump_sigspec(f, sig_b.extract(sig_b.size() - 1));
            f << stringf(") || ");
            dump_sigspec(f, sig_a);
            f << stringf(" == 0 ? %s : ", buf_a.c_str());
            f << stringf("$signed(%s - (", buf_a.c_str());
            dump_sigspec(f, sig_b.extract(sig_b.size() - 1));
            f << stringf(" ? %s + 1 : %s - 1));\n", buf_b.c_str(), buf_b.c_str());

            f << stringf("%s"
                         "assign ",
                indent.c_str());
            dump_sigspec(f, cell->getPort(ID::Y));
            f << stringf(" = $signed(%s) / ", buf_num.c_str());
            dump_attributes(f, "", cell->attributes, ' ');
            f << stringf("$signed(%s);\n", buf_b.c_str());
            return true;
        }
        else {
            // same as truncating division
            dump_cell_expr_binop(f, indent, cell, "/");
            return true;
        }
    }

    if (cell->type == ID($modfloor)) { // unported for now (rem?)
        // wire truncated = $signed(A) % $signed(B);
        // assign Y = (A[-1] == B[-1]) || truncated == 0 ? truncated :
        // $signed(B) + $signed(truncated);

        if (cell->getParam(ID::A_SIGNED).as_bool() && cell->getParam(ID::B_SIGNED).as_bool()) {
            SigSpec sig_a = cell->getPort(ID::A);
            SigSpec sig_b = cell->getPort(ID::B);

            std::string temp_id = next_auto_id();
            f << stringf("%s"
                         "wire [%d:0] %s = ",
                indent.c_str(), GetSize(cell->getPort(ID::A)) - 1, temp_id.c_str());
            dump_cell_expr_port(f, cell, "A", true);
            f << stringf(" %% ");
            dump_attributes(f, "", cell->attributes, ' ');
            dump_cell_expr_port(f, cell, "B", true);
            f << ";\n";

            f << stringf("%s"
                         "assign ",
                indent.c_str());
            dump_sigspec(f, cell->getPort(ID::Y));
            f << stringf(" = (");
            dump_sigspec(f, sig_a.extract(sig_a.size() - 1));
            f << stringf(" == ");
            dump_sigspec(f, sig_b.extract(sig_b.size() - 1));
            f << stringf(") || %s == 0 ? %s : ", temp_id.c_str(), temp_id.c_str());
            dump_cell_expr_port(f, cell, "B", true);
            f << stringf(" + $signed(%s);\n", temp_id.c_str());
            return true;
        }
        else {
            // same as truncating modulo
            dump_cell_expr_binop(f, indent, cell, "%");
            return true;
        }
    }

    if (cell->type == ID($shift)) { // unported for now
        f << stringf("%s"
                     "assign ",
            indent.c_str());
        dump_sigspec(f, cell->getPort(ID::Y));
        f << stringf(" = ");
        if (cell->getParam(ID::B_SIGNED).as_bool()) {
            dump_cell_expr_port(f, cell, "B", true);
            f << stringf(" < 0 ? ");
            dump_cell_expr_port(f, cell, "A", true);
            f << stringf(" << - ");
            dump_sigspec(f, cell->getPort(ID::B));
            f << stringf(" : ");
            dump_cell_expr_port(f, cell, "A", true);
            f << stringf(" >> ");
            dump_sigspec(f, cell->getPort(ID::B));
        }
        else {
            dump_cell_expr_port(f, cell, "A", true);
            f << stringf(" >> ");
            dump_sigspec(f, cell->getPort(ID::B));
        }
        f << ";\n";
        return true;
    }

    if (cell->type == ID($shiftx)) { // unported for now
        std::string temp_id = next_auto_id();
        f << stringf("%s"
                     "wire [%d:0] %s = ",
            indent.c_str(), GetSize(cell->getPort(ID::A)) - 1, temp_id.c_str());
        dump_sigspec(f, cell->getPort(ID::A));
        f << ";\n";

        f << stringf("%s"
                     "assign ",
            indent.c_str());
        dump_sigspec(f, cell->getPort(ID::Y));
        f << stringf(" = %s[", temp_id.c_str());
        if (cell->getParam(ID::B_SIGNED).as_bool())
            f << stringf("$signed(");
        dump_sigspec(f, cell->getPort(ID::B));
        if (cell->getParam(ID::B_SIGNED).as_bool())
            f << stringf(")");
        f << stringf(" +: %d", cell->getParam(ID::Y_WIDTH).as_int());
        f << stringf("];\n");
        return true;
    }

    if (cell->type == ID($mux)) {
        // TODO: attribute dumping was on B
        dump_attributes(f, "", cell->attributes, ' ');
        f << indent;
        dump_sigspec(f, cell->getPort(ID::Y), true);
        f << stringf(" <= ");
        dump_sigspec(f, cell->getPort(ID::B));
        f << stringf(" when ");
        dump_sigspec(f, cell->getPort(ID::S));
        f << stringf(" = '1' else ");
        dump_sigspec(f, cell->getPort(ID::A));
        f << ";\n";
        return true;
    }

    if (cell->type == ID($pmux)) {
        /*
         * Use a case statement in a process instead of with..select
         * This makes it easier to handle SigSpecs with multiple chunks
         * This is a deliberate break from the output of ghdl --synth
         *
         * Could use (a, b) := c & d; instead in VHDL-2008 mode?
         * This would require informing the concatenation generators
         * about whether the expression is an LHS or RHS expression
         * (Should be implemented already but check again before changing this)
         */
        /*
         * TODO: remove assumption of downto
         * (This assumption is also present in Verilog backend)?
         */
        int width = cell->parameters[ID::WIDTH].as_int();
        int s_width = cell->getPort(ID::S).size();

        auto dst_port = cell->getPort(ID::Y);
        auto a_port = cell->getPort(ID::A);
        auto b_port = cell->getPort(ID::B);
        auto s_port = cell->getPort(ID::S);
        std::ostringstream a_str_stream;
        std::ostringstream b_str_stream;
        std::ostringstream s_str_stream;
        std::ostringstream y_str_stream;
        dump_sigspec(a_str_stream, a_port);
        dump_sigspec(b_str_stream, b_port);
        dump_sigspec(s_str_stream, s_port);
        dump_sigspec(y_str_stream, dst_port, true);
        std::string a_str, b_str, s_str, y_str;
        a_str = a_str_stream.str();
        b_str = b_str_stream.str();
        s_str = s_str_stream.str();
        y_str = y_str_stream.str();

        // ivar_ names are escaped above, so there shouldn't be collisions
        std::string a_var_str, b_var_str, s_var_str;
        std::string cellname_prefix = cellname(cell);
        cellname_prefix = cellname_prefix.substr(1, cellname_prefix.length() - 2);
        a_var_str = "ivar_" + cellname_prefix + "_a";
        b_var_str = "ivar_" + cellname_prefix + "_b";
        s_var_str = "ivar_" + cellname_prefix + "_s";

        std::set<RTLIL::SigChunk> sensitivities = get_sensitivity_set(
            { cell->getPort(ID::A), cell->getPort(ID::B), cell->getPort(ID::S) });
        f << stringf("%s"
                     "process(%s) is\n",
            indent.c_str(), process_sensitivity_str(sensitivities).c_str());
        f << indent << sig_decl_type(a_var_str, width, true) << ";\n";
        f << indent << sig_decl_type(b_var_str, s_width * width, true) << ";\n";
        f << indent << sig_decl_type(s_var_str, s_width, true) << ";\n";
        f << indent << "begin\n";

        {
            INDENT
            // TODO: see if any of the case functions can do this
            // Use intermediate variables to handle multichunk SigSpecs
            f << indent << a_var_str << " := " << a_str << ";\n";
            f << indent << b_var_str << " := " << b_str << ";\n";
            f << indent << s_var_str << " := " << s_str << ";\n";

            f << indent << "case " << s_var_str << " is\n";
            char case_comparisons[s_width + 1];
            case_comparisons[s_width] = '\0';
            // onehot selection cases...
            for (int j = 0; j < s_width; j++) {
                case_comparisons[j] = '0';
            }

            auto assign_str = " <= ";
            {
                INDENT
                for (int i = 0; i < s_width; i++) {
                    int hot_bit = s_width - 1 - i;
                    case_comparisons[hot_bit] = '1';
                    f << indent << "when \"" << case_comparisons << "\" =>\n";
                    f << NEXT_INDENT(indent) << y_str << assign_str << b_var_str << "(";
                    if (width == 1) {
                        f << i;
                    }
                    else {
                        f << stringf("%d downto %d", (i + 1) * width - 1, i * width);
                    }
                    f << ");\n";
                    case_comparisons[hot_bit] = '0';
                }
                f << indent << "when others =>\n";
                f << NEXT_INDENT(indent) << y_str << assign_str << a_var_str << ";\n";
            }
            f << indent << "end case;\n";
        }
        f << indent << "end process;\n";

        return true;
    }

    if (cell->type == ID($tribuf)) {
        f << indent;
        dump_sigspec(f, cell->getPort(ID::Y), true);
        f << " <= ";
        dump_sigspec(f, cell->getPort(ID::A));
        f << " when ";
        dump_sigspec(f, cell->getPort(ID::EN));
        f << " = '1' else";
        if (cell->parameters.at(ID::WIDTH).as_int() == 1) {
            f << "'z'";
        }
        else {
            f << "(others => 'z')";
        }
        f << ";\n";
        return true;
    }

    if (cell->type == ID($slice)) { // unported for now // FIXME
        f << indent << "assign ";
        dump_sigspec(f, cell->getPort(ID::Y));
        f << stringf(" = ");
        dump_sigspec(f, cell->getPort(ID::A));
        f << stringf(" >> %d;\n", cell->parameters.at(ID::OFFSET).as_int());
        return true;
    }

    if (cell->type == ID($concat)) {
        f << indent;
        dump_sigspec(f, cell->getPort(ID::Y), true);
        f << stringf(" <= ");
        dump_sigspec(f, cell->getPort(ID::B));
        f << stringf(" & ");
        dump_sigspec(f, cell->getPort(ID::A));
        f << ";\n";
        return true;
    }

    // TODO: handle LUT1's
    if (cell->type == ID($lut)) {
        // Assumes that ID::LUT param is downto (but matches techlib model)
        // ghdl --synth for a LUT is unknown as it gets expanded into $mux es

        std::string lut_const_name = stringf("LUTstr_%s", id(cell->name).c_str());
        // Encapsulate LUT constant with process, which is otherwise unnecessary
        SigSpec a_port = cell->getPort(ID::A);
        Const lut_const = cell->parameters.at(ID::LUT);
        // TODO: fix handling of width 1 LUT input
        int lut_width = lut_const.size();
        f << stringf("%s"
                     "process (%s) is\n",
            indent.c_str(), process_sensitivity_str(get_sensitivity_set(a_port)).c_str());
        f << stringf("%s"
                     "  constant %s: std_logic_vector(%d downto 0) := ",
            indent.c_str(), lut_const_name.c_str(), lut_width - 1);
        // offset=default, no_decimal=true
        dump_const(f, lut_const, lut_width, 0, true);
        f << ";\n";

        f << stringf("%s"
                     "begin\n",
            indent.c_str());
        f << stringf("%s  ", indent.c_str());
        dump_sigspec(f, cell->getPort(ID::Y), true);
        f << stringf(" <= ");
        dump_attributes(f, "", cell->attributes, ' ');
        f << lut_const_name;
        // Outermost parentheses are indexing wrapper
        f << stringf("(to_integer(");

        /*
         * Use a qualified expression for std_logic concats
         * If all elements are non-array type, the aggregate has ambiguous type
         * Qualified expressions are defined in IEEE 1076-2008 5.2.1
         * Concatenation return types are defined in IEEE 1076-2008 9.2.5
         * TODO: concatenation qualified expr may need to be used elsewhere
         */
        bool use_qualified_expr = true;
        for (auto it = a_port.chunks().rbegin(); it != a_port.chunks().rend(); it++) {
            if (it->width > 1) {
                use_qualified_expr = false;
            }
        }
        if (use_qualified_expr) {
            f << stringf("unsigned'(");
        }
        else {
            f << stringf("unsigned(");
        }
        dump_sigspec(f, a_port);
        f << stringf(")));\n");
        f << stringf("%s"
                     "end process;\n",
            indent.c_str());
        return true;
    }

    /*
     * Use a single process to wrap the entire thing
     * Each bit is programatically unrolled (like a for..generate statement)
     * Grouping will be more obvious this way
     * Entire FF group shares a cell type so a single sensitivity list suffices
     */
    if (RTLIL::builtin_ff_cell_types().count(cell->type)) { // porting needs testing
        FfData ff(nullptr, cell);
        bool has_d = cell->hasPort(ID::D);

        // $ff / $_FF_ cell: not supported.
        if (has_d && !ff.has_clk && !ff.has_ce)
            return false;

        std::string reg_name = cellname(cell);
        bool out_is_reg_wire = is_reg_wire(ff.sig_q, reg_name);
        std::string assignment_operator = out_is_reg_wire ? "<=" : ":="; // FIXME?

        std::string assign = " " + assignment_operator + " ";

        // Sensitivity list
        std::set<RTLIL::SigSpec> sensitivity_set;
        if (ff.has_clk) {
            sensitivity_set.insert(ff.sig_clk);
        }
        else {
            sensitivity_set.insert(ff.sig_d);
            sensitivity_set.insert(ff.sig_ce);
        }
        if (ff.has_sr) {
            sensitivity_set.insert(ff.sig_clr);
            sensitivity_set.insert(ff.sig_set);
        }
        else if (ff.has_arst) {
            sensitivity_set.insert(ff.sig_arst);
        }
        f << indent
          << stringf("process(%s) is\n",
                 process_sensitivity_str(get_sensitivity_set(sensitivity_set)).c_str());
        {
            INDENT
            if (!out_is_reg_wire) {
                f << indent << "variable " << reg_name << ": ";
                if (ff.width == 1)
                    f << "std_logic";
                else
                    f << stringf("std_logic_vector(%d downto 0)", ff.width - 1);
                dump_reg_init(f, ff.sig_q);
                f << ";\n";
            }
        }

        f << indent << "begin\n";

        {
            INDENT

            // If the FF has CLR/SET inputs, emit every bit slice separately.
            int chunks = ff.has_sr ? ff.width : 1;
            bool chunky = ff.has_sr && ff.width != 1;

            /*
             * Changes from Yosys 8f1d53e6 were not copied over
             * Their rationale doesn't seem to apply here?
             * If there is a bug in dumping FFs here but not in Verilog,
             * re-examine the above commit as a first troubleshooting step
             */
            for (int i = 0; i < chunks; i++) {
                SigSpec sig_d;
                Const val_arst, val_srst;
                std::string reg_bit_name;
                if (chunky) {
                    reg_bit_name = stringf("%s(%d)", reg_name.c_str(), i);
                    if (has_d)
                        sig_d = ff.sig_d[i];
                }
                else {
                    reg_bit_name = reg_name;
                    if (has_d)
                        sig_d = ff.sig_d;
                }
                if (ff.has_arst)
                    val_arst = chunky ? ff.val_arst[i] : ff.val_arst;
                if (ff.has_srst)
                    val_srst = chunky ? ff.val_srst[i] : ff.val_srst;

                dump_attributes(f, indent, cell->attributes);
                // TODO: replace dump_sigspec with dump_const when appropriate
                // Cannot combine as much string gen because VHDL is stricter
                // TODO: avoid code sharing when it decreases legibility
                if (ff.has_clk) {
                    INDENT
                    f << indent << "-- FFs\n";
                    // FFs.
                    f << indent << "if ";
                    // Generate asynchronous behavior syntax
                    if (ff.has_sr) {
                        // Async reset in SR pair
                        dump_sig_equal_bool(f, ff.sig_clr[i], ff.pol_clr);
                        f << " then\n";
                        f << NEXT_INDENT(indent) << reg_bit_name << assign << "'0';\n";
                        // Async set in SR pair
                        f << indent << "elsif ";
                        dump_sig_equal_bool(f, ff.sig_set[i], ff.pol_set);
                        f << " then\n";
                        f << NEXT_INDENT(indent) << reg_bit_name << assign << "'1';\n";
                        f << indent << "elsif ";
                    }
                    else if (ff.has_arst) {
                        dump_sig_equal_bool(f, ff.sig_arst, ff.pol_arst);
                        f << " then\n";
                        f << NEXT_INDENT(indent) << reg_bit_name << assign << "'0';\n";
                        f << indent << "elsif ";
                    }
                    f << stringf("%s_edge(", ff.pol_clk ? "rising" : "falling");
                    dump_sigspec(f, ff.sig_clk);
                    f << stringf(") then\n");
                    // ff.ce_over_srst means sync-reset is also gated by enable
                    if (ff.has_srst && ff.has_ce && ff.ce_over_srst) {
                        INDENT
                        f << indent << "if ";
                        dump_sig_equal_bool(f, ff.sig_ce[i], ff.pol_ce);
                        f << " then\n";
                        {
                            INDENT
                            f << indent << "if ";
                            dump_sig_equal_bool(f, ff.sig_srst, ff.pol_srst);
                            f << " then\n";
                            f << NEXT_INDENT(indent) << reg_bit_name << assign;
                            dump_sigspec(f, val_srst);
                            f << ";\n";
                            f << indent << "else\n";
                            f << NEXT_INDENT(indent)
                              << stringf(
                                     "%s %s ", reg_bit_name.c_str(), assignment_operator.c_str());
                            dump_sigspec(f, sig_d);
                            f << ";\n";
                            f << indent << "end if;\n";
                        }
                        f << indent << "end if;\n";
                    }
                    else {
                        if (!ff.has_srst && !ff.has_ce) {
                            f << stringf("%s"
                                         "    %s %s ",
                                indent.c_str(), reg_bit_name.c_str(), assignment_operator.c_str());
                            dump_sigspec(f, sig_d);
                            f << ";\n";
                        }
                        else {
                            INDENT
                            if (ff.has_srst) {
                                f << indent << "if ";
                                dump_sig_equal_bool(f, ff.sig_srst, ff.pol_srst);
                                f << " then\n";
                                f << NEXT_INDENT(indent) << reg_bit_name << assign;
                                dump_sigspec(f, val_srst);
                                f << ";\n";
                            }
                            if (ff.has_ce) {
                                f << indent << (ff.has_srst ? "elsif " : "if ");
                                dump_sig_equal_bool(f, ff.sig_ce, ff.pol_ce);
                                f << " then\n";
                            }
                            else {
                                f << stringf("%s"
                                             "    else\n",
                                    indent.c_str());
                            }
                            f << NEXT_INDENT(indent) << reg_bit_name << assign;
                            dump_sigspec(f, sig_d);
                            f << ";\n";
                            f << indent << "end if;\n";
                        }
                    }
                    f << indent << "end if;\n";
                }
                else {
                    INDENT
                    // Latches.
                    f << indent;
                    // Assumption that at least one of these ifs will be hit
                    // Awkward "els" is first half of "elsif"
                    if (ff.has_sr) {
                        f << "if ";
                        dump_sig_equal_bool(f, ff.sig_clr[i], ff.pol_clr);
                        f << " then \n";
                        f << NEXT_INDENT(indent) << reg_bit_name << assign << "'0';\n";
                        f << indent << "elsif ";
                        dump_sig_equal_bool(f, ff.sig_set[i], ff.pol_set);
                        f << " then \n";
                        f << NEXT_INDENT(indent) << reg_bit_name << assign << "'1';\n";
                        if (has_d) {
                            f << indent << "els";
                        }
                    }
                    else if (ff.has_arst) {
                        f << "if ";
                        dump_sig_equal_bool(f, ff.sig_arst, ff.pol_arst);
                        f << " then\n";
                        f << NEXT_INDENT(indent) << reg_bit_name << assign;
                        dump_sigspec(f, val_arst);
                        f << ";\n";
                        if (has_d) {
                            f << indent << "els";
                        }
                    }
                    if (has_d) {
                        f << "if ";
                        dump_sig_equal_bool(f, ff.sig_ce, ff.pol_ce);
                        f << " then\n";
                        f << NEXT_INDENT(indent) << reg_bit_name << assign;
                        dump_sigspec(f, sig_d);
                        f << ";\n";
                    }
                    f << indent << "end if;\n";
                }
            }

            // Group inside process for readability
            if (!out_is_reg_wire) {
                f << indent;
                dump_sigspec(f, ff.sig_q, true);
                f << stringf(" <= %s;\n", reg_name.c_str());
            }
        }

        f << indent << "end process;\n";

        return true;
    }

    if (cell->type.in(ID($assert), ID($assume), ID($cover))) {
        if (cell->type != ID($assert)) {
            log_warning(
                "Cell of type %s will be dumped as a PSL comment\n", cell->type.c_str() + 1);
            log("PSL unclocked directives do not work (yet) with GHDL\n");
        }
        log_experimental("Formal cells as PSL comments");
        std::stringstream en_sstream;
        std::stringstream a_sstream; // Not actually arbitrary haha
        string en_str;
        string a_str; // [A]rticle of interest
        SigSpec en_sigspec = cell->getPort(ID::EN);
        dump_sigspec(en_sstream, en_sigspec);
        /*
         * en_sigspec should be exactly one bit wide
         * Use this to skip the hypothesis portion of the implication
         * (A false hypothesis causes the property to be a tautology)
         */
        bool en_const_on = en_sigspec.is_fully_ones();
        en_str = en_sstream.str();

        dump_sigspec(a_sstream, cell->getPort(ID::A));
        a_str = a_sstream.str();
        // TODO: special handling for asserts of x->'1'?
        if (cell->type == ID($assert)) {
            if (en_const_on) {
                if (std08) {
                    f << stringf("%s"
                                 "assert %s;\n",
                        indent.c_str(), a_str.c_str());
                }
                else {
                    f << stringf("%s"
                                 "assert %s = '1';\n",
                        indent.c_str(), a_str.c_str());
                }
            }
            else {
                if (std08) {
                    f << stringf("%s"
                                 "assert ((not %s) or %s) = '1';",
                        indent.c_str(), en_str.c_str(), a_str.c_str());
                }
                else {
                    f << stringf("%s"
                                 "assert (not %s) or %s;",
                        indent.c_str(), en_str.c_str(), a_str.c_str());
                }
                f << stringf(" -- %s -> %s\n", en_str.c_str(), a_str.c_str());
            }
        }
        else {
            f << indent;
            if (!std08 && cell->type != ID($assert)) {
                // PSL comment that GHDL interprets with -fpsl
                f << stringf("-- psl ");
            }
            f << stringf("%s ", cell->type.c_str() + 1);
            const char *property_impl_str;
            if (en_const_on) {
                property_impl_str = a_str.c_str();
            }
            else {
                property_impl_str = stringf("%s -> %s", en_str.c_str(), a_str.c_str()).c_str();
            }
            if (cell->type != ID($cover)) {
                f << stringf("always (%s);\n", property_impl_str);
            }
            else {
                /*
                 * PSL cover statements require a Sequence (PSL 2005 7.1.6)
                 * Construct a one-long sequence as a Braced SERE
                 */
                f << stringf("{%s};\n", property_impl_str);
            }
        }
        return true;
    }

    if (cell->type.in(ID($specify2), ID($specify3), ID($specrule))) {
        /*
         * There are a number of more graceful ways to handle this:
         * - Dump this as a subcomponent
         * - Leave a more informative comment behind in the generated VHDL
         * - Use the information from the src attribute to augment the above
         * Suggestions are welcome if you actually need $specify* cells dumped
         * (Yosys has limited support for these anyway so this should be fine)
         */
        log_warning("%s cell %s detected\n", cell->type.c_str(), cell->name.c_str());
        log_warning("$specify* cells are not supported by the VHDL backend and "
                    "will be ignored\n");
        f << stringf("-- Cell of type %s was not dumped\n", cell->type.c_str());
        // Return true regardless to avoid a subcomponent instantiation
        return true;
    }

    // FIXME: $fsm

    return false;
}

bool is_internal_cell(RTLIL::IdString type)
{
    return !type.isPublic() && !type.begins_with("$paramod");
}

void dump_cell(std::ostream &f, std::string indent, RTLIL::Cell *cell)
{ // PORTING REQUIRED
    // Handled by dump_memory
    if (cell->type.in(ID($mem), ID($memwr), ID($memrd), ID($meminit)))
        return;

    if (is_internal_cell(cell->type) && !noexpr) {
        if (dump_cell_expr(f, indent, cell))
            return;
    }

    std::string cell_name = cellname(cell);
    dump_attributes(f, indent, cell->attributes);
    f << indent << cell_name << ": " << id(cell->type, false);
    if (cell_name != id(cell->name)) {
        f << " -- " << id(cell->name) << "\n";
    }
    f << "\n";

    if (unisim) { // TODO ???
        inst_generic_types[std::make_pair("FDSE", "INIT")] = VhdlType::VHDL_BIT;
        inst_generic_types[std::make_pair("FDRE", "INIT")] = VhdlType::VHDL_BIT;
    }

    if (cell->parameters.size() > 0) {
        f << indent << "generic map(\n";
        for (auto it = cell->parameters.begin(); it != cell->parameters.end(); ++it) {
            if (it != cell->parameters.begin()) {
                f << ",\n";
            }
            auto param_name = id(it->first);
            f << NEXT_INDENT(indent) << param_name << " => ";
            // FIXME how could we possibily know the type? std_logic? bit_vector? int? boolean? Is
            // this an unfixable YOSYS limitation?
            // workaround: user provided mapping file
            // for now, let's assume everything is a string or bit_vector
            auto vhdl_type = VhdlType::VHDL_UNKNOWN;
            auto entity = id(cell->type, false);
            auto search = inst_generic_types.find(make_pair(entity, param_name));
            if (search != inst_generic_types.end()) {
                vhdl_type = search->second;
                log_warning("using type %d for %s generic %s\n", vhdl_type, entity.c_str(),
                    param_name.c_str());
            }
            dump_const(f, it->second, -1, 0, vhdl_type != VhdlType::VHDL_NUMERIC, vhdl_type);
        }
        f << "\n" << indent << ")\n";
    }

    bool first_arg = true;
    std::set<RTLIL::IdString> numbered_ports; // TODO?
    // for (int i = 1; true; i++) {
    //     char str[16];
    //     snprintf(str, 16, "$%d", i);
    //     for (auto it = cell->connections().begin(); it != cell->connections().end(); ++it) {
    //         if (it->first != str)
    //             continue;
    //         if (!first_arg)
    //             f << stringf(",");
    //         first_arg = false;
    //         f << stringf("\n%s  ", indent.c_str());
    //         dump_sigspec(f, it->second);
    //         numbered_ports.insert(it->first);
    //         goto found_numbered_port;
    //     }
    //     break;
    // found_numbered_port:;
    // }

    f << indent << "port map(\n";
    for (auto it = cell->connections().begin(); it != cell->connections().end(); ++it) {
        if (numbered_ports.count(it->first))
            continue;
        if (!first_arg)
            f << stringf(",\n");
        first_arg = false;
        f << NEXT_INDENT(indent) << id(it->first) << " => ";
        dump_sigspec(f, it->second, false);
    }
    f << "\n" << indent << ");\n";

    if (siminit && RTLIL::builtin_ff_cell_types().count(cell->type) && cell->hasPort(ID::Q) &&
        !cell->type.in(ID($ff), ID($_FF_))) {
        std::stringstream ss;
        dump_reg_init(ss, cell->getPort(ID::Q));
        if (!ss.str().empty()) { // FIXME
            f << stringf("%sinitial %s.Q", indent.c_str(), cell_name.c_str());
            f << ss.str();
            f << ";\n";
        }
    }
}

void dump_conn(
    std::ostream &f, std::string indent, const RTLIL::SigSpec &left, const RTLIL::SigSpec &right)
{ // PORTING NEEDS TESTING
    /*
     * Split LHS of connection by default
     * Use VHDL-2008 style concatenation with -nosimple-lhs and -std08
     * TODO: any reason to bother with -nosimple-hls and not just split?
     */
    if (!(nosimple_lhs && std08)) {
        int offset = 0;
        for (auto &chunk : left.chunks()) {
            f << indent;
            dump_sigspec(f, chunk);
            f << stringf(" <= ");
            dump_sigspec(f, right.extract(offset, GetSize(chunk)));
            f << ";\n";
            offset += GetSize(chunk);
        }
    }
    else {
        f << indent;
        dump_sigspec(f, left, true);
        f << stringf(" <= ");
        dump_sigspec(f, right);
        f << ";\n";
    }
}

// This is a forward declaration
void dump_proc_switch(std::ostream &f, std::string indent, RTLIL::SwitchRule *sw);

void dump_case_body(
    std::ostream &f, std::string indent, RTLIL::CaseRule *cs, bool omit_trailing_begin = false)
{ // PORTING REQUIRED FIXME
    int number_of_stmts = cs->switches.size() + cs->actions.size();

    if (!omit_trailing_begin && number_of_stmts >= 2)
        f << stringf("%s"
                     "begin\n",
            indent.c_str());

    for (auto it = cs->actions.begin(); it != cs->actions.end(); ++it) {
        if (it->first.size() == 0)
            continue;
        f << stringf("%s  ", indent.c_str());
        dump_sigspec(f, it->first);
        f << stringf(" = ");
        dump_sigspec(f, it->second);
        f << ";\n";
    }

    for (auto it = cs->switches.begin(); it != cs->switches.end(); ++it)
        dump_proc_switch(f, NEXT_INDENT(indent), *it);

    if (!omit_trailing_begin && number_of_stmts == 0)
        f << stringf("%s  /* empty */;\n", indent.c_str());

    if (omit_trailing_begin || number_of_stmts >= 2)
        f <<indent << "end\n";
}

void dump_proc_switch(std::ostream &f, std::string indent, RTLIL::SwitchRule *sw)
{ // PORTING REQUIRED
    if (sw->signal.size() == 0) {
        f << indent << "begin\n";
        for (auto it = sw->cases.begin(); it != sw->cases.end(); ++it) {
            if ((*it)->compare.size() == 0)
                dump_case_body(f, NEXT_INDENT(indent), *it);
        }
        f << indent << "end\n";
        return;
    }

    dump_attributes(f, indent, sw->attributes);
    f << indent << "casez (";
    dump_sigspec(f, sw->signal);
    f << stringf(")\n");
    {
        INDENT
        bool got_default = false;
        for (auto it = sw->cases.begin(); it != sw->cases.end(); ++it) {
            dump_attributes(f, NEXT_INDENT(indent), (*it)->attributes, /*modattr=*/false,
                /*regattr=*/false, /*as_comment=*/true);
            if ((*it)->compare.size() == 0) {
                if (got_default)
                    continue;
                f << indent << "default";
                got_default = true;
            }
            else {
                f << indent;
                for (size_t i = 0; i < (*it)->compare.size(); i++) {
                    if (i > 0)
                        f << stringf(", ");
                    dump_sigspec(f, (*it)->compare[i]);
                }
            }
            f << ":\n";
            dump_case_body(f, NEXT_INDENT(indent), *it);
        }
    }
    f << indent << "endcase\n";
}

void case_body_find_regs(RTLIL::CaseRule *cs)
{ // NO PORTING REQUIRED
    for (auto it = cs->switches.begin(); it != cs->switches.end(); ++it)
        for (auto it2 = (*it)->cases.begin(); it2 != (*it)->cases.end(); it2++)
            case_body_find_regs(*it2);

    for (auto it = cs->actions.begin(); it != cs->actions.end(); ++it) {
        for (auto &c : it->first.chunks())
            if (c.wire != NULL)
                reg_wires.insert(c.wire->name);
    }
}

void find_process_regs(RTLIL::Process *proc)
{
    case_body_find_regs(&proc->root_case);
    for (auto it = proc->syncs.begin(); it != proc->syncs.end(); ++it) {
        for (auto it2 = (*it)->actions.begin(); it2 != (*it)->actions.end(); it2++) {
            for (auto &c : it2->first.chunks())
                if (c.wire != NULL)
                    reg_wires.insert(c.wire->name);
        }
    }
    return;
}
void dump_process(std::ostream &f, std::string indent, RTLIL::Process *proc)
{ // PORTING REQUIRED
    f << stringf("%s"
                 "always @* begin\n",
        indent.c_str());
    dump_case_body(f, indent, &proc->root_case, true);

    std::string backup_indent = indent;

    for (size_t i = 0; i < proc->syncs.size(); i++) {
        RTLIL::SyncRule *sync = proc->syncs[i];
        indent = backup_indent;
        if (sync->type == RTLIL::STa) {
            f << stringf("%s"
                         "always @* begin\n",
                indent.c_str());
        }
        else if (sync->type == RTLIL::STi) {
            f << stringf("%s"
                         "initial begin\n",
                indent.c_str());
        }
        else {
            f << indent << "always @(";
            if (sync->type == RTLIL::STp || sync->type == RTLIL::ST1)
                f << stringf("posedge ");
            if (sync->type == RTLIL::STn || sync->type == RTLIL::ST0)
                f << stringf("negedge ");
            dump_sigspec(f, sync->signal);
            f << stringf(") begin\n");
        }
        std::string ends = indent + "end\n";
        indent += "  ";

        if (sync->type == RTLIL::ST0 || sync->type == RTLIL::ST1) {
            f << indent << stringf("if (%s", sync->type == RTLIL::ST0 ? "!" : "");
            dump_sigspec(f, sync->signal);
            f << stringf(") begin\n");
            ends = indent + "end\n" + ends;
            indent += "  ";
        }

        if (sync->type == RTLIL::STp || sync->type == RTLIL::STn) {
            for (size_t j = 0; j < proc->syncs.size(); j++) {
                RTLIL::SyncRule *sync2 = proc->syncs[j];
                if (sync2->type == RTLIL::ST0 || sync2->type == RTLIL::ST1) {
                    f << indent << stringf("if (%s", sync2->type == RTLIL::ST1 ? "!" : "");
                    dump_sigspec(f, sync2->signal);
                    f << stringf(") begin\n");
                    ends = indent + "end\n" + ends;
                    indent += "  ";
                }
            }
        }

        for (auto it = sync->actions.begin(); it != sync->actions.end(); ++it) {
            if (it->first.size() == 0)
                continue;
            f << stringf("%s  ", indent.c_str());
            dump_sigspec(f, it->first);
            f << stringf(" <= ");
            dump_sigspec(f, it->second);
            f << ";\n";
        }

        f << ends;
    }
}

void dump_module(std::ostream &f, std::string indent, RTLIL::Module *module)
{ // PORTING REQUIRED
    reg_wires.clear();
    reset_auto_counter(module);
    active_module = module;
    active_sigmap.set(module);
    active_initdata.clear();
    memory_array_types.clear();

    for (auto wire : module->wires())
        if (wire->attributes.count(ID::init)) {
            SigSpec sig = active_sigmap(wire);
            Const val = wire->attributes.at(ID::init);
            for (int i = 0; i < GetSize(sig) && i < GetSize(val); i++)
                if (val[i] == State::S0 || val[i] == State::S1)
                    active_initdata[sig[i]] = val[i];
        }

    // TODO: remove if unnecessary
    if (!module->processes.empty())
        log_warning("Module %s contains unmapped RTLIL processes. RTLIL processes\n"
                    "can't always be mapped directly to Verilog always blocks. Unintended\n"
                    "changes in simulation behavior are possible! Use \"proc\" to convert\n"
                    "processes to logic networks and registers.\n",
            log_id(module));

    f << stringf("\n");
    for (auto it = module->processes.begin(); it != module->processes.end(); ++it)
        // This just updates internal data structures
        find_process_regs(it->second);

    if (!noexpr) {
        std::set<std::pair<RTLIL::Wire *, int>> reg_bits;
        for (auto cell : module->cells()) {
            if (!RTLIL::builtin_ff_cell_types().count(cell->type) || !cell->hasPort(ID::Q) ||
                cell->type.in(ID($ff), ID($_FF_)))
                continue;

            RTLIL::SigSpec sig = cell->getPort(ID::Q);

            if (sig.is_chunk()) {
                RTLIL::SigChunk chunk = sig.as_chunk();
                if (chunk.wire != NULL)
                    for (int i = 0; i < chunk.width; i++)
                        reg_bits.insert(
                            std::pair<RTLIL::Wire *, int>(chunk.wire, chunk.offset + i));
            }
        }
        for (auto wire : module->wires()) {
            for (int i = 0; i < wire->width; i++)
                if (reg_bits.count(std::pair<RTLIL::Wire *, int>(wire, i)) == 0)
                    goto this_wire_aint_reg;
            if (wire->width)
                reg_wires.insert(wire->name);
        this_wire_aint_reg:;
        }
    }

    // Entity declaration
    // Find ports first before dumping them
    std::map<int, Wire *> port_wires;
    for (auto wire : module->wires()) {
        if (wire->port_input || wire->port_output) {
            port_wires.insert({ wire->port_id, wire });
        }
    }
    dump_attributes(f, indent, module->attributes, /*modattr=*/true);
    f << indent << "entity " << id(module->name, false) << " is\n";
    {
        INDENT
        f << indent << "port (\n";

        for (auto wire_it = port_wires.cbegin(); wire_it != port_wires.cend(); wire_it++) {
            Wire *wire = wire_it->second;
            f << NEXT_INDENT(indent) << id(wire->name) << " : ";
            // TODO: Verilog inout = VHDL inout?
            if (wire->port_input && wire->port_output) {
                f << stringf(" inout ");
            }
            else if (wire->port_input && !wire->port_output) {
                f << stringf(" in ");
            }
            else if (!wire->port_input && wire->port_output) {
                f << stringf(" out ");
            }
            else {
                // Should never execute
                log_error("Port %s is neither an input nor an output\n", id(wire->name).c_str());
            }
            // TODO: verify arithmetic
            f << wire_typestr(wire);
            auto wire_it_next = std::next(wire_it);
            if (wire_it_next != port_wires.cend()) {
                f << stringf(";");
            }
            else {
                f << stringf(");");
            }
            f << stringf("\n");
        }
    }
    f << indent << "end entity " << id(module->name, false) << ";\n\n";

    // Architecture
    f << indent << stringf("architecture rtl of %s is\n", id(module->name, false).c_str());

    // submodules output ports should connect to temporary wires
    for (auto cell : module->cells()) {
        if (!is_internal_cell(cell->type)) {
            for (auto it = cell->connections().begin(); it != cell->connections().end(); ++it) {
                if (it->second.size() > 1 &&
                    it->second.chunks().size() > 1) { // TODO only check chunks?
                    if (cell->output(it->first)) {
                        auto new_wire = module->addWire(NEW_ID, it->second.size());
                        module->connect(it->second, new_wire);
                        cell->setPort(it->first, new_wire);
                        reset_auto_counter_id(new_wire->name, true);
                    }
                    else if (!std08 && cell->input(it->first)) { // TODO verify
                        auto new_wire = module->addWire(NEW_ID, it->second.size());
                        module->connect(new_wire, it->second);
                        cell->setPort(it->first, new_wire);
                        reset_auto_counter_id(new_wire->name, true);
                    }
                }
            }
        }
    }

    for (auto w : module->wires())
        dump_wire(f, NEXT_INDENT(indent), w);

    for (auto &mem : Mem::get_all_memories(module))
        dump_memory_types(f, NEXT_INDENT(indent), mem);

    f << indent << "begin\n";

    for (auto &mem : Mem::get_all_memories(module))
        // TODO: fix once ported
        dump_memory(f, NEXT_INDENT(indent), mem);

    for (auto cell : module->cells())
        dump_cell(f, NEXT_INDENT(indent), cell);

    for (auto it = module->processes.begin(); it != module->processes.end(); ++it)
        dump_process(f, NEXT_INDENT(indent), it->second);

    for (auto it = module->connections().begin(); it != module->connections().end(); ++it)
        dump_conn(f, NEXT_INDENT(indent), it->first, it->second);

    f << indent << stringf("end architecture;\n");
    active_module = NULL;
    active_sigmap.clear();
    active_initdata.clear();
}

void write_header_imports(std::ostream &f, std::string indent)
{
    f << indent << "library IEEE;\n";
    f << indent << "use IEEE.std_logic_1164.ALL;\n";
    // Could scan for arithmetic-type cells, but this is too cumbersome
    f << indent << "use IEEE.NUMERIC_STD.ALL;\n";
    if (extmem) {
        f << indent << "\nuse STD.TEXTIO.ALL\n";
    }
    if (unisim) {
        f << indent << "\n";
        f << indent << "library unisim;\n";
        f << indent << "use unisim.VCOMPONENTS.all;\n";
        f << indent << "use unisim.VPKG.all;\n";
    }
}

struct VHDLBackend : public Backend {
    VHDLBackend() : Backend("vhdl", "write design to VHDL file") {}
    void help() override
    {
        //   |---v---|---v---|---v---|---v---|---v---|---v---|---v---|---v---|---v---|---v---|
        log("\n");
        log("    write_vhdl [options] [filename]\n");
        log("\n");
        log("Write the current design to a VHDL file (WIP).\n");
        log("\n");
        log("    -std08\n");
        log("        use some VHDL-2008 syntax for more readable code\n");
        log("\n");
        log("    -norename\n");
        log("        without this option all internal object names (the ones with a dollar\n");
        log("        instead of a backslash prefix) are changed to short names in the\n");
        log("        format '<prefix>'. See '-renameprefix'.\n");
        log("\n");
        log("    -renameprefix <prefix>\n");
        log("        insert this prefix in front of auto-generated instance names, instead of the default \"n\"\n");
        log("\n");
        log("    -noattr\n");
        log("        with this option no attributes are included in the output\n");
        log("\n");
        log("    -attr2comment\n");
        log("        with this option attributes are included as comments in the output\n");
        log("\n");
        log("    -noexpr\n");
        log("        without this option all internal cells are converted to Verilog\n");
        log("        expressions.\n");
        log("\n");
        log("    -siminit\n");
        log("        add initial statements with hierarchical refs to initialize FFs when\n");
        log("        in -noexpr mode.\n");
        log("\n");
        log("    -nodec\n");
        log("        32-bit constant values are by default dumped as decimal numbers,\n");
        log("        not bit pattern. This option deactivates this feature and instead\n");
        log("        will write out all constants in binary.\n");
        log("\n");
        log("    -nohex\n");
        log("        constant values that are compatible with hex output are usually\n");
        log("        dumped as hex values. This option deactivates this feature and\n");
        log("        instead will write out all constants in binary.\n");
        log("\n");
        log("    -nostr\n");
        log("        Parameters and attributes that are specified as strings in the\n");
        log("        original input will be output as strings by this back-end. This\n");
        log("        deactivates this feature and instead will write string constants\n");
        log("        as binary numbers.\n");
        log("\n");
        log("    -nosimple-lhs\n");
        log("        Connection assignments with simple left hand side with concatenations. Only allowed with -std08.\n");
        log("\n");
        log("    -extmem\n");
        log("        instead of initializing memories using assignments to individual\n");
        log("        elements, use the '$readmemh' function to read initialization data\n");
        log("        from a file. This data is written to a file named by appending\n");
        log("        a sequential index to the Verilog filename and replacing the extension\n");
        log("        with '.mem', e.g. 'write_verilog -extmem foo.v' writes 'foo-1.mem',\n");
        log("        'foo-2.mem' and so on.\n");
        log("\n");
        log("    -blackboxes\n");
        log("        usually modules with the 'blackbox' attribute are ignored. with\n");
        log("        this option set only the modules with the 'blackbox' attribute\n");
        log("        are written to the output file.\n");
        log("\n");
        log("    -selected\n");
        log("        only write selected modules. modules must be selected entirely or\n");
        log("        not at all.\n");
        log("\n");
        log("    -unisim\n");
        log("        Add unisim library use to the preamble.\n");
        log("\n");
        log("    -v\n");
        log("        verbose output (print new names of all renamed wires and cells)\n");
        log("\n");
        log("Note that RTLIL processes can't always be mapped directly to Verilog\n");
        log("always blocks. This frontend should only be used to export an RTLIL\n");
        log("netlist, i.e. after the \"proc\" pass has been used to convert all\n");
        log("processes to logic networks and registers. A warning is generated when\n");
        log("this command is called on a design with RTLIL processes.\n");
        log("\n");
        log("RTLIL does not distinguish between a vector of length 1 and a nonvector.\n");
        log("This may cause pre-synth/post-synth mismatches when a port\n");
        log("is a vector of length 1.\n");
    }
    void execute(std::ostream *&f, std::string filename, std::vector<std::string> args,
        RTLIL::Design *design) override
    { // PORTING TOP COMPLETE, SUBROUTINES IN PROGRESS
        log_header(design, "Executing VHDL backend.\n");

        std08 = false;
        verbose = true;
        norename = false;
        noattr = false;
        attr2comment = false;
        noexpr = false;
        nodec = false;
        nohex = false;
        nostr = false;
        extmem = false;
        siminit = false;
        nosimple_lhs = false;
        auto_prefix = "n";
        unisim = false;

        bool blackboxes = false;
        bool selected = false;

        auto_name_map.clear();
        reg_wires.clear();

        size_t argidx;
        for (argidx = 1; argidx < args.size(); argidx++) {
            std::string arg = args[argidx];
            if (arg == "-std08") {
                std08 = true;
                continue;
            }
            if (arg == "-norename") {
                norename = true;
                continue;
            }
            if (arg == "-renameprefix" && argidx + 1 < args.size()) {
                auto_prefix = args[++argidx];
                continue;
            }
            if (arg == "-noattr") {
                noattr = true;
                continue;
            }
            if (arg == "-attr2comment") {
                attr2comment = true;
                continue;
            }
            if (arg == "-noexpr") {
                noexpr = true;
                continue;
            }
            if (arg == "-nodec") {
                nodec = true;
                continue;
            }
            if (arg == "-nohex") {
                nohex = true;
                continue;
            }
            if (arg == "-nostr") {
                nostr = true;
                continue;
            }
            if (arg == "-extmem") {
                extmem = true;
                extmem_counter = 1;
                continue;
            }
            if (arg == "-siminit") {
                siminit = true;
                continue;
            }
            if (arg == "-blackboxes") {
                blackboxes = true;
                continue;
            }
            if (arg == "-selected") {
                selected = true;
                continue;
            }
            if (arg == "-nosimple-lhs") {
                nosimple_lhs = true;
                continue;
            }
            if (arg == "-unisim") {
                unisim = true;
                continue;
            }
            if (arg == "-v") {
                verbose = true;
                continue;
            }
            break;
        }
        extra_args(f, filename, args, argidx);
        if (extmem) {
            if (filename == "<stdout>")
                log_cmd_error("Option -extmem must be used with a filename.\n");
            extmem_prefix = filename.substr(0, filename.rfind('.'));
        }
        if (auto_prefix.length() == 0) {
            log_cmd_error("Prefix specified by -renameprefix must not be empty.\n");
        }
        if (nosimple_lhs && !std08) {
            log_cmd_error("-nosimple-lhs is only allowed with -std08.\n");
        }

        design->sort();

        *f << stringf("-- Generated by:\n");
        // Already contains string "Yosys"
        *f << stringf("-- %s\n", yosys_version_str);
#ifdef VERSION
        *f << stringf("-- GHDL-Yosys-Plugin %s\n", VERSION);
#else
        *f << stringf("-- GHDL-Yosys-Plugin %s\n", "unknown version");
#endif
        // TODO: check all log calls to see if \n is needed
        log_experimental("VHDL backend");
        write_header_imports(*f, "");
        for (auto module : design->modules()) {
            if (module->get_blackbox_attribute() != blackboxes)
                continue;
            if (selected && !design->selected_whole_module(module->name)) {
                if (design->selected_module(module->name))
                    log_cmd_error(
                        "Can't handle partially selected module %s!\n", log_id(module->name));
                continue;
            }
            log("Dumping module `%s'.\n", module->name.c_str());
            dump_module(*f, "", module);
        }

        auto_name_map.clear();
        reg_wires.clear();
    }
} VHDLBackend;

PRIVATE_NAMESPACE_END
