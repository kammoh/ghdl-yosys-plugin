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
 */

#include "kernel/register.h"
#include "kernel/celltypes.h"
#include "kernel/log.h"
#include "kernel/sigtools.h"
#include <string>
#include <sstream>
#include <set>
#include <map>

USING_YOSYS_NAMESPACE
PRIVATE_NAMESPACE_BEGIN

bool verbose, norename, noattr, attr2comment, noexpr, nodec, nohex, nostr, extmem, defparam, siminit;
int auto_name_counter, auto_name_offset, auto_name_digits, extmem_counter;
std::map<RTLIL::IdString, int> auto_name_map;
std::set<RTLIL::IdString> reg_wires, reg_ct;
std::string auto_prefix, extmem_prefix;

RTLIL::Module *active_module;
dict<RTLIL::SigBit, RTLIL::State> active_initdata;
std::unordered_set<unsigned int> memory_array_types;
SigMap active_sigmap;

const char * const ctrl_char_array[]={"NUL", "SOH", "STX", "ETX",
				"EOT", "ENQ", "ACK", "BEL",
				"BS", "HT", "LF", "VT",
				"FF", "CR", "SO", "SI",
				"DLE", "DC1", "DC2", "DC3",
				"DC4", "NAK", "SYN", "ETB",
				"CAN", "EM", "SUB", "ESC",
				"FSP", "GSP", "RSP", "USP"};

void reset_auto_counter_id(RTLIL::IdString id, bool may_rename)
{ // NO PORTING REQUIRED
	const char *str = id.c_str();

	if (*str == '$' && may_rename && !norename)
		auto_name_map[id] = auto_name_counter++;

	if (str[0] != '\\' || str[1] != '_' || str[2] == 0)
		return;

	for (int i = 2; str[i] != 0; i++) {
		if (str[i] == '_' && str[i+1] == 0)
			continue;
		if (str[i] < '0' || str[i] > '9')
			return;
	}

	int num = atoi(str+2);
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
	for (size_t i = 10; i < auto_name_offset + auto_name_map.size(); i = i*10)
		auto_name_digits++;

	if (verbose)
		for (auto it = auto_name_map.begin(); it != auto_name_map.end(); ++it)
			log("  renaming `%s' to `%s%0*d'.\n", it->first.c_str(), auto_prefix.c_str(), auto_name_digits, auto_name_offset + it->second);
}

std::string next_auto_id()
{ // PORTING NEEDS TESTING
	return stringf("%s%0*d", auto_prefix.c_str(),
		auto_name_digits, auto_name_offset + auto_name_counter++);
}

std::string id(RTLIL::IdString internal_id, bool may_rename = true)
{ // PORTING NEEDS TESTING
	const char *str = internal_id.c_str();
	bool do_escape = false;

	if (may_rename && auto_name_map.count(internal_id) != 0)
		return stringf("%s%0*d", auto_prefix.c_str(), auto_name_digits, auto_name_offset + auto_name_map[internal_id]);

	if (*str == '\\')
		str++;

	if ('0' <= *str && *str <= '9')
		do_escape = true;

	for (int i = 0; str[i]; i++)
	{
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
	const pool<string> vhdl_keywords = {
		// IEEE 1076-2008 Section 15.10
		"abs", "access", "after", "alias", "all", "and",
		"architecture", "array", "assert", "assume",
		"assume_guarantee", "attribute", "begin", "block", "body",
		"buffer", "bus", "case", "component", "configuration",
		"constant", "context", "cover", "default", "disconnect",
		"downto", "else", "elsif", "end", "entity", "exit", "fairness",
		"file", "for", "force", "function", "generate", "generic",
		"group", "guarded", "if", "impure", "in", "inertial", "inout",
		"is", "label", "library", "linkage", "literal", "loop", "map",
		"mod", "nand", "new", "next", "nor", "not", "null", "of", "on",
		"open", "or", "others", "out", "package", "parameter", "port",
		"postponed", "procedure", "process", "property", "protected",
		"pure", "range", "record", "register", "reject", "release",
		"rem", "report", "restrict", "restrict_guarantee", "return",
		"rol", "ror", "select", "sequence", "severity", "shared",
		"signal", "sla", "sll", "sra", "srl", "strong", "subtype",
		"then", "to", "transport", "type", "unaffected", "units",
		"until", "use", "variable", "vmode", "vprop", "vunit", "wait",
		"when", "while", "with", "xnor", "xor"
	};
	const pool<string> psl_keywords = {
		// IEEE 1076-2008 Section 15.10
		"assert", "assume", "assume_guarantee", "cover", "default",
		"fairness", "property", "restrict", "restrict_guarantee",
		"sequence", "strong", "vmode", "vprop", "vunit"
	};
	if (vhdl_keywords.count(str) || psl_keywords.count(str))
		do_escape = true;
	// TODO: check for numbers afterwards, but regex is overkill here
	// array_type_(width) is used by the memory dump pass
	if (strncmp(str,"array_type_",strlen("array_type_"))==0)
		do_escape = true;

	if (do_escape)
		// VHDL extended identifier
		return "\\" + std::string(str) + "\\";
	return std::string(str);
}

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
			reg_name += stringf("(%d)",
				chunk.wire->start_offset + chunk.offset);
		else if (chunk.wire->upto)
			reg_name += stringf("(%d to %d)",
				(chunk.wire->width - (chunk.offset + chunk.width - 1) - 1) + chunk.wire->start_offset,
				(chunk.wire->width - chunk.offset - 1) + chunk.wire->start_offset);
		else
			reg_name += stringf("(%d downto %d)",
				chunk.wire->start_offset + chunk.offset + chunk.width - 1,
				chunk.wire->start_offset + chunk.offset);
	}

	return true;
}

void dump_const(std::ostream &f, const RTLIL::Const &data, int width = -1, int offset = 0, bool no_decimal = false)
{ // PORTING NEEDS TESTING
	bool set_signed = (data.flags & RTLIL::CONST_FLAG_SIGNED) != 0;
	/* TODO: verify correctness
	 * width==0 is a null range, as defined by IEEE 1076-2008 5.2.1
	 * width<0 is ?
	 */
	if (width < 0)
		width = data.bits.size() - offset;
	if (width == 0) {
		f << "(others => '0')";
		return;
	}
	if (nostr)
		goto dump_hex;
	if ((data.flags & RTLIL::CONST_FLAG_STRING) == 0 || width != (int)data.bits.size()) {
		if (width == 32 && !no_decimal && !nodec) {
			int32_t val = 0;
			for (int i = offset+width-1; i >= offset; i--) {
				log_assert(i < (int)data.bits.size());
				if (data.bits[i] != State::S0 && data.bits[i] != State::S1)
					goto dump_hex;
				if (data.bits[i] == State::S1)
					val |= 1 << (i - offset);
			}
			if (set_signed)
				f << stringf("std_logic_vector(to_signed(%d,%d))", val, width);
			else
				f << stringf("std_logic_vector(to_unsigned(%d,%d))", val, width);
		} else {
	dump_hex:
			if (nohex)
				goto dump_bin;
			vector<char> bin_digits, hex_digits;
			for (int i = offset; i < offset+width; i++) {
				log_assert(i < (int)data.bits.size());
				switch (data.bits[i]) {
				case State::S0: bin_digits.push_back('0'); break;
				case State::S1: bin_digits.push_back('1'); break;
				case RTLIL::Sx: bin_digits.push_back('x'); break;
				case RTLIL::Sz: bin_digits.push_back('z'); break;
				case RTLIL::Sa: bin_digits.push_back('-'); break;
				case RTLIL::Sm: log_error("Found marker state in final netlist.");
				}
			}
			if (GetSize(bin_digits) <= 1)
				goto dump_bin;
			while (GetSize(bin_digits) % 4 != 0)
				if (bin_digits.back() == '1')
					bin_digits.push_back('0');
				else
					bin_digits.push_back(bin_digits.back());
			for (int i = 0; i < GetSize(bin_digits); i += 4)
			{
				char bit_3 = bin_digits[i+3];
				char bit_2 = bin_digits[i+2];
				char bit_1 = bin_digits[i+1];
				char bit_0 = bin_digits[i+0];
				if (bit_3 == 'x' || bit_2 == 'x' || bit_1 == 'x' || bit_0 == 'x') {
					if (bit_3 != 'x' || bit_2 != 'x' || bit_1 != 'x' || bit_0 != 'x')
						goto dump_bin;
					hex_digits.push_back('x');
					continue;
				}
				if (bit_3 == 'z' || bit_2 == 'z' || bit_1 == 'z' || bit_0 == 'z') {
					if (bit_3 != 'z' || bit_2 != 'z' || bit_1 != 'z' || bit_0 != 'z')
						goto dump_bin;
					hex_digits.push_back('z');
					continue;
				}
				if (bit_3 == '-' || bit_2 == '-' || bit_1 == '-' || bit_0 == '-') {
					if (bit_3 != '-' || bit_2 != '-' || bit_1 != '-' || bit_0 != '-')
						goto dump_bin;
					hex_digits.push_back('-');
					continue;
				}
				int val = 8*(bit_3 - '0') + 4*(bit_2 - '0') + 2*(bit_1 - '0') + (bit_0 - '0');
				hex_digits.push_back(val < 10 ? '0' + val : 'a' + val - 10);
			}
			// TODO: is this correct when the width is not a multiple of 4?
			f << stringf("x\"");
			for (int i = GetSize(hex_digits)-1; i >= 0; i--)
				f << hex_digits[i];
			f << stringf("\"");
		}
		if (0) {
	dump_bin:
			if (width > 1) {
				f << stringf("\"");
			} else {
				f << stringf("'");
			}
			for (int i = offset+width-1; i >= offset; i--) {
				log_assert(i < (int)data.bits.size());
				switch (data.bits[i]) {
				case State::S0: f << stringf("0"); break;
				case State::S1: f << stringf("1"); break;
				case RTLIL::Sx: f << stringf("x"); break;
				case RTLIL::Sz: f << stringf("z"); break;
				case RTLIL::Sa: f << stringf("-"); break;
				case RTLIL::Sm: log_error("Found marker state in final netlist.");
				}
			}
			if (width > 1) {
				f << stringf("\"");
			} else {
				f << stringf("'");
			}
		}
	} else {
		if ((data.flags & RTLIL::CONST_FLAG_REAL) == 0)
			f << stringf("\"");
		std::string str = data.decode_string();
		for (size_t i = 0; i < str.size(); i++) {
			unsigned char current_char_unsigned = (unsigned char) str[i];
			/*
			 * See the following IEEE 1076-2008 sections:
			 * 15.7 "Character Set"
			 * 15.9 "String Literals"
			 * 16.3 "Package STANDARD"
			 */
			if (current_char_unsigned < 32)
				f << stringf("\" & %s & \"",
					ctrl_char_array[current_char_unsigned]);
			else if (current_char_unsigned >= 128
					&& current_char_unsigned <= 159)
				f << stringf("\" & C%d & \"", current_char_unsigned);
			else if (str[i] == '"')
				f << stringf("\"\"");
			else
				f << str[i];
		}
		if ((data.flags & RTLIL::CONST_FLAG_REAL) == 0)
			f << stringf("\"");
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
		} else {
			initval.bits.push_back(State::Sx);
		}
	}

	if (gotinit) {
		f << " := ";
		dump_const(f, initval);
	}
}

void dump_sigchunk(std::ostream &f, const RTLIL::SigChunk &chunk, bool no_decimal = false)
{ // PORTING NEEDS TESTING
	if (chunk.wire == NULL) {
		dump_const(f, chunk.data, chunk.width, chunk.offset, no_decimal);
	} else {
		if (chunk.width == chunk.wire->width && chunk.offset == 0) {
			f << stringf("%s", id(chunk.wire->name).c_str());
		} else if (chunk.width == 1) {
			if (chunk.wire->upto)
				f << stringf("%s (%d)", id(chunk.wire->name).c_str(), (chunk.wire->width - chunk.offset - 1) + chunk.wire->start_offset);
			else
				f << stringf("%s (%d)", id(chunk.wire->name).c_str(), chunk.offset + chunk.wire->start_offset);
		} else {
			if (chunk.wire->upto)
				f << stringf("%s (%d to %d)", id(chunk.wire->name).c_str(),
						(chunk.wire->width - (chunk.offset + chunk.width - 1) - 1) + chunk.wire->start_offset,
						(chunk.wire->width - chunk.offset - 1) + chunk.wire->start_offset);
			else
				f << stringf("%s (%d downto %d)", id(chunk.wire->name).c_str(),
						(chunk.offset + chunk.width - 1) + chunk.wire->start_offset,
						chunk.offset + chunk.wire->start_offset);
		}
	}
}

void dump_sigspec(std::ostream &f, const RTLIL::SigSpec &sig)
{ // PORTING NEEDS TESTING
	if (GetSize(sig) == 0) {
		// TODO this is a null range that may not be handled correctly
		f << "\"\"";
		return;
	}
	if (sig.is_chunk()) {
		dump_sigchunk(f, sig.as_chunk());
	} else {
		for (auto it = sig.chunks().rbegin(); it != sig.chunks().rend(); ++it) {
			if (it != sig.chunks().rbegin())
				f << stringf(" & ");
			dump_sigchunk(f, *it, true);
		}
	}
}

void dump_attributes(std::ostream &f, std::string indent, dict<RTLIL::IdString, RTLIL::Const> &attributes, bool modattr = false, bool regattr = false, bool as_comment = false)
{ // PORTING REQUIRED
	if (noattr)
		return;
	if (attr2comment)
		as_comment = true;
	for (auto it = attributes.begin(); it != attributes.end(); ++it) {
		if (it->first == ID::init && regattr) continue;
		f << stringf("%s" "%s %s", indent.c_str(), as_comment ? "/*" : "(*", id(it->first).c_str());
		f << stringf(" = ");
		if (modattr && (it->second == State::S0 || it->second == Const(0)))
			f << stringf(" 0 ");
		else if (modattr && (it->second == State::S1 || it->second == Const(1)))
			f << stringf(" 1 ");
		else
			dump_const(f, it->second, -1, 0, false);
		f << stringf(" %s\n", as_comment ? "*/" : "*)");
	}
}

void dump_wire(std::ostream &f, std::string indent, RTLIL::Wire *wire)
{ // PORTING NEEDS TESTING
	// Ports are dumped earlier in entity declaration, so ignore them here
	dump_attributes(f, indent, wire->attributes, /*modattr=*/false, /*regattr=*/reg_wires.count(wire->name));
	std::string typestr = "";
	if (wire->width != 1) {
		if (wire->upto)
			typestr = stringf("STD_LOGIC_VECTOR (%d to %d)", wire->start_offset,
				wire->width - 1 + wire->start_offset);
		else
			typestr = stringf("STD_LOGIC_VECTOR (%d downto %d)",
				wire->width - 1 + wire->start_offset, wire->start_offset);
	} else {
		typestr = stringf("STD_LOGIC");
	}
	if (!wire->port_input && !wire->port_output) {
		f << stringf("%s" "signal %s: %s", indent.c_str(),
			id(wire->name).c_str(), typestr.c_str());
		if (reg_wires.count(wire->name) && wire->attributes.count(ID::init)) {
			f << stringf(" := ");
			dump_const(f, wire->attributes.at(ID::init));
		}
		f << stringf(";\n");
	}
}

void dump_memory(std::ostream &f, std::string indent, RTLIL::Memory *memory)
{ // PORTING NEEDS TESTING
	size_t is_element_present = memory_array_types.count(memory->width);
	std::string memory_type_name = stringf("array_type_%d",memory->width);
	if (!is_element_present) {
		memory_array_types.insert(memory->width);
		f << stringf("%s"
			"type %s is array (natural range <>) of std_logic_vector(%d downto 0)\n",
			indent.c_str(), memory_type_name.c_str(), memory->width-1);
	}
	dump_attributes(f, indent, memory->attributes);
	// TODO: if memory->size is always positive then this is unnecessary
	std::string range_str = stringf("(%d %s %d)",
			memory->start_offset+memory->size-1,
			memory->size>=0 ? "downto" : "to", memory->start_offset);
	// TODO: memory initialization?
	f << stringf("%s" "signal %s: %s %s;\n", indent.c_str(),
		id(memory->name).c_str(), memory_type_name.c_str(),
		range_str.c_str());
}

void dump_cell_expr_port(std::ostream &f, RTLIL::Cell *cell, std::string port, bool gen_signed = true, bool gen_unsigned = false)
{ // PORTING NEEDS TESTING
	SigSpec signal_spec = cell->getPort("\\" + port);
	bool signal_is_const = signal_spec.is_fully_const();
	if (gen_signed && !signal_is_const &&
			cell->parameters.count("\\" + port + "_SIGNED") > 0 &&
			cell->parameters["\\" + port + "_SIGNED"].as_bool()) {
		// TODO check how signed arithmetic interacts with x"blah" constants
		f << stringf("signed(");
		dump_sigspec(f, signal_spec);
		f << stringf(")");
	} else if (gen_unsigned && !signal_is_const) {
		f << stringf("unsigned(");
		dump_sigspec(f, signal_spec);
		f << stringf(")");
	} else {
		dump_sigspec(f, signal_spec);
	}
}

std::string cellname(RTLIL::Cell *cell)
{ // PORTING NEEDS TESTING
	if (!norename && cell->name[0] == '$' && reg_ct.count(cell->type) && cell->hasPort(ID::Q))
	{
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
	else
	{
no_special_reg_name:
		return id(cell->name).c_str();
	}
}

void dump_cell_expr_uniop(std::ostream &f, std::string indent, RTLIL::Cell *cell, std::string op, bool is_arith_op = false)
{ // PORTING NEEDS TESTING
	f << stringf("%s", indent.c_str());
	dump_sigspec(f, cell->getPort(ID::Y));
	f << stringf(" <= ");
	if (is_arith_op) {
		f << stringf("std_logic_vector(");
	}
	f << stringf(" %s ", op.c_str());
	dump_attributes(f, "", cell->attributes, ' ');
	dump_cell_expr_port(f, cell, "A", is_arith_op, is_arith_op);
	if (is_arith_op) {
		f << stringf(")");
	}
	f << stringf(";\n");
}

void dump_cell_expr_binop(std::ostream &f, std::string indent, RTLIL::Cell *cell, std::string op, bool is_arith_op = false)
{ // PORTING NEEDS TESTING
	// TODO: typecasting for arithmetic operations
	f << stringf("%s", indent.c_str());
	dump_sigspec(f, cell->getPort(ID::Y));
	f << stringf(" <= ");
	if (is_arith_op) {
		f << stringf("std_logic_vector(");
	}
	dump_cell_expr_port(f, cell, "A", is_arith_op, is_arith_op);
	f << stringf(" %s ", op.c_str());
	dump_attributes(f, "", cell->attributes, ' ');
	dump_cell_expr_port(f, cell, "B", is_arith_op, is_arith_op);
	if (is_arith_op) {
		f << stringf(")");
	}
	f << stringf(";\n");
}

bool dump_cell_expr(std::ostream &f, std::string indent, RTLIL::Cell *cell)
{ // PORTING IN PROGRESS
	f << stringf("-- Cell type is %s\n", cell->type.c_str());
	if (cell->type == ID($_NOT_)) {
		f << stringf("%s", indent.c_str());
		dump_sigspec(f, cell->getPort(ID::Y));
		f << stringf(" = ");
		f << stringf("not ");
		dump_attributes(f, "", cell->attributes, ' ');
		dump_cell_expr_port(f, cell, "A", false);
		f << stringf(";\n");
		return true;
	}

	if (cell->type.in(ID($_AND_), ID($_NAND_), ID($_OR_), ID($_NOR_), ID($_XOR_), ID($_XNOR_), ID($_ANDNOT_), ID($_ORNOT_))) {
		f << stringf("%s", indent.c_str());
		dump_sigspec(f, cell->getPort(ID::Y));
		f << stringf(" = ");
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
		f << stringf(";\n");
		return true;
	}

	if (cell->type == ID($_MUX_)) {
		// TODO: attribute dumping was on B
		dump_attributes(f, "", cell->attributes, ' ');
		f << stringf("%s", indent.c_str());
		dump_sigspec(f, cell->getPort(ID::Y));
		f << stringf(" = ");
		dump_cell_expr_port(f, cell, "B", false);
		f << stringf(" when ");
		dump_cell_expr_port(f, cell, "S", false);
		f << stringf(" = '1' else ");
		dump_cell_expr_port(f, cell, "A", false);
		f << stringf(";\n");
		return true;
	}

	if (cell->type == ID($_NMUX_)) {
		// TODO: attribute dumping was on B
		dump_attributes(f, "", cell->attributes, ' ');
		f << stringf("%s" "assign ", indent.c_str());
		dump_sigspec(f, cell->getPort(ID::Y));
		f << stringf(" = !(");
		dump_cell_expr_port(f, cell, "B", false);
		f << stringf(" when ");
		dump_cell_expr_port(f, cell, "S", false);
		f << stringf(" = '1' else ");
		dump_cell_expr_port(f, cell, "A", false);
		f << stringf(");\n");
		return true;
	}

	if (cell->type.in(ID($_AOI3_), ID($_OAI3_))) {
		f << stringf("%s", indent.c_str());
		dump_sigspec(f, cell->getPort(ID::Y));
		f << stringf(" = not ((");
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
		f << stringf("%s", indent.c_str());
		dump_sigspec(f, cell->getPort(ID::Y));
		f << stringf(" = not ((");
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

	if (cell->type.begins_with("$_DFF_"))
	{
		std::string reg_name = cellname(cell);
		bool out_is_reg_wire = is_reg_wire(cell->getPort(ID::Q), reg_name);

		std::string assignment_operator = out_is_reg_wire ? "<=" : ":=";

		// Sensitivity list
		// [6] == P is rising
		// [7] != _ is asynchronous reset
		dump_attributes(f, indent, cell->attributes);
		f << stringf("%s" "process(", indent.c_str());
		dump_sigspec(f, cell->getPort(ID::C));
		if (cell->type[7] != '_') {
			f << stringf(", ");
			dump_sigspec(f, cell->getPort(ID::R));
		}
		f << stringf(") is\n");
		// TODO: implicit assumption of width 1
		// TODO: get rid of intermediate variable?
		if (!out_is_reg_wire) {
			f << stringf("%s" "  variable %s: STD_LOGIC ", indent.c_str(), reg_name.c_str());
			dump_reg_init(f, cell->getPort(ID::Q));
			f << "\n";
		}
		f << stringf("%s" "begin\n", indent.c_str());

		// Actual edge checking logic (clock, async reset if present)
		if (cell->type[7] != '_') {
			// async reset
			f << stringf("%s" "  if ", indent.c_str());
			dump_sigspec(f, cell->getPort(ID::R));
			f << stringf(" = '%c' then\n", cell->type[7] == 'P' ? '1' : '0');
			f << stringf("%s" "    %s %s '%c';\n", indent.c_str(),
				reg_name.c_str(), assignment_operator.c_str(), cell->type[8]);
		}
		// clock edge
		f << stringf("%s" "  %s %s_edge(", indent.c_str(),
			cell->type[7] != '_' ? "elsif" : "if",
			cell->type[6] == 'P' ? "rising" : "falling");
		dump_sigspec(f, cell->getPort(ID::C));
		f << stringf(") then\n");

		f << stringf("%s" "    %s %s ", indent.c_str(),
			assignment_operator.c_str(), reg_name.c_str());
		dump_cell_expr_port(f, cell, "D", false);
		f << stringf(";\n");
		f << stringf("%s" "  end if;\n", indent.c_str());

		if (!out_is_reg_wire) {
			f << stringf("%s  ", indent.c_str());
			dump_sigspec(f, cell->getPort(ID::Q));
			f << stringf(" <= %s;\n", reg_name.c_str());
		}
		f << stringf("%s" "end process;\n", indent.c_str());

		return true;
	}

	if (cell->type.begins_with("$_DFFSR_"))
	{
		char pol_c = cell->type[8], pol_s = cell->type[9], pol_r = cell->type[10];

		std::string reg_name = cellname(cell);
		bool out_is_reg_wire = is_reg_wire(cell->getPort(ID::Q), reg_name);

		std::string assignment_operator = out_is_reg_wire ? "<=" : ":=";

		// Sensitivity list
		dump_attributes(f, indent, cell->attributes);
		f << stringf("%s" "process(", indent.c_str());
		dump_sigspec(f, cell->getPort(ID::C));
		f << stringf(", ");
		dump_sigspec(f, cell->getPort(ID::R));
		f << stringf(", ");
		dump_sigspec(f, cell->getPort(ID::S));
		f << stringf(") is\n");
		// TODO: implicit assumption of width 1
		// TODO: get rid of intermediate variable?
		if (!out_is_reg_wire) {
			f << stringf("%s" "  variable %s: STD_LOGIC ", indent.c_str(), reg_name.c_str());
			dump_reg_init(f, cell->getPort(ID::Q));
			f << "\n";
		}
		f << stringf("%s" "begin\n", indent.c_str());

		// reset
		f << stringf("%s" "  if ", indent.c_str());
		dump_sigspec(f, cell->getPort(ID::R));
		f << stringf("%s" " = '%c' then\n", indent.c_str(),
			pol_r == 'P' ? '1' : '0');
		f << stringf("%s" "    %s %s '0'", indent.c_str(),
			reg_name.c_str(), assignment_operator.c_str());
		// set
		f << stringf("%s" "  elsif ", indent.c_str());
		dump_sigspec(f, cell->getPort(ID::S));
		f << stringf("%s" " = '%c' then\n", indent.c_str(),
			pol_s == 'P' ? '1' : '0');
		f << stringf("%s" "    %s %s '1'", indent.c_str(),
			reg_name.c_str(), assignment_operator.c_str());
		// clock edge
		f << stringf("%s" "  elsif %s_edge(", indent.c_str(),
			pol_c == 'P' ? "rising" : "falling");
		dump_sigspec(f, cell->getPort(ID::C));
		f << stringf(") then\n");

		f << stringf("%s" "    %s %s ", indent.c_str(),
			reg_name.c_str(), assignment_operator.c_str());
		dump_cell_expr_port(f, cell, "D", false);
		f << stringf(";\n");
		f << stringf("%s" "  end if;\n", indent.c_str());

		if (!out_is_reg_wire) {
			f << stringf("%s  ", indent.c_str());
			dump_sigspec(f, cell->getPort(ID::Q));
			f << stringf(" <= %s;\n", reg_name.c_str());
		}

		return true;
	}

#define HANDLE_UNIOP(_type, _operator, _is_arith) \
	if (cell->type ==_type) { dump_cell_expr_uniop(f, indent, cell, _operator, _is_arith); return true; }
#define HANDLE_BINOP(_type, _operator, _is_arith) \
	if (cell->type ==_type) { dump_cell_expr_binop(f, indent, cell, _operator, _is_arith); return true; }

	// UNIOP/BINOP symbols partly ported
	// TODO: casts to unsigned/signed as appropriate
	HANDLE_UNIOP(ID($not), "not", false)
	HANDLE_UNIOP(ID($pos), "+",   true) // unported
	HANDLE_UNIOP(ID($neg), "-",   true) // unported

	HANDLE_BINOP(ID($and),  "and",  false)
	HANDLE_BINOP(ID($or),   "or",   false)
	HANDLE_BINOP(ID($xor),  "xor",  false)
	HANDLE_BINOP(ID($xnor), "xnor", false)

	// Cheat a bit and use the VHDL-2008 operators for now
	// TODO: replace the generated VHDL-2008 code with 93-compatible code
	HANDLE_UNIOP(ID($reduce_and),  "and",  false)
	HANDLE_UNIOP(ID($reduce_or),   "or",   false)
	HANDLE_UNIOP(ID($reduce_xor),  "xor",  false)
	HANDLE_UNIOP(ID($reduce_xnor), "xnor", false)
	HANDLE_UNIOP(ID($reduce_bool), "or",   false)

	// TODO: port these
	HANDLE_BINOP(ID($shl),  "<<",  false)
	HANDLE_BINOP(ID($shr),  ">>",  false)
	HANDLE_BINOP(ID($sshl), "<<<", true)
	HANDLE_BINOP(ID($sshr), ">>>", true)

	// TODO: check if we want to replicate $eq vs $eqx in VHDL
	// TODO: port these
	HANDLE_BINOP(ID($lt),  "<",  true)
	HANDLE_BINOP(ID($le),  "<=", true)
	HANDLE_BINOP(ID($eq),  "=", false)
	HANDLE_BINOP(ID($ne),  "!=", true)
	HANDLE_BINOP(ID($eqx), "=", false)
	HANDLE_BINOP(ID($nex), "!=", true)
	HANDLE_BINOP(ID($ge),  ">=", true)
	HANDLE_BINOP(ID($gt),  ">",  true)

	HANDLE_BINOP(ID($add), "+",   true)
	HANDLE_BINOP(ID($sub), "-",   true)
	HANDLE_BINOP(ID($mul), "*",   true)
	HANDLE_BINOP(ID($div), "/",   true)
	HANDLE_BINOP(ID($mod), "mod", true)
	HANDLE_BINOP(ID($pow), "**",  true) // unported

	HANDLE_UNIOP(ID($logic_not), "not", false)
	HANDLE_BINOP(ID($logic_and), "and", false)
	HANDLE_BINOP(ID($logic_or),  "or",  false)

#undef HANDLE_UNIOP
#undef HANDLE_BINOP

	if (cell->type == ID($shift))
	{ // unported for now
		f << stringf("%s" "assign ", indent.c_str());
		dump_sigspec(f, cell->getPort(ID::Y));
		f << stringf(" = ");
		if (cell->getParam(ID::B_SIGNED).as_bool())
		{
			f << stringf("$signed(");
			dump_sigspec(f, cell->getPort(ID::B));
			f << stringf(")");
			f << stringf(" < 0 ? ");
			dump_sigspec(f, cell->getPort(ID::A));
			f << stringf(" << - ");
			dump_sigspec(f, cell->getPort(ID::B));
			f << stringf(" : ");
			dump_sigspec(f, cell->getPort(ID::A));
			f << stringf(" >> ");
			dump_sigspec(f, cell->getPort(ID::B));
		}
		else
		{
			dump_sigspec(f, cell->getPort(ID::A));
			f << stringf(" >> ");
			dump_sigspec(f, cell->getPort(ID::B));
		}
		f << stringf(";\n");
		return true;
	}

	if (cell->type == ID($shiftx))
	{ // unported for now
		std::string temp_id = next_auto_id();
		f << stringf("%s" "wire [%d:0] %s = ", indent.c_str(), GetSize(cell->getPort(ID::A))-1, temp_id.c_str());
		dump_sigspec(f, cell->getPort(ID::A));
		f << stringf(";\n");

		f << stringf("%s" "assign ", indent.c_str());
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

	if (cell->type == ID($mux))
	{
		// TODO: attribute dumping was on B
		dump_attributes(f, "", cell->attributes, ' ');
		f << stringf("%s", indent.c_str());
		dump_sigspec(f, cell->getPort(ID::Y));
		f << stringf(" <= ");
		dump_sigspec(f, cell->getPort(ID::B));
		f << stringf(" when ");
		dump_sigspec(f, cell->getPort(ID::S));
		f << stringf(" = '1' else ");
		dump_sigspec(f, cell->getPort(ID::A));
		f << stringf(";\n");
		return true;
	}

	if (cell->type == ID($pmux))
	{ // unported for now
		int width = cell->parameters[ID::WIDTH].as_int();
		int s_width = cell->getPort(ID::S).size();
		std::string func_name = cellname(cell);

		f << stringf("%s" "function [%d:0] %s;\n", indent.c_str(), width-1, func_name.c_str());
		f << stringf("%s" "  input [%d:0] a;\n", indent.c_str(), width-1);
		f << stringf("%s" "  input [%d:0] b;\n", indent.c_str(), s_width*width-1);
		f << stringf("%s" "  input [%d:0] s;\n", indent.c_str(), s_width-1);

		dump_attributes(f, indent + "  ", cell->attributes);
		if (!noattr)
			f << stringf("%s" "  (* parallel_case *)\n", indent.c_str());
		f << stringf("%s" "  casez (s)", indent.c_str());
		f << stringf(noattr ? " // synopsys parallel_case\n" : "\n");

		for (int i = 0; i < s_width; i++)
		{
			f << stringf("%s" "    %d'b", indent.c_str(), s_width);

			for (int j = s_width-1; j >= 0; j--)
				f << stringf("%c", j == i ? '1' : '?');

			f << stringf(":\n");
			f << stringf("%s" "      %s = b[%d:%d];\n", indent.c_str(), func_name.c_str(), (i+1)*width-1, i*width);
		}

		f << stringf("%s" "    default:\n", indent.c_str());
		f << stringf("%s" "      %s = a;\n", indent.c_str(), func_name.c_str());

		f << stringf("%s" "  endcase\n", indent.c_str());
		f << stringf("%s" "endfunction\n", indent.c_str());

		f << stringf("%s" "assign ", indent.c_str());
		dump_sigspec(f, cell->getPort(ID::Y));
		f << stringf(" = %s(", func_name.c_str());
		dump_sigspec(f, cell->getPort(ID::A));
		f << stringf(", ");
		dump_sigspec(f, cell->getPort(ID::B));
		f << stringf(", ");
		dump_sigspec(f, cell->getPort(ID::S));
		f << stringf(");\n");
		return true;
	}

	if (cell->type == ID($tribuf))
	{
		f << stringf("%s", indent.c_str());
		dump_sigspec(f, cell->getPort(ID::Y));
		f << stringf(" <= ");
		dump_sigspec(f, cell->getPort(ID::A));
		f << stringf(" when ");
		dump_sigspec(f, cell->getPort(ID::EN));
		f << stringf(" = '1' else");
		if (cell->parameters.at(ID::WIDTH).as_int()==1) {
			f << stringf("'z'");
		} else {
			f << stringf("(others => 'z')");
		}
		f << stringf(";\n");
		return true;
	}

	if (cell->type == ID($slice))
	{ // unported for now
		f << stringf("%s" "assign ", indent.c_str());
		dump_sigspec(f, cell->getPort(ID::Y));
		f << stringf(" = ");
		dump_sigspec(f, cell->getPort(ID::A));
		f << stringf(" >> %d;\n", cell->parameters.at(ID::OFFSET).as_int());
		return true;
	}

	if (cell->type == ID($concat))
	{
		f << stringf("%s", indent.c_str());
		dump_sigspec(f, cell->getPort(ID::Y));
		f << stringf(" <= ");
		dump_sigspec(f, cell->getPort(ID::B));
		f << stringf(" & ");
		dump_sigspec(f, cell->getPort(ID::A));
		f << stringf(";\n");
		return true;
	}

	if (cell->type == ID($lut))
	{ // unported for now
		f << stringf("%s" "assign ", indent.c_str());
		dump_sigspec(f, cell->getPort(ID::Y));
		f << stringf(" = ");
		dump_const(f, cell->parameters.at(ID::LUT));
		f << stringf(" >> ");
		dump_attributes(f, "", cell->attributes, ' ');
		dump_sigspec(f, cell->getPort(ID::A));
		f << stringf(";\n");
		return true;
	}

	if (cell->type == ID($dffsr))
	{ // porting in progress
		SigSpec sig_clk = cell->getPort(ID::CLK);
		SigSpec sig_set = cell->getPort(ID::SET);
		SigSpec sig_clr = cell->getPort(ID::CLR);
		SigSpec sig_d = cell->getPort(ID::D);
		SigSpec sig_q = cell->getPort(ID::Q);

		int width = cell->parameters[ID::WIDTH].as_int();
		bool pol_clk = cell->parameters[ID::CLK_POLARITY].as_bool();
		bool pol_set = cell->parameters[ID::SET_POLARITY].as_bool();
		bool pol_clr = cell->parameters[ID::CLR_POLARITY].as_bool();

		std::string reg_name = cellname(cell);
		bool out_is_reg_wire = is_reg_wire(sig_q, reg_name);

		std::string assignment_operator = out_is_reg_wire ? "<=" : ":=";

		if (!out_is_reg_wire) {
			f << stringf("%s" "  variable %s: STD_LOGIC_VECTOR (%d downto 0)", indent.c_str(), reg_name.c_str(), width-1);
			dump_reg_init(f, sig_q);
			f << ";\n";
		}
		// This could look nicer as a generate statement
		for (int i = 0; i < width; i++) {
			f << stringf("%s" "always @(%sedge ", indent.c_str(), pol_clk ? "pos" : "neg");
			dump_sigspec(f, sig_clk);
			f << stringf(", %sedge ", pol_set ? "pos" : "neg");
			dump_sigspec(f, sig_set);
			f << stringf(", %sedge ", pol_clr ? "pos" : "neg");
			dump_sigspec(f, sig_clr);
			f << stringf(")\n");

			f << stringf("%s" "  if (%s", indent.c_str(), pol_clr ? "" : "!");
			dump_sigspec(f, sig_clr);
			f << stringf(") %s[%d] <= 1'b0;\n", reg_name.c_str(), i);

			f << stringf("%s" "  else if (%s", indent.c_str(), pol_set ? "" : "!");
			dump_sigspec(f, sig_set);
			f << stringf(") %s[%d] <= 1'b1;\n", reg_name.c_str(), i);

			f << stringf("%s" "  else  %s[%d] <= ", indent.c_str(), reg_name.c_str(), i);
			dump_sigspec(f, sig_d[i]);
			f << stringf(";\n");
		}

		if (!out_is_reg_wire) {
			f << stringf("%s" "assign ", indent.c_str());
			dump_sigspec(f, sig_q);
			f << stringf(" = %s;\n", reg_name.c_str());
		}

		return true;
	}

	if (cell->type.in(ID($dff), ID($adff), ID($dffe)))
	{
		RTLIL::SigSpec sig_clk, sig_arst, sig_en, val_arst;
		bool pol_clk, pol_arst = false, pol_en = false;

		sig_clk = cell->getPort(ID::CLK);
		pol_clk = cell->parameters[ID::CLK_POLARITY].as_bool();

		if (cell->type == ID($adff)) {
			sig_arst = cell->getPort(ID::ARST);
			pol_arst = cell->parameters[ID::ARST_POLARITY].as_bool();
			val_arst = RTLIL::SigSpec(cell->parameters[ID::ARST_VALUE]);
		}

		if (cell->type == ID($dffe)) {
			sig_en = cell->getPort(ID::EN);
			pol_en = cell->parameters[ID::EN_POLARITY].as_bool();
		}

		std::string reg_name = cellname(cell);
		bool out_is_reg_wire = is_reg_wire(cell->getPort(ID::Q), reg_name);

		std::string assignment_operator = out_is_reg_wire ? "<=" : ":=";

		f << stringf("%s" "process (", indent.c_str());
		dump_sigspec(f, sig_clk);
		if (cell->type == ID($adff)) {
			f << stringf(", ");
			dump_sigspec(f, sig_arst);
		}
		f << stringf(") is\n");

		if (!out_is_reg_wire) {
			f << stringf("%s" "  variable %s: STD_LOGIC_VECTOR (%d downto 0)",
				indent.c_str(), reg_name.c_str(), 
				cell->parameters[ID::WIDTH].as_int()-1);
			dump_reg_init(f, cell->getPort(ID::Q));
			f << ";\n";
		}
		f << stringf("%s" "begin\n", indent.c_str());

		if (cell->type == ID($adff)) {
			f << stringf("%s" "  if ", indent.c_str());
			dump_sigspec(f, sig_arst);
			f << stringf(" = '%c'", pol_arst ? '1' : '0');
			f << stringf(" then\n");
			f << stringf("%s" "    %s %s ", indent.c_str(),
				reg_name.c_str(), assignment_operator.c_str());
			dump_sigspec(f, val_arst);
			f << stringf(";\n");
			f << stringf("%s" "  elsif ", indent.c_str());
		} else {
			f << stringf("%s" "  if ", indent.c_str());
		}
		f << stringf("%s_edge(", pol_clk ? "rising" : "falling");
		dump_sigspec(f, sig_clk);
		f << stringf(") then\n");

		if (cell->type == ID($dffe)) {
			f << stringf("%s" "    if (", indent.c_str());
			dump_sigspec(f, sig_en);
			f << stringf(" = '%c'", pol_en ? '1' : '0');
			f << stringf(") then\n");
			f << stringf("%s" "      %s %s ", indent.c_str(),
				reg_name.c_str(), assignment_operator.c_str());
		} else {
			f << stringf("%s" "    %s %s ", indent.c_str(),
			reg_name.c_str(), assignment_operator.c_str());
		}

		dump_cell_expr_port(f, cell, "D", false);
		f << stringf(";\n");

		if (cell->type == ID($dffe)) {
			f << stringf("%s" "    end if;\n", indent.c_str());
		}
		f << stringf("%s" "  end if;\n", indent.c_str());

		if (!out_is_reg_wire) {
			f << stringf("%s", indent.c_str());
			dump_sigspec(f, cell->getPort(ID::Q));
			f << stringf(" <= %s;\n", reg_name.c_str());
		}
		f << stringf("%s" "end process;\n", indent.c_str());

		return true;
	}

	if (cell->type == ID($dlatch))
	{
		RTLIL::SigSpec sig_en;
		bool pol_en = false;

		sig_en = cell->getPort(ID::EN);
		pol_en = cell->parameters[ID::EN_POLARITY].as_bool();

		std::string reg_name = cellname(cell);
		bool out_is_reg_wire = is_reg_wire(cell->getPort(ID::Q), reg_name);

		std::string assignment_operator = out_is_reg_wire ? "<=" : ":=";

		f << stringf("%s" "process(", indent.c_str());
		dump_sigspec(f, sig_en);
		f << stringf(", ");
		// TODO: the following would break for nontrivial expressions
		dump_cell_expr_port(f, cell, "D", false);
		f << stringf(") is\n");

		if (!out_is_reg_wire) {
			f << stringf("%s" "variable %s: std_logic_vector (%d downto0)",
				indent.c_str(),
				reg_name.c_str(), cell->parameters[ID::WIDTH].as_int()-1);
			dump_reg_init(f, cell->getPort(ID::Q));
			f << ";\n";
		}

		f << stringf("%s" "begin\n", indent.c_str());

		f << stringf("%s" "  if (", indent.c_str());
		dump_sigspec(f, sig_en);
		f << stringf(" = '%c') then\n",  pol_en ? '1' : '0');

		f << stringf("%s" "    %s %s ", indent.c_str(),
			reg_name.c_str(), assignment_operator.c_str());
		dump_cell_expr_port(f, cell, "D", false);
		f << stringf(";\n");
		f << stringf("%s" "  end if;\n", indent.c_str());

		if (!out_is_reg_wire) {
			f << stringf("%s", indent.c_str());
			dump_sigspec(f, cell->getPort(ID::Q));
			f << stringf(" <= %s;\n", reg_name.c_str());
		}
		f << stringf("%s" "end process;\n", indent.c_str());

		return true;
	}

	if (cell->type == ID($mem))
	{ // unported for now
		RTLIL::IdString memid = cell->parameters[ID::MEMID].decode_string();
		std::string mem_id = id(cell->parameters[ID::MEMID].decode_string());
		int abits = cell->parameters[ID::ABITS].as_int();
		int size = cell->parameters[ID::SIZE].as_int();
		int offset = cell->parameters[ID::OFFSET].as_int();
		int width = cell->parameters[ID::WIDTH].as_int();
		bool use_init = !(RTLIL::SigSpec(cell->parameters[ID::INIT]).is_fully_undef());

		// for memory block make something like:
		//  reg [7:0] memid [3:0];
		//  initial begin
		//    memid[0] = ...
		//  end
		dump_attributes(f, indent.c_str(), cell->attributes);
		f << stringf("%s" "reg [%d:%d] %s [%d:%d];\n", indent.c_str(), width-1, 0, mem_id.c_str(), size+offset-1, offset);
		if (use_init)
		{
			if (extmem)
			{
				std::string extmem_filename = stringf("%s-%d.mem", extmem_prefix.c_str(), extmem_counter++);

				std::string extmem_filename_esc;
				for (auto c : extmem_filename)
				{
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
				f << stringf("%s" "initial $readmemb(\"%s\", %s);\n", indent.c_str(), extmem_filename_esc.c_str(), mem_id.c_str());

				std::ofstream extmem_f(extmem_filename, std::ofstream::trunc);
				if (extmem_f.fail())
					log_error("Can't open file `%s' for writing: %s\n", extmem_filename.c_str(), strerror(errno));
				else
				{
					for (int i=0; i<size; i++)
					{
						RTLIL::Const element = cell->parameters[ID::INIT].extract(i*width, width);
						for (int j=0; j<element.size(); j++)
						{
							switch (element[element.size()-j-1])
							{
								case State::S0: extmem_f << '0'; break;
								case State::S1: extmem_f << '1'; break;
								case State::Sx: extmem_f << 'x'; break;
								case State::Sz: extmem_f << 'z'; break;
								case State::Sa: extmem_f << '_'; break;
								case State::Sm: log_error("Found marker state in final netlist.");
							}
						}
						extmem_f << '\n';
					}
				}

			}
			else
			{
				f << stringf("%s" "initial begin\n", indent.c_str());
				for (int i=0; i<size; i++)
				{
					f << stringf("%s" "  %s[%d] = ", indent.c_str(), mem_id.c_str(), i);
					dump_const(f, cell->parameters[ID::INIT].extract(i*width, width));
					f << stringf(";\n");
				}
				f << stringf("%s" "end\n", indent.c_str());
			}
		}

		// create a map : "edge clk" -> expressions within that clock domain
		dict<std::string, std::vector<std::string>> clk_to_lof_body;
		clk_to_lof_body[""] = std::vector<std::string>();
		std::string clk_domain_str;
		// create a list of reg declarations
		std::vector<std::string> lof_reg_declarations;

		int nread_ports = cell->parameters[ID::RD_PORTS].as_int();
		RTLIL::SigSpec sig_rd_clk, sig_rd_en, sig_rd_data, sig_rd_addr;
		bool use_rd_clk, rd_clk_posedge, rd_transparent;
		// read ports
		for (int i=0; i < nread_ports; i++)
		{
			sig_rd_clk = cell->getPort(ID::RD_CLK).extract(i);
			sig_rd_en = cell->getPort(ID::RD_EN).extract(i);
			sig_rd_data = cell->getPort(ID::RD_DATA).extract(i*width, width);
			sig_rd_addr = cell->getPort(ID::RD_ADDR).extract(i*abits, abits);
			use_rd_clk = cell->parameters[ID::RD_CLK_ENABLE].extract(i).as_bool();
			rd_clk_posedge = cell->parameters[ID::RD_CLK_POLARITY].extract(i).as_bool();
			rd_transparent = cell->parameters[ID::RD_TRANSPARENT].extract(i).as_bool();
			if (use_rd_clk)
			{
				{
					std::ostringstream os;
					dump_sigspec(os, sig_rd_clk);
					clk_domain_str = stringf("%sedge %s", rd_clk_posedge ? "pos" : "neg", os.str().c_str());
					if( clk_to_lof_body.count(clk_domain_str) == 0 )
						clk_to_lof_body[clk_domain_str] = std::vector<std::string>();
				}
				if (!rd_transparent)
				{
					// for clocked read ports make something like:
					//   reg [..] temp_id;
					//   always @(posedge clk)
					//      if (rd_en) temp_id <= array_reg[r_addr];
					//   assign r_data = temp_id;
					std::string temp_id = next_auto_id();
					lof_reg_declarations.push_back( stringf("reg [%d:0] %s;\n", sig_rd_data.size() - 1, temp_id.c_str()) );
					{
						std::ostringstream os;
						if (sig_rd_en != RTLIL::SigBit(true))
						{
							os << stringf("if (");
							dump_sigspec(os, sig_rd_en);
							os << stringf(") ");
						}
						os << stringf("%s <= %s[", temp_id.c_str(), mem_id.c_str());
						dump_sigspec(os, sig_rd_addr);
						os << stringf("];\n");
						clk_to_lof_body[clk_domain_str].push_back(os.str());
					}
					{
						std::ostringstream os;
						dump_sigspec(os, sig_rd_data);
						std::string line = stringf("assign %s = %s;\n", os.str().c_str(), temp_id.c_str());
						clk_to_lof_body[""].push_back(line);
					}
				}
				else
				{
					// for rd-transparent read-ports make something like:
					//   reg [..] temp_id;
					//   always @(posedge clk)
					//     temp_id <= r_addr;
					//   assign r_data = array_reg[temp_id];
					std::string temp_id = next_auto_id();
					lof_reg_declarations.push_back( stringf("reg [%d:0] %s;\n", sig_rd_addr.size() - 1, temp_id.c_str()) );
					{
						std::ostringstream os;
						dump_sigspec(os, sig_rd_addr);
						std::string line = stringf("%s <= %s;\n", temp_id.c_str(), os.str().c_str());
						clk_to_lof_body[clk_domain_str].push_back(line);
					}
					{
						std::ostringstream os;
						dump_sigspec(os, sig_rd_data);
						std::string line = stringf("assign %s = %s[%s];\n", os.str().c_str(), mem_id.c_str(), temp_id.c_str());
						clk_to_lof_body[""].push_back(line);
					}
				}
			} else {
				// for non-clocked read-ports make something like:
				//   assign r_data = array_reg[r_addr];
				std::ostringstream os, os2;
				dump_sigspec(os, sig_rd_data);
				dump_sigspec(os2, sig_rd_addr);
				std::string line = stringf("assign %s = %s[%s];\n", os.str().c_str(), mem_id.c_str(), os2.str().c_str());
				clk_to_lof_body[""].push_back(line);
			}
		}

		int nwrite_ports = cell->parameters[ID::WR_PORTS].as_int();
		RTLIL::SigSpec sig_wr_clk, sig_wr_data, sig_wr_addr, sig_wr_en;
		bool wr_clk_posedge;

		// write ports
		for (int i=0; i < nwrite_ports; i++)
		{
			sig_wr_clk = cell->getPort(ID::WR_CLK).extract(i);
			sig_wr_data = cell->getPort(ID::WR_DATA).extract(i*width, width);
			sig_wr_addr = cell->getPort(ID::WR_ADDR).extract(i*abits, abits);
			sig_wr_en = cell->getPort(ID::WR_EN).extract(i*width, width);
			wr_clk_posedge = cell->parameters[ID::WR_CLK_POLARITY].extract(i).as_bool();
			{
				std::ostringstream os;
				dump_sigspec(os, sig_wr_clk);
				clk_domain_str = stringf("%sedge %s", wr_clk_posedge ? "pos" : "neg", os.str().c_str());
				if( clk_to_lof_body.count(clk_domain_str) == 0 )
					clk_to_lof_body[clk_domain_str] = std::vector<std::string>();
			}
			//   make something like:
			//   always @(posedge clk)
			//      if (wr_en_bit) memid[w_addr][??] <= w_data[??];
			//   ...
			for (int i = 0; i < GetSize(sig_wr_en); i++)
			{
				int start_i = i, width = 1;
				SigBit wen_bit = sig_wr_en[i];

				while (i+1 < GetSize(sig_wr_en) && active_sigmap(sig_wr_en[i+1]) == active_sigmap(wen_bit))
					i++, width++;

				if (wen_bit == State::S0)
					continue;

				std::ostringstream os;
				if (wen_bit != State::S1)
				{
					os << stringf("if (");
					dump_sigspec(os, wen_bit);
					os << stringf(") ");
				}
				os << stringf("%s[", mem_id.c_str());
				dump_sigspec(os, sig_wr_addr);
				if (width == GetSize(sig_wr_en))
					os << stringf("] <= ");
				else
					os << stringf("][%d:%d] <= ", i, start_i);
				dump_sigspec(os, sig_wr_data.extract(start_i, width));
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
		for(auto &reg : lof_reg_declarations)
		{
			f << stringf("%s" "%s", indent.c_str(), reg.c_str());
		}
		// the block of expressions by clock domain
		for(auto &pair : clk_to_lof_body)
		{
			std::string clk_domain = pair.first;
			std::vector<std::string> lof_lines = pair.second;
			if( clk_domain != "")
			{
				f << stringf("%s" "always @(%s) begin\n", indent.c_str(), clk_domain.c_str());
				for(auto &line : lof_lines)
					f << stringf("%s%s" "%s", indent.c_str(), indent.c_str(), line.c_str());
				f << stringf("%s" "end\n", indent.c_str());
			}
			else
			{
				// the non-clocked assignments
				for(auto &line : lof_lines)
					f << stringf("%s" "%s", indent.c_str(), line.c_str());
			}
		}

		return true;
	}

	if (cell->type.in(ID($assert), ID($assume), ID($cover)))
	{
		// TODO dump `assert` as a typical VHDL assert with severity, etc. ?
		log_warning("Cell of type %s will be dumped as a PSL comment\n",
			cell->type.c_str()+1);
		log_experimental("Formal cells as PSL comments");
		f << stringf("%s" "-- psl %s (", indent.c_str(), cell->type.c_str()+1);
		if (cell->type != ID($cover)) {
			f << stringf("always ");
		}
		dump_sigspec(f, cell->getPort(ID::EN));
		f << stringf(" -> ");
		dump_sigspec(f, cell->getPort(ID::A));
		f << stringf(");\n");
		return true;
	}

	if (cell->type.in(ID($specify2), ID($specify3), ID($specrule)))
	{
		/*
		 * TODO: There are a number of more graceful ways to handle this:
		 * - Dump this as a subcomponent
		 * - Leave a more informative comment behind in the generated VHDL
		 * - Use the information from the src attribute to augment the above
		 * Suggestions are welcome if you actually need $specify* cells dumped
		 */
		log_warning("%s cell %s detected\n", cell->type.c_str(), cell->name.c_str());
		log_warning("$specify* cells are not supported by the VHDL backend and will be ignored\n");
		f << stringf("-- Cell of type %s was not dumped\n", cell->type.c_str());
		// Return true regardless to avoid a subcomponent instantiation
		return true;
	}

	// FIXME: $_SR_[PN][PN]_, $_DLATCH_[PN]_, $_DLATCHSR_[PN][PN][PN]_
	// FIXME: $sr, $dlatch, $memrd, $memwr, $fsm

	return false;
}

void dump_cell(std::ostream &f, std::string indent, RTLIL::Cell *cell)
{ // PORTING REQUIRED
	if (cell->type[0] == '$' && !noexpr) {
		if (dump_cell_expr(f, indent, cell))
			return;
	}

	dump_attributes(f, indent, cell->attributes);
	f << stringf("%s" "%s", indent.c_str(), id(cell->type, false).c_str());

	if (!defparam && cell->parameters.size() > 0) {
		f << stringf(" #(");
		for (auto it = cell->parameters.begin(); it != cell->parameters.end(); ++it) {
			if (it != cell->parameters.begin())
				f << stringf(",");
			f << stringf("\n%s  .%s(", indent.c_str(), id(it->first).c_str());
			dump_const(f, it->second);
			f << stringf(")");
		}
		f << stringf("\n%s" ")", indent.c_str());
	}

	std::string cell_name = cellname(cell);
	if (cell_name != id(cell->name))
		f << stringf(" %s /* %s */ (", cell_name.c_str(), id(cell->name).c_str());
	else
		f << stringf(" %s (", cell_name.c_str());

	bool first_arg = true;
	std::set<RTLIL::IdString> numbered_ports;
	for (int i = 1; true; i++) {
		char str[16];
		snprintf(str, 16, "$%d", i);
		for (auto it = cell->connections().begin(); it != cell->connections().end(); ++it) {
			if (it->first != str)
				continue;
			if (!first_arg)
				f << stringf(",");
			first_arg = false;
			f << stringf("\n%s  ", indent.c_str());
			dump_sigspec(f, it->second);
			numbered_ports.insert(it->first);
			goto found_numbered_port;
		}
		break;
	found_numbered_port:;
	}
	for (auto it = cell->connections().begin(); it != cell->connections().end(); ++it) {
		if (numbered_ports.count(it->first))
			continue;
		if (!first_arg)
			f << stringf(",");
		first_arg = false;
		f << stringf("\n%s  .%s(", indent.c_str(), id(it->first).c_str());
		if (it->second.size() > 0)
			dump_sigspec(f, it->second);
		f << stringf(")");
	}
	f << stringf("\n%s" ");\n", indent.c_str());

	if (defparam && cell->parameters.size() > 0) {
		for (auto it = cell->parameters.begin(); it != cell->parameters.end(); ++it) {
			f << stringf("%sdefparam %s.%s = ", indent.c_str(), cell_name.c_str(), id(it->first).c_str());
			dump_const(f, it->second);
			f << stringf(";\n");
		}
	}

	if (siminit && reg_ct.count(cell->type) && cell->hasPort(ID::Q)) {
		std::stringstream ss;
		dump_reg_init(ss, cell->getPort(ID::Q));
		if (!ss.str().empty()) {
			f << stringf("%sinitial %s.Q", indent.c_str(), cell_name.c_str());
			f << ss.str();
			f << ";\n";
		}
	}
}

void dump_conn(std::ostream &f, std::string indent, const RTLIL::SigSpec &left, const RTLIL::SigSpec &right)
{ // PORTING NEEDS TESTING
	f << stringf("%s", indent.c_str());
	dump_sigspec(f, left);
	f << stringf(" <= ");
	dump_sigspec(f, right);
	f << stringf(";\n");
}

// This is a forward declaration
void dump_proc_switch(std::ostream &f, std::string indent, RTLIL::SwitchRule *sw);

void dump_case_body(std::ostream &f, std::string indent, RTLIL::CaseRule *cs, bool omit_trailing_begin = false)
{ // PORTING REQUIRED
	int number_of_stmts = cs->switches.size() + cs->actions.size();

	if (!omit_trailing_begin && number_of_stmts >= 2)
		f << stringf("%s" "begin\n", indent.c_str());

	for (auto it = cs->actions.begin(); it != cs->actions.end(); ++it) {
		if (it->first.size() == 0)
			continue;
		f << stringf("%s  ", indent.c_str());
		dump_sigspec(f, it->first);
		f << stringf(" = ");
		dump_sigspec(f, it->second);
		f << stringf(";\n");
	}

	for (auto it = cs->switches.begin(); it != cs->switches.end(); ++it)
		dump_proc_switch(f, indent + "  ", *it);

	if (!omit_trailing_begin && number_of_stmts == 0)
		f << stringf("%s  /* empty */;\n", indent.c_str());

	if (omit_trailing_begin || number_of_stmts >= 2)
		f << stringf("%s" "end\n", indent.c_str());
}

void dump_proc_switch(std::ostream &f, std::string indent, RTLIL::SwitchRule *sw)
{ // PORTING REQUIRED
	if (sw->signal.size() == 0) {
		f << stringf("%s" "begin\n", indent.c_str());
		for (auto it = sw->cases.begin(); it != sw->cases.end(); ++it) {
			if ((*it)->compare.size() == 0)
				dump_case_body(f, indent + "  ", *it);
		}
		f << stringf("%s" "end\n", indent.c_str());
		return;
	}

	dump_attributes(f, indent, sw->attributes);
	f << stringf("%s" "casez (", indent.c_str());
	dump_sigspec(f, sw->signal);
	f << stringf(")\n");

	bool got_default = false;
	for (auto it = sw->cases.begin(); it != sw->cases.end(); ++it) {
		dump_attributes(f, indent + "  ", (*it)->attributes, /*modattr=*/false, /*regattr=*/false, /*as_comment=*/true);
		if ((*it)->compare.size() == 0) {
			if (got_default)
				continue;
			f << stringf("%s  default", indent.c_str());
			got_default = true;
		} else {
			f << stringf("%s  ", indent.c_str());
			for (size_t i = 0; i < (*it)->compare.size(); i++) {
				if (i > 0)
					f << stringf(", ");
				dump_sigspec(f, (*it)->compare[i]);
			}
		}
		f << stringf(":\n");
		dump_case_body(f, indent + "    ", *it);
	}

	f << stringf("%s" "endcase\n", indent.c_str());
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

void dump_process(std::ostream &f, std::string indent, RTLIL::Process *proc, bool find_regs = false)
{ // PORTING REQUIRED
	if (find_regs) {
		case_body_find_regs(&proc->root_case);
		for (auto it = proc->syncs.begin(); it != proc->syncs.end(); ++it)
		for (auto it2 = (*it)->actions.begin(); it2 != (*it)->actions.end(); it2++) {
			for (auto &c : it2->first.chunks())
				if (c.wire != NULL)
					reg_wires.insert(c.wire->name);
		}
		return;
	}

	f << stringf("%s" "always @* begin\n", indent.c_str());
	dump_case_body(f, indent, &proc->root_case, true);

	std::string backup_indent = indent;

	for (size_t i = 0; i < proc->syncs.size(); i++)
	{
		RTLIL::SyncRule *sync = proc->syncs[i];
		indent = backup_indent;

		if (sync->type == RTLIL::STa) {
			f << stringf("%s" "always @* begin\n", indent.c_str());
		} else if (sync->type == RTLIL::STi) {
			f << stringf("%s" "initial begin\n", indent.c_str());
		} else {
			f << stringf("%s" "always @(", indent.c_str());
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
			f << stringf("%s" "if (%s", indent.c_str(), sync->type == RTLIL::ST0 ? "!" : "");
			dump_sigspec(f, sync->signal);
			f << stringf(") begin\n");
			ends = indent + "end\n" + ends;
			indent += "  ";
		}

		if (sync->type == RTLIL::STp || sync->type == RTLIL::STn) {
			for (size_t j = 0; j < proc->syncs.size(); j++) {
				RTLIL::SyncRule *sync2 = proc->syncs[j];
				if (sync2->type == RTLIL::ST0 || sync2->type == RTLIL::ST1) {
					f << stringf("%s" "if (%s", indent.c_str(), sync2->type == RTLIL::ST1 ? "!" : "");
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
			f << stringf(";\n");
		}

		f << stringf("%s", ends.c_str());
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
				"processes to logic networks and registers.\n", log_id(module));

	f << stringf("\n");
	for (auto it = module->processes.begin(); it != module->processes.end(); ++it)
		// This just updates internal data structures
		dump_process(f, indent + "  ", it->second, true);

	if (!noexpr)
	{
		std::set<std::pair<RTLIL::Wire*,int>> reg_bits;
		for (auto cell : module->cells())
		{
			if (!reg_ct.count(cell->type) || !cell->hasPort(ID::Q))
				continue;

			RTLIL::SigSpec sig = cell->getPort(ID::Q);

			if (sig.is_chunk()) {
				RTLIL::SigChunk chunk = sig.as_chunk();
				if (chunk.wire != NULL)
					for (int i = 0; i < chunk.width; i++)
						reg_bits.insert(std::pair<RTLIL::Wire*,int>(chunk.wire, chunk.offset+i));
			}
		}
		for (auto wire : module->wires())
		{
			for (int i = 0; i < wire->width; i++)
				if (reg_bits.count(std::pair<RTLIL::Wire*,int>(wire, i)) == 0)
					goto this_wire_aint_reg;
			if (wire->width)
				reg_wires.insert(wire->name);
		this_wire_aint_reg:;
		}
	}

	// Entity declaration
	// Find ports first before dumping them
	std::map<int, Wire*> port_wires;
	// TODO: validate assumption that port_id is port iff it is positive
	for (auto wire : module->wires()) {
		if (wire->port_id > 0) {
			port_wires.insert({wire->port_id, wire});
		}
	}
	dump_attributes(f, indent, module->attributes, /*modattr=*/true);
	f << stringf("%s" "entity %s is\n", indent.c_str(),
		id(module->name, false).c_str());
	f << stringf("%s" "  port (\n", indent.c_str());
	for (auto wire_it = port_wires.cbegin();
			wire_it != port_wires.cend(); wire_it++) {
		Wire* wire = wire_it->second;
		f << stringf("%s" "    %s :",
			indent.c_str(), id(wire->name).c_str());
		// TODO: Verilog inout = VHDL inout?
		if (wire->port_input && wire->port_output) {
			f << stringf(" inout ");
		} else if (wire->port_input && !wire->port_output) {
			f << stringf(" in ");
		} else if (!wire->port_input && wire->port_output) {
			f << stringf(" out ");
		} else {
			log_error("Port %s is neither an input nor an output\n",
				id(wire->name).c_str());
		}
		if (wire->width > 1) {
			// TODO: verify arithmetic
			if (wire->upto) {
				f << stringf("std_logic_vector (%d to %d)",
					wire->start_offset, wire->start_offset+wire->width-1);
			} else {
				f << stringf("std_logic_vector (%d downto %d)",
					wire->start_offset+wire->width-1, wire->start_offset);
			}
		} else {
			f << stringf("std_logic");
		}
		auto wire_it_next = std::next(wire_it);
		if (wire_it_next != port_wires.cend()) {
			f << stringf(";");
		} else {
			f << stringf(");");
		}
		f << stringf("\n");
	}
	//f << stringf("%s" "  );\n", indent.c_str());
	f << stringf("%s" "end %s;\n",
		indent.c_str(), id(module->name, false).c_str());

	// Architecture
	f << stringf("%s" "architecture rtl of %s is\n", indent.c_str(),
		id(module->name, false).c_str());
	for (auto w : module->wires())
		dump_wire(f, indent + "  ", w);

	for (auto it = module->memories.begin(); it != module->memories.end(); ++it)
		dump_memory(f, indent + "  ", it->second);
	f << stringf("%s" "begin\n", indent.c_str());
	for (auto cell : module->cells())
		dump_cell(f, indent + "  ", cell);

	for (auto it = module->processes.begin(); it != module->processes.end(); ++it)
		dump_process(f, indent + "  ", it->second);

	for (auto it = module->connections().begin(); it != module->connections().end(); ++it)
		dump_conn(f, indent + "  ", it->first, it->second);

	f << stringf("%s" "end rtl;\n", indent.c_str());
	active_module = NULL;
	active_sigmap.clear();
	active_initdata.clear();
}

void write_header_imports(std::ostream &f, std::string indent)
{
	f << indent << "library IEEE;\n";
	f << indent << "use IEEE.STD_LOGIC_1164.ALL;\n";
	f << indent << "use IEEE.NUMERIC_STD.ALL;\n";
	if (extmem) {
		f << indent << "\nuse STD.TEXTIO.ALL\n";
	}
}

struct VHDLBackend : public Backend {
	VHDLBackend() : Backend("vhdl", "write design to VHDL file") { }
	void help() YS_OVERRIDE
	{
		//   |---v---|---v---|---v---|---v---|---v---|---v---|---v---|---v---|---v---|---v---|
		log("\n");
		log("    write_vhdl [options] [filename]\n");
		log("\n");
		log("Write the current design to a VHDL file (WIP).\n");
		log("\n");
		log("    -norename\n");
		log("        without this option all internal object names (the ones with a dollar\n");
		log("        instead of a backslash prefix) are changed to short names in the\n");
		log("        format '_<number>_'.\n");
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
		log("    -extmem\n");
		log("        instead of initializing memories using assignments to individual\n");
		log("        elements, use the '$readmemh' function to read initialization data\n");
		log("        from a file. This data is written to a file named by appending\n");
		log("        a sequential index to the Verilog filename and replacing the extension\n");
		log("        with '.mem', e.g. 'write_verilog -extmem foo.v' writes 'foo-1.mem',\n");
		log("        'foo-2.mem' and so on.\n");
		log("\n");
		log("    -defparam\n");
		log("        use 'defparam' statements instead of the Verilog-2001 syntax for\n");
		log("        cell parameters.\n");
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
	void execute(std::ostream *&f, std::string filename, std::vector<std::string> args, RTLIL::Design *design) YS_OVERRIDE
	{ // PORTING TOP COMPLETE, SUBROUTINES IN PROGRESS
		log_header(design, "Executing VHDL backend.\n");

		verbose = false;
		norename = false;
		noattr = false;
		attr2comment = false;
		noexpr = false;
		nodec = false;
		nohex = false;
		nostr = false;
		extmem = false;
		defparam = false;
		siminit = false;
		auto_prefix = "n";

		bool blackboxes = false;
		bool selected = false;

		auto_name_map.clear();
		reg_wires.clear();
		reg_ct.clear();

		reg_ct.insert(ID($dff));
		reg_ct.insert(ID($adff));
		reg_ct.insert(ID($dffe));
		reg_ct.insert(ID($dlatch));

		reg_ct.insert(ID($_DFF_N_));
		reg_ct.insert(ID($_DFF_P_));

		reg_ct.insert(ID($_DFF_NN0_));
		reg_ct.insert(ID($_DFF_NN1_));
		reg_ct.insert(ID($_DFF_NP0_));
		reg_ct.insert(ID($_DFF_NP1_));
		reg_ct.insert(ID($_DFF_PN0_));
		reg_ct.insert(ID($_DFF_PN1_));
		reg_ct.insert(ID($_DFF_PP0_));
		reg_ct.insert(ID($_DFF_PP1_));

		reg_ct.insert(ID($_DFFSR_NNN_));
		reg_ct.insert(ID($_DFFSR_NNP_));
		reg_ct.insert(ID($_DFFSR_NPN_));
		reg_ct.insert(ID($_DFFSR_NPP_));
		reg_ct.insert(ID($_DFFSR_PNN_));
		reg_ct.insert(ID($_DFFSR_PNP_));
		reg_ct.insert(ID($_DFFSR_PPN_));
		reg_ct.insert(ID($_DFFSR_PPP_));

		size_t argidx;
		for (argidx = 1; argidx < args.size(); argidx++) {
			std::string arg = args[argidx];
			if (arg == "-norename") {
				norename = true;
				continue;
			}
			if (arg == "-renameprefix" && argidx+1 < args.size()) {
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
			if (arg == "-defparam") {
				defparam = true;
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
			if (arg == "-v") {
				verbose = true;
				continue;
			}
			break;
		}
		extra_args(f, filename, args, argidx);
		if (extmem)
		{
			if (filename == "<stdout>")
				log_cmd_error("Option -extmem must be used with a filename.\n");
			extmem_prefix = filename.substr(0, filename.rfind('.'));
		}
		if (auto_prefix.length() == 0) {
			log_cmd_error("Prefix specified by -renameprefix must not be empty.\n");
		}

		design->sort();

		*f << stringf("-- Generated by %s\n", yosys_version_str);
		log_experimental("VHDL backend");
		write_header_imports(*f, "");
		for (auto module : design->modules()) {
			if (module->get_blackbox_attribute() != blackboxes)
				continue;
			if (selected && !design->selected_whole_module(module->name)) {
				if (design->selected_module(module->name))
					log_cmd_error("Can't handle partially selected module %s!\n", log_id(module->name));
				continue;
			}
			log("Dumping module `%s'.\n", module->name.c_str());
			dump_module(*f, "", module);
		}

		auto_name_map.clear();
		reg_wires.clear();
		reg_ct.clear();
	}
} VerilogBackend;

PRIVATE_NAMESPACE_END