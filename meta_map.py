import json
import struct
import sys


TAG_END = 0
TAG_BYTE = 1
TAG_SHORT = 2
TAG_INT = 3
TAG_LONG = 4
TAG_FLOAT = 5
TAG_DOUBLE = 6
TAG_BYTE_ARRAY = 7
TAG_STRING = 8
TAG_LIST = 9
TAG_COMPOUND = 10
TAG_INT_ARRAY = 11


class NbtError(Exception):
	pass


def read_bytes(
	data: bytes,
	pos: int,
	length: int
) -> tuple[bytes, int]:

	end = pos + length

	if end > len(data):
		raise NbtError(
			f"Unexpected end of data: need {length} bytes, "
			f"have {len(data) - pos}"
		)

	return data[pos:end], end


def read_unsigned_byte(
	data: bytes,
	pos: int
) -> tuple[int, int]:

	raw, pos = read_bytes(data, pos, 1)

	return raw[0], pos


def read_byte(
	data: bytes,
	pos: int
) -> tuple[int, int]:

	raw, pos = read_bytes(data, pos, 1)

	return struct.unpack(">b", raw)[0], pos


def read_varint(
	data: bytes,
	pos: int
) -> tuple[int, int]:

	result = 0
	shift = 0

	while True:
		if pos >= len(data):
			raise NbtError(
				"Unexpected end of data while reading VarInt"
			)

		byte = data[pos]
		pos += 1

		result |= (byte & 0x7f) << shift

		if (byte & 0x80) == 0:
			return result, pos

		shift += 7

		if shift >= 35:
			raise NbtError(
				"VarInt is too long"
			)


def read_signed_varint(
	data: bytes,
	pos: int
) -> tuple[int, int]:

	value, pos = read_varint(data, pos)

	# Convert 32-bit two's-complement value.
	if value & 0x80000000:
		value -= 0x100000000

	return value, pos


def read_varlong(
	data: bytes,
	pos: int
) -> tuple[int, int]:

	result = 0
	shift = 0

	while True:
		if pos >= len(data):
			raise NbtError(
				"Unexpected end of data while reading VarLong"
			)

		byte = data[pos]
		pos += 1

		result |= (byte & 0x7f) << shift

		if (byte & 0x80) == 0:
			if result & (1 << 63):
				result -= 1 << 64

			return result, pos

		shift += 7

		if shift >= 70:
			raise NbtError(
				"VarLong is too long"
			)


def read_float(
	data: bytes,
	pos: int
) -> tuple[float, int]:

	raw, pos = read_bytes(data, pos, 4)

	return struct.unpack("<f", raw)[0], pos


def read_double(
	data: bytes,
	pos: int
) -> tuple[float, int]:

	raw, pos = read_bytes(data, pos, 8)

	return struct.unpack("<d", raw)[0], pos


def read_name(
	data: bytes,
	pos: int
) -> tuple[str, int]:

	length, pos = read_unsigned_byte(data, pos)

	raw, pos = read_bytes(
		data,
		pos,
		length
	)

	try:
		return raw.decode("utf-8"), pos
	except UnicodeDecodeError as e:
		raise NbtError(
			f"Invalid UTF-8 tag name at offset "
			f"{pos - length}"
		) from e


def read_string(
	data: bytes,
	pos: int
) -> tuple[str, int]:

	length, pos = read_varint(data, pos)

	raw, pos = read_bytes(
		data,
		pos,
		length
	)

	try:
		return raw.decode("utf-8"), pos
	except UnicodeDecodeError as e:
		raise NbtError(
			f"Invalid UTF-8 string at offset "
			f"{pos - length}"
		) from e


def read_byte_array(
	data: bytes,
	pos: int
) -> tuple[bytes, int]:

	length, pos = read_signed_varint(
		data,
		pos
	)

	if length < 0:
		raise NbtError(
			f"Negative TAG_Byte_Array length: {length}"
		)

	return read_bytes(
		data,
		pos,
		length
	)


def read_int_array(
	data: bytes,
	pos: int
) -> tuple[list[int], int]:

	length, pos = read_signed_varint(
		data,
		pos
	)

	if length < 0:
		raise NbtError(
			f"Negative TAG_Int_Array length: {length}"
		)

	result = []

	for _ in range(length):
		value, pos = read_signed_varint(
			data,
			pos
		)

		result.append(value)

	return result, pos


def read_list(
	data: bytes,
	pos: int,
	depth: int
) -> tuple[list, int]:

	element_type, pos = read_unsigned_byte(
		data,
		pos
	)

	length, pos = read_signed_varint(
		data,
		pos
	)

	if length < 0:
		raise NbtError(
			f"Negative TAG_List length: {length}"
		)

	if (
		element_type == TAG_END
		and length > 0
	):
		raise NbtError(
			"TAG_List cannot contain "
			"TAG_End elements"
		)

	result = []

	for _ in range(length):
		value, pos = read_payload(
			data,
			pos,
			element_type,
			depth + 1
		)

		result.append(value)

	return result, pos


def read_compound(
	data: bytes,
	pos: int,
	depth: int
) -> tuple[dict, int]:

	result = {}

	while True:
		tag_type, pos = read_unsigned_byte(
			data,
			pos
		)

		if tag_type == TAG_END:
			return result, pos

		name, pos = read_name(
			data,
			pos
		)

		value, pos = read_payload(
			data,
			pos,
			tag_type,
			depth + 1
		)

		result[name] = value


def read_payload(
	data: bytes,
	pos: int,
	tag_type: int,
	depth: int = 0
):
	if depth > 512:
		raise NbtError(
			"NBT nesting depth exceeded"
		)

	if tag_type == TAG_BYTE:
		return read_byte(data, pos)

	if tag_type == TAG_SHORT:
		return read_signed_varint(data, pos)

	if tag_type == TAG_INT:
		return read_signed_varint(data, pos)

	if tag_type == TAG_LONG:
		return read_varlong(data, pos)

	if tag_type == TAG_FLOAT:
		return read_float(data, pos)

	if tag_type == TAG_DOUBLE:
		return read_double(data, pos)

	if tag_type == TAG_BYTE_ARRAY:
		return read_byte_array(data, pos)

	if tag_type == TAG_STRING:
		return read_string(data, pos)

	if tag_type == TAG_LIST:
		return read_list(
			data,
			pos,
			depth
		)

	if tag_type == TAG_COMPOUND:
		return read_compound(
			data,
			pos,
			depth
		)

	if tag_type == TAG_INT_ARRAY:
		return read_int_array(
			data,
			pos
		)

	raise NbtError(
		f"Unknown NBT tag type {tag_type} "
		f"at offset {pos}"
	)


def read_root(
	data: bytes,
	pos: int
) -> tuple[str, dict, int]:

	tag_type, pos = read_unsigned_byte(
		data,
		pos
	)

	if tag_type == TAG_END:
		raise NbtError(
			f"Found TAG_End at root at offset "
			f"{pos - 1}"
		)

	root_name, pos = read_name(
		data,
		pos
	)

	value, pos = read_payload(
		data,
		pos,
		tag_type,
		0
	)

	return root_name, value, pos


def load_nbt_file(
	filename: str
) -> list[dict]:

	with open(filename, "rb") as f:
		data = f.read()

	roots = []
	pos = 0

	while pos < len(data):
		root_name, root, new_pos = read_root(
			data,
			pos
		)

		if new_pos <= pos:
			raise NbtError(
				f"Parser made no progress at "
				f"offset {pos}"
			)

		roots.append(root)
		pos = new_pos

		# canonical_block_states.nbt has an
		# additional zero byte between roots.
		if pos < len(data) and data[pos] == TAG_END:
			pos += 1

	return roots


def load_canonical_block_states(
	filename: str
) -> list[dict]:

	roots = load_nbt_file(filename)

	states = []

	for root in roots:

		if "name" not in root:
			raise NbtError(
				'Block state is missing "name"'
			)

		if "states" not in root:
			root["states"] = {}

		states.append(root)

	return states


def make_meta_map(states: list[dict]) -> list[int]:
    counters: dict[str, int] = {}
    result: list[int] = []

    for state in states:
        name = state["name"]

        index = counters.get(name, 0)
        result.append(index)

        counters[name] = index + 1

    return result


def main() -> None:

	filename = (
		sys.argv[1]
		if len(sys.argv) > 1
		else "canonical_block_states.nbt"
	)

	states = load_canonical_block_states(
		filename
	)

	print(
		f"Total states: {len(states)}"
	)

	for index, state in enumerate(states):

		name = state.get(
			"name",
			"<unknown>"
		)

		properties = state.get(
			"states",
			{}
		)

		print(
			f"[{index}] {name}"
		)

		if "version" in state:
			print(
				f"    version = "
				f"{state['version']}"
			)

		for key, value in properties.items():
			print(
				f"    {key} = {value}"
			)

	meta_map = make_meta_map(states)

	with open(
		"block_state_meta_map.generated.json",
		"w",
		encoding="utf-8"
	) as f:
		json.dump(
			meta_map,
			f,
			ensure_ascii=False,
			indent=4
		)

	print()
	print(
		"Generated:",
		"block_state_meta_map.generated.json"
	)


if __name__ == "__main__":
	main()