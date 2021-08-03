#include "AbiDecoder.h"
#include <boost/algorithm/hex.hpp>
#include <boost/algorithm/string/join.hpp>
#include <numeric>
#include <iostream>
#include "Keccak.h"

using namespace nlohmann;

static void decodeParameters(const json& paramDefs, size_t& offset, const std::string& data, json& result);
static std::string encodeParameters(const json& paramDefs, const json& values);

static std::string to_hexstring(const std::vector<uint8_t>& bytes)
{
	std::string s;
	boost::algorithm::hex_lower(bytes.begin(), bytes.end(), std::back_inserter(s));
	return s;
}

template<typename T> std::string to_hexstring(T value)
{
	std::ostringstream s;
	s << std::hex << value;
	return s.str();
}

static std::string& pad_hexstring(std::string& s, size_t width)
{
	auto len = s.length();
	if (width > len) {
		auto padLen = width - len;
		s.insert(0, padLen, '0');
	}
	return s;
}

static std::string& strip_front_zeroes(std::string& s)
{
	auto pos = s.find_first_not_of('0');
	if (pos == std::string::npos)
		s = "0";
	else
		s.erase(0, (pos >> 1) << 1);
	return s;
}

static std::string& remove_hexspec(std::string& s)
{
	if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X'))
		s.erase(0, 2);
	return s;
}

static std::string type_string(const json& input);

static std::string type_array_string(const json& list) {
	std::vector<std::string> types;
	std::transform(list.begin(), list.end(), std::back_inserter(types),
		[](const json& e) { return type_string(e); });

	return "(" + boost::algorithm::join(types, ",") + ")";
}

static std::string type_string(const json &input) {
	auto type = input["type"].get<std::string>();
	if (type == "tuple") {
		return type_array_string(input["components"]);
	}
	return type;
}

static std::string sha3(const std::string& message)
{
	Keccak keccak(256);
	keccak.update(message.c_str(), message.length());
	auto hash = keccak.finalize();
	return to_hexstring(hash);
}

void AbiDecoder::addABI(const json& abiArray)
{
	if (!abiArray.is_array())
		return;

	for (auto& abi : abiArray) {
		auto name_it = abi.find("name");
		if (name_it != abi.end()) {
			auto inputs = abi["inputs"];
			auto method = name_it.value().get<std::string>() +
				type_array_string(abi["inputs"]);
			auto signature = sha3(method);

			if (abi["type"].get<std::string>() == "event") {
				methodIDs[signature] = abi;
			}
			else {
				methodIDs[signature.substr(0, 8)] = abi;
			}
		}
	}
}

json AbiDecoder::decodeMethod(const std::string& data) const
{
	auto methodID = data.substr(2, 8);
	auto abiItemIt = methodIDs.find(methodID);
	if (abiItemIt == methodIDs.end())
		return json{};

	auto &abiItem = abiItemIt->second;

	//std::cout << abiItem << std::endl;

	auto methodName = abiItem["name"].get<std::string>();

	auto paramsData = data.substr(10);
	json params;
	size_t offset = 0;
	decodeParameters(abiItem["inputs"], offset, paramsData, params);

	return json{
		{ "name", abiItem["name"].get<std::string>() },
		{ "params", params },
	};
}

std::string AbiDecoder::encodeMethod(const std::string& method, const nlohmann::json& values) const
{
	std::string data;
	json methodAbi{};
	for (auto& methodID : methodIDs) {
		auto abi = methodID.second;
		if (abi["name"].get<std::string>() == method) {
			methodAbi = abi;
			data = methodID.first;
		}
	}

	if (data.empty())
		return data;

	data.insert(0, "0x");
	data.append(encodeParameters(methodAbi["inputs"], values));
	return data;
}

static std::string elementaryName(const std::string& name)
{
	if (name == "int") {
		return "int256";
	}
	if (name.substr(0, 4) == "int[") {
		return "int256" + name.substr(3);
	}
	if (name == "uint") {
		return "uint256";
	}
	if (name.substr(0, 5) == "uint[") {
		return "uint256" + name.substr(4);
	}
	if (name == "fixed") {
		return "fixed128x128";
	}
	if (name.substr(0, 6) == "fixed[") {
		return "fixed" + name.substr(5);
	}
	if (name == "ufixed") {
		return "ufixed128x128";
	}
	if (name.substr(0, 7) == "ufixed[") {
		return "ufixed" + name.substr(6);
	}
	return name;
}

static bool isArray(const std::string& name)
{
	auto len = name.length();
	return len > 0 && name[len - 1] == ']';
}

// Parse N in type[<N>] where "type" can itself be an array type.
static bool parseTypeArray(const std::string& name, std::string &subArray, size_t &size)
{
	auto start = name.find_last_of('[');
	auto end = name.find_last_of(']');
	if (start != std::string::npos && end != std::string::npos
		&& start < end)
	{
		subArray = name.substr(0, start);
		auto size_str = name.substr(start + 1, end - start - 1);
		size = size_str.empty() ? 0 : std::stoi(size_str);
		return true;
	}
	return false;
}

static const char DIGITS[] = "0123456789";

// Parse N from type<N>
static size_t parseTypeN(const std::string& name)
{
	auto start = name.find_first_of(DIGITS, 0);
	return std::stoi(name.substr(start));
}

// Parse N,M from type<N>x<M>
static void parseTypeNxM(const std::string& name, size_t &N, size_t &M)
{
	auto start1 = name.find_first_of(DIGITS, 0);
	auto start2 = name.find_first_of('x', start1);

	N = std::stoi(name.substr(start1, start2 - start1));
	M = std::stoi(name.substr(start2 + 1));
}

static json decodeSingle(const std::string& type, const std::string& data, size_t &offset)
{
	if (isArray(type)) {
		json ret;

		size_t arraySize = 0;
		std::string subArray;
		parseTypeArray(type, subArray, arraySize);

		auto data_offset = offset;
		auto data_size = arraySize;
		if (arraySize == 0) { // dynamic
			data_offset = std::stoul(decodeSingle("uint256", data, data_offset).get<std::string>(), nullptr, 16);
			data_size = std::stoul(decodeSingle("uint256", data, data_offset).get<std::string>(), nullptr, 16);
		}
		for (size_t i = 0; i < data_size; ++i) {
			auto e = decodeSingle(subArray, data, data_offset);
			ret.push_back(e);
		}

		if (arraySize == 0) {
			offset += 32;
		}
		else {
			offset = data_offset;
		}

		return ret;
	}
	else {
		static const std::unordered_map<std::string, std::string> rawTypeMap{
			{ "address", "uint160" },
			{ "bool", "uint8" },
			{ "string", "bytes" },
		};

		const auto rawTypeIt = rawTypeMap.find(type);
		if (rawTypeIt != rawTypeMap.end())
			return decodeSingle(rawTypeIt->second, data, offset);

		if (type == "bytes") {
			size_t data_offset = std::stoul(decodeSingle("uint256", data, offset).get<std::string>(), nullptr, 16);
			size_t size = std::stoul(decodeSingle("uint256", data, data_offset).get<std::string>(), nullptr, 16);
			auto ret = data.substr(data_offset * 2, size * 2);
			offset += 32;
			return ret;
		}
		else if (type.substr(0, 5) == "bytes"
			|| type.substr(0, 4) == "uint"
			|| type.substr(0, 3) == "int") {
			//auto size = parseTypeN(type);
			size_t size = 32;
			auto ret_str = data.substr(offset * 2, size * 2);
			offset += size;
			if (type.substr(0, 5) != "bytes")
				strip_front_zeroes(ret_str);
			ret_str.insert(0, "0x");
			return ret_str;
		}
		else if (type.substr(0, 6) == "ufixed"
			|| type.substr(0, 5) == "fixed") {
			//size_t size, sizeM;
			//parseTypeNxM(type, size, sizeM);
			size_t size = 32;
			// TODO
			auto ret = data.substr(offset * 2, size * 2);
			strip_front_zeroes(ret);
			offset += size;
			ret.insert(0, "0x");
			return ret;
		}
	}
	return json{};
}

static void decodeParameters(const json& paramDefs, size_t &offset, const std::string& data, json &result)
{
	for (auto& paramDef : paramDefs) {
		auto name = paramDef["name"].get<std::string>();
		auto type = elementaryName(paramDef["type"].get<std::string>());

		result[name] = decodeSingle(type, data, offset);
	}
}

static bool isDynamic(const std::string type)
{
	std::string subArray;
	size_t size;

	return type == "string"
		|| type == "bytes"
		|| parseTypeArray(type, subArray, size);
}

static size_t encodeSingle(const std::string& type, const json& value, std::string& data)
{
	if (type == "address") {
		return encodeSingle("uint160", value, data);
	}
	else if (type == "bool") {
		return encodeSingle("uint8", value, data);
	}
	else if (type == "string") {
		return encodeSingle("bytes", value, data);
	}
	else if (isArray(type)) {
		std::string subArray;
		size_t size;

		parseTypeArray(type, subArray, size);

		if (value.is_array() && size <= value.size()) {
			size_t dataSize = 0;
			std::string data2;
			for (auto& e : value) {
				dataSize += encodeSingle(subArray, e, data2);
			}

			if (size == 0) { // dynamic
				dataSize += encodeSingle("uint256", to_hexstring(value.size()), data);
			}

			data.append(data2);
			return dataSize;
		}
		else {
			return 0;
		}
	}
	else if (type == "bytes") {
		auto bytes = value.get<std::string>();
		auto len = (bytes.length() + 1) >> 1;
		remove_hexspec(bytes);
		pad_hexstring(bytes, len << 1);

		encodeSingle("uint256", to_hexstring(len), data);
		data.append(bytes);
		if ((len % 32) != 0) {
			data.append(32 - (len % 32), '0');
		}
		return 32 + len + 32 - (len % 32);
	}
	else if (type.substr(0, 5) == "bytes") {
		auto size = parseTypeN(type);
		if (size > 0 && size <= 32) {
			auto bytes = value.get<std::string>();
			auto len = (bytes.length() + 1) >> 1;
			remove_hexspec(bytes);
			pad_hexstring(bytes, len << 1);
			data.append(bytes);
			if (len < 32) {
				data.append(32 - len, '0');
			}
		}
		return 32;
	}
	else if (type.substr(0, 4) == "uint"
		|| type.substr(0, 3) == "int"
		|| type.substr(0, 6) == "ufixed"
		|| type.substr(0, 5) == "fixed") {

		std::string bytes;
		bytes = value.get<std::string>();
		remove_hexspec(bytes);
		pad_hexstring(bytes, 32 << 1);
		data.append(bytes);
		return 32;
	}
	else
		return 0;
}

static std::string encodeParameters(const json& paramDefs, const json& values)
{
	size_t headerSize = 0;
	for (auto& paramDef : paramDefs) {
		auto type = paramDef["type"].get<std::string>();
		if (isArray(type)) {
			size_t arraySize = 0;
			std::string subArray;
			parseTypeArray(type, subArray, arraySize);
			if (arraySize == 0) { // dynamic
				headerSize += 32;
			}
			else {
				headerSize += arraySize * 32;
			}
		}
		else {
			headerSize += 32;
		}
	}

	std::string header, data;

	for (auto& paramDef : paramDefs) {
		auto name = paramDef["name"].get<std::string>();
		auto value = values[name];
		auto type = elementaryName(paramDef["type"].get<std::string>());

		if (isDynamic(type)) {
			encodeSingle("uint256", to_hexstring(headerSize), header);
			auto size = encodeSingle(type, value, data);
			headerSize += size;
		}
		else {
			encodeSingle(type, value, header);
		}
	}

	return header + data;
}
