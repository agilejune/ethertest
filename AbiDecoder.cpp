#include "AbiDecoder.h"
#include <boost/algorithm/hex.hpp>
#include <boost/algorithm/string/join.hpp>
#include <numeric>
#include <iostream>
#include "Keccak.h"

using namespace nlohmann;

static std::string to_hexstring(const std::vector<uint8_t>& bytes)
{
	std::string s;
	boost::algorithm::hex_lower(bytes.begin(), bytes.end(), std::back_inserter(s));
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
static void parseTypeArray(const std::string& name, std::string &subArray, size_t &size)
{
	auto start = name.find_last_of('[');
	auto end = name.find_last_of(']');
	if (start != std::string::npos && end != std::string::npos
		&& start < end)
	{
		subArray = name.substr(0, start);
		auto size_str = name.substr(start + 1, end - start - 1);
		size = size_str.empty() ? 0 : std::stoi(size_str);
	}
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
			auto ret = data.substr(offset * 2, size * 2);
			offset += size;
			return ret;
		}
		else if (type.substr(0, 6) == "ufixed"
			|| type.substr(0, 5) == "fixed") {
			size_t size, sizeM;
			parseTypeNxM(type, size, sizeM);
			// TODO
			auto ret = data.substr(offset * 2, size * 2);
			offset += 32;
			return ret;
		}
	}
	return json{};
}

void AbiDecoder::decodeParameters(const json& paramDefs, size_t &offset, const std::string& data, json &result) const
{
	for (auto& paramDef : paramDefs) {
		auto name = paramDef["name"].get<std::string>();
		auto type = elementaryName(paramDef["type"].get<std::string>());

		result[name] = decodeSingle(type, data, offset);
	}
}
