#ifndef __ABI_DECODER_H__
#define __ABI_DECODER_H__

#include <vector>
#include <unordered_map>
#include <string>
#include "nlohmann/json.hpp"

class AbiDecoder
{
	std::vector<nlohmann::json> savedABIS;
	std::unordered_map<std::string, nlohmann::json> methodIDs;

public:
	inline const std::vector<nlohmann::json>& getABIs() const { return savedABIS; }
	void addABI(const nlohmann::json& abiArray);
	nlohmann::json decodeMethod(const std::string& data) const;
	std::string encodeMethod(const std::string &method, const nlohmann::json& values) const;
};

#endif
