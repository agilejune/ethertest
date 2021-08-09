#ifndef __ABI_DECODER_H__
#define __ABI_DECODER_H__

#include <vector>
#include <unordered_map>
#include <string>
#include "nlohmann/json.hpp"

class AbiDecoder
{
	std::vector<nlohmann::json> saved_abis_;
	std::unordered_map<std::string, std::string> method_id_to_name_map_;
	std::unordered_map<std::string, nlohmann::json> method_name_to_abi_map_;

public:
	inline const std::vector<nlohmann::json>& getABIs() const { return saved_abis_; }
	void addABI(const nlohmann::json& abiArray);
	nlohmann::json decodeData(const std::string& data) const;
	nlohmann::json decodeInput(const std::string& method, const std::string& data) const;
	nlohmann::json decodeOutput(const std::string& method, const std::string& data) const;
	std::string encodeInput(const std::string &method, const nlohmann::json& values) const;
};

#endif
