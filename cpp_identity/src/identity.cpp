#include "identity.hpp"

namespace sentinelmesh {
Identity classify(const std::unordered_map<std::string, std::string>& metadata) {
    const auto platform = metadata.find("platform");
    if (platform != metadata.end() && platform->second.find("Windows") != std::string::npos) {
        return {"unknown", "workstation", 55};
    }
    if (metadata.find("mac") != metadata.end()) {
        return {"unknown", "network-neighbor", 25};
    }
    return {"unknown", "unclassified", 0};
}
}
