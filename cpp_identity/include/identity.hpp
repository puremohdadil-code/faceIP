#pragma once

#include <string>
#include <unordered_map>

namespace sentinelmesh {
struct Identity {
    std::string vendor;
    std::string device_class;
    int confidence;
};

Identity classify(const std::unordered_map<std::string, std::string>& metadata);
}
