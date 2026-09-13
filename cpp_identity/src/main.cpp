#include "identity.hpp"
#include <iostream>
#include <string>

static std::string field(const std::string& line, const std::string& key) {
    const std::string marker = "\"" + key + "\":\"";
    const auto start = line.find(marker);
    if (start == std::string::npos) return "";
    const auto value_start = start + marker.size();
    const auto end = line.find('"', value_start);
    return end == std::string::npos ? "" : line.substr(value_start, end - value_start);
}

int main() {
    std::string line;
    while (std::getline(std::cin, line)) {
        const auto address = field(line, "address");
        const auto mac = field(line, "mac");
        const auto platform = field(line, "platform");
        const auto hostname = field(line, "hostname");
        const auto source = field(line, "source");
        std::unordered_map<std::string, std::string> metadata{{"mac", mac}, {"platform", platform}};
        const auto identity = sentinelmesh::classify(metadata);
        std::cout << "{\"schema_version\":\"1.0\",\"kind\":\"observation\",\"module\":\"cpp_identity\",\"payload\":{";
        std::cout << "\"address\":\"" << address << "\",\"hostname\":\"" << hostname
              << "\",\"source\":\"" << source << "\",\"mac\":\"" << mac
              << "\",\"vendor\":\"" << identity.vendor
                  << "\",\"device_class\":\"" << identity.device_class << "\",\"confidence\":"
                  << identity.confidence << "}}\n";
    }
    return 0;
}
