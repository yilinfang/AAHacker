#include <stdexcept>
#include <string>
#include <sys/stat.h>
#include <vector>
#pragma once

#if __BYTE_ORDER == __LITTLE_ENDIAN
#define cpu_to_le16(x) (x)
#define cpu_to_le32(x) (x)
#else
#error "Big Endian not supported"
#endif
#define be16_to_cpu(x) be16toh(x)

std::string rr(const std::string &str);
std::string sr(const std::string &str);
void pushBackInt16(std::vector<uint8_t> &vec, uint16_t num);
void pushBackInt64(std::vector<uint8_t> &vec, uint64_t num);
std::string hexStr(uint8_t *data, int len);
uint64_t bytesToUInt64(const std::vector<uint8_t> &vec, int offset);
