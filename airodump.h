#pragma once

#include<cstdint>
#include"mac.h"

#pragma pack(push, 1)
struct Radiotap {
        uint8_t it_version;     /* set to 0 */
        uint8_t it_pad;
        uint16_t it_len;         /* entire length */
        uint32_t it_present;     /* fields present */
};
#pragma pack(pop)

#pragma pack(push, 1)
struct Beacon {
	uint8_t type;
	uint8_t flags;
	uint16_t duration;
  	Mac daddr;
	Mac sa;
  	Mac bssid;
  	uint16_t fragment_sequence;
};
#pragma pack(pop)

#pragma pack(push, 1)
struct Fixed_param {
  uint64_t timestamp;
  uint16_t interval;
  uint16_t capa_info;  
};
#pragma pack(pop)

#pragma pack(push, 1)
struct Tagged_param {
  	uint8_t num;
  	uint8_t len;
	char essid;
};
#pragma pack(pop)
