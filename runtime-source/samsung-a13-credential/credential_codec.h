// SPDX-License-Identifier: MIT
#pragma once
#include "crypto.h"
namespace sp {
// Exact Samsung framework.jar 731db55a...144. Input is valid UTF-8 for type4
// or canonical ASCII1..9 for type1. All other types are refused.
bool read_samsung_credential_frame(int fd,unsigned actual_type,g3::Secret* output);
bool encode_samsung_credential(unsigned type,const g3::Secret& input,g3::Secret* output);
}
