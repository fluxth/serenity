/*
 * Copyright (c) 2022, Thitat Auareesuksakul (thitat@flux.ci)
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

namespace Kernel {

enum class IPProtocol : u16 {
    ICMP = 1,
    TCP = 6,
    UDP = 17,
};

}
