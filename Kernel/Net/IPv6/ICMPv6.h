/*
 * Copyright (c) 2022, Thitat Auareesuksakul (thitat@flux.ci)
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <AK/MACAddress.h>
#include <Kernel/Net/IPv6/IPv6.h>

namespace Kernel {

enum class ICMPv6Type {
    // Error messages
    DestinationUnreachable = 1,
    PacketTooBig = 2,
    TimeExceeded = 3,
    ParameterProblem = 4,

    // Informational messages
    EchoRequest = 128,
    EchoReply = 129,
    RouterSolicitation = 133,
    RouterAdvertisement = 134,
    NeighborSolicitation = 135,
    NeighborAdvertisement = 136,
};

class [[gnu::packed]] ICMPv6Header {
public:
    ICMPv6Header() = default;
    ~ICMPv6Header() = default;

    u8 type() const { return m_type; }
    void set_type(u8 b) { m_type = b; }

    u8 code() const { return m_code; }
    void set_code(u8 b) { m_code = b; }

    u16 checksum() const { return m_checksum; }
    void set_checksum(u16 w) { m_checksum = w; }

    void const* payload() const { return this + 1; }
    void* payload() { return this + 1; }

private:
    u8 m_type { 0 };
    u8 m_code { 0 };
    NetworkOrdered<u16> m_checksum { 0 };
};

static_assert(AssertSize<ICMPv6Header, 4>());

struct [[gnu::packed]] ICMPv6EchoPacket {
    ICMPv6Header header;
    NetworkOrdered<u16> identifier;
    NetworkOrdered<u16> sequence_number;

    void* payload() { return this + 1; }
    void const* payload() const { return this + 1; }
};

}
