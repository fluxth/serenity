/*
 * Copyright (c) 2022, Thitat Auareesuksakul (thitat@flux.ci)
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <AK/Assertions.h>
#include <AK/Endian.h>
#include <AK/Format.h>
#include <AK/IPv6Address.h>
#include <Kernel/Net/IP.h>

namespace Kernel {

class [[gnu::packed]] IPv6Packet {
public:
    u8 version() const { return (m_version_and_class_and_flow >> 28) & 0xf; } 
    void set_version(u8 version) {
        m_version_and_class_and_flow = (m_version_and_class_and_flow & 0xfffffff) | (version << 28);
    }

    u8 traffic_class() const { return (m_version_and_class_and_flow >> 20) & 0xff; }
    void set_traffic_class(u8 traffic_class) {
        m_version_and_class_and_flow = (m_version_and_class_and_flow & 0xf00fffff) | (traffic_class << 20);
    }

    u32 flow_label() const {
        return AK::convert_between_host_and_network_endian(m_version_and_class_and_flow & 0xfffff);
    }
    void set_flow_label(u32 flow_label) {
        m_version_and_class_and_flow = (m_version_and_class_and_flow & 0xfff00000) | (flow_label & 0xfffff);
    }

    u16 length() const { return m_length; }
    void set_length(u16 length) { m_length = length; }

    u8 next_header() const { return m_next_header; }
    void set_next_header(u8 next_header) { m_next_header = next_header; }

    u8 hop_limit() const { return m_hop_limit; }
    void set_hop_limit(u8 hop_limit) { m_hop_limit = hop_limit; }

    IPv6Address const& source() const { return m_source; }
    void set_source(IPv6Address const& address) { m_source = address; }

    IPv6Address const& destination() const { return m_destination; }
    void set_destination(IPv6Address const& address) { m_destination = address; }

    void* payload() { return this + 1; }
    void const* payload() const { return this + 1; }

    u16 payload_size() const { return m_length - sizeof(IPv6Packet); }

    void print() const {
        dbgln("IPv6Packet:");
        dbgln("    ver={} traffic_class={} flow_label={:#05x}", version(), traffic_class(), flow_label());
        dbgln("    len={} next_header={} hop_limit={}", length(), next_header(), hop_limit());
        dbgln("    src={} dest={}", source(), destination());
    };

private:
    NetworkOrdered<u32> m_version_and_class_and_flow;
    NetworkOrdered<u16> m_length;
    u8 m_next_header { 0 };
    u8 m_hop_limit { 0 };
    IPv6Address m_source;
    IPv6Address m_destination;
};

static_assert(AssertSize<IPv6Packet, 40>());

}
