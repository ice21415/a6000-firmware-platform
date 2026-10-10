#pragma once

#include <cstdint>

// Descriptive Camera evidence only.  These are ELF VMAs, field offsets and
// observed constants from the private SHA-pinned 3.21 primary ELF.  They are
// not host pointers, live-camera handles or callable firmware wrappers.
namespace a6000_research::camera_3_21 {

struct EeNeutralEvidenceConstants {
    static constexpr std::uint32_t sender_vma = 0x00443d14;
    static constexpr std::uint32_t command_vma = 0x004b1a20;
    static constexpr std::uint32_t relay_counter_offset = 0x2700;
    static constexpr std::uint32_t pending_byte_offset = 0x26fc;
    static constexpr std::uint32_t message_group = 0x3100;
    static constexpr std::uint32_t message_command = 0x7502;
    static constexpr std::uint32_t selector_first = 0x11;
    static constexpr std::uint32_t selector_second = 0x12;
    static constexpr std::uint32_t event_helper_selector = 0x0e;
    static constexpr std::uint32_t event_helper_command = 0x33ba;
    static constexpr std::uint32_t issue_command_async_plt = 0x000dc144;
};

// This is a register/field observation model, not a C++ object layout.  The
// receiver class, return type, transport completion and ownership remain
// unknown; callers must not instantiate or invoke this structure.
struct EeNeutralStaticObservation {
    std::uint32_t opaque_receiver;
    std::uint32_t relay_counter_value;
    std::uint8_t pending_byte_value;
    std::uint8_t unknown_padding[3];
};

static_assert(sizeof(EeNeutralStaticObservation) == 12);

}  // namespace a6000_research::camera_3_21
