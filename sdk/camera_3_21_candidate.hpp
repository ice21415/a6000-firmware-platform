#pragma once

#include <cstddef>
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
    static constexpr std::uint32_t selector_getter_vma = 0x00131e94;
    static constexpr std::uint32_t local_word_getter_vma = 0x0010cf18;
    static constexpr std::uint32_t header_builder_vma = 0x00131bcc;
    static constexpr std::uint32_t set_blog_data_wrapper_vma = 0x0013228c;
    static constexpr std::uint32_t envelope_builder_vma = 0x001323b4;
    static constexpr std::uint32_t model_manager_check_status_plt = 0x000df964;
    static constexpr std::uint32_t set_blog_data_plt = 0x000de480;
    static constexpr std::uint32_t envelope_payload_size = 0x14;
    static constexpr std::uint32_t optional_label_copy_size = 8;
    static constexpr std::uint32_t neutr_on_literal_vma = 0x00ce8d7b;
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

// The header/payload shape is a descriptive byte-layout snapshot derived from
// the bounded primary-ELF stores.  The field names are positional on purpose;
// no event, action or hardware meaning is assigned to these words.
struct EeNeutralEnvelopeSnapshot {
    std::uint16_t header_word_zero;
    std::uint8_t header_byte_from_r2;
    std::uint8_t header_byte_from_r1;
    std::uint16_t header_halfword_from_r2;
    std::uint16_t header_word_zero_2;
    std::uint32_t payload_words[5];
};

static_assert(sizeof(EeNeutralEnvelopeSnapshot) == 0x1c);
static_assert(offsetof(EeNeutralEnvelopeSnapshot, payload_words) == 0x08);

}  // namespace a6000_research::camera_3_21
