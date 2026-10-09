#pragma once
#include <cstdint>
#include <cstddef>

// Descriptive snapshot layouts only. Do NOT cast live camera objects to these
// types. These words are target addresses, not host pointers or owning handles.
namespace a6000_research {
struct ParamListWords { std::uint32_t container_address; std::uint32_t counter_address; };
struct PointerContainerWords { std::uint32_t begin_address; std::uint32_t end_address; std::uint32_t unknown_08; };
struct ParamPrefixWords {
    std::uint32_t vptr_address;
    std::uint32_t discriminator_word;
    std::uint32_t key_word;
    std::uint32_t payload_word; // Type and meaning depend on concrete subclass.
};
static_assert(sizeof(ParamListWords) == 8);
static_assert(sizeof(ParamPrefixWords) == 16);
struct PrmNumberSnapshotWords {
    std::uint32_t vptr_address, discriminator_word, key_word;
    std::int32_t payload;
};
struct PrmBoolSnapshotWords {
    std::uint32_t vptr_address, discriminator_word, key_word;
    std::uint8_t payload;
    std::uint8_t unknown_padding[3];
};
static_assert(offsetof(PrmNumberSnapshotWords, payload) == 12);
static_assert(offsetof(PrmBoolSnapshotWords, payload) == 12);
static_assert(sizeof(PrmNumberSnapshotWords) == 16);
static_assert(sizeof(PrmBoolSnapshotWords) == 16);

// Candidate source-level declaration, STATIC_INFERRED return type only.
// Explicit unsigned-long parameters and const are supported by mangling.
// ParamBase* return is NOT encoded in that symbol and remains unverified.
class ParamBase;
class ParamListCandidate {
public:
    ParamBase* get(unsigned long key, unsigned long discriminator) const;
};
// No implementation, address binding, device-call wrapper or runtime guarantee.
}
