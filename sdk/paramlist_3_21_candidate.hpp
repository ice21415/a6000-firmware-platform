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

// ParamBase evidence constants for firmware 3.21. These are ELF VMAs and
// static-analysis locators, not host function pointers or callable wrappers.
struct ParamBaseEvidenceConstants {
    static constexpr std::uint32_t rtti_vma = 0x00fe6e24;
    static constexpr std::uint32_t vtable_prefix_vma = 0x00fe6e30;
    static constexpr std::uint32_t vtable_address_point = 0x00fe6e38;
    static constexpr std::uint32_t constructor_vma = 0x000e50b4;
    static constexpr std::uint32_t destructor_vma = 0x000e4734;
    static constexpr std::uint32_t deleting_destructor_vma = 0x000e4854;
    static constexpr std::uint32_t key_setter_vma = 0x007eda84;
};
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

struct PrmStringSnapshotWords {
    std::uint32_t vptr_address, discriminator_word, key_word;
    std::uint32_t string_address;
};
struct PrmPointSnapshotWords {
    std::uint32_t vptr_address, discriminator_word, key_word;
    std::uint32_t word_0c, word_10;
};
struct PrmDimensionSnapshotWords {
    std::uint32_t vptr_address, discriminator_word, key_word;
    std::uint32_t word_0c, word_10;
};
struct PrmStructSnapshotWords {
    std::uint32_t vptr_address, discriminator_word, key_word;
    std::uint32_t opaque_word_0c, opaque_word_10;
};
struct PrmSetSnapshotWords {
    std::uint32_t vptr_address, discriminator_word, key_word;
    std::uint32_t opaque_payload[6];
};
static_assert(offsetof(PrmStringSnapshotWords, string_address) == 12);
static_assert(offsetof(PrmPointSnapshotWords, word_0c) == 12);
static_assert(offsetof(PrmDimensionSnapshotWords, word_0c) == 12);
static_assert(offsetof(PrmStructSnapshotWords, opaque_word_0c) == 12);
static_assert(offsetof(PrmSetSnapshotWords, opaque_payload) == 12);
static_assert(sizeof(PrmStringSnapshotWords) == 16);
static_assert(sizeof(PrmPointSnapshotWords) == 20);
static_assert(sizeof(PrmDimensionSnapshotWords) == 20);
static_assert(sizeof(PrmStructSnapshotWords) == 20);
static_assert(sizeof(PrmSetSnapshotWords) == 36);

// The following words describe the bounded ELF-local tree evidence inside a
// PrmSet payload.  They are not a std::set declaration and must not be used
// as host pointers or live camera objects.  The source alias, comparator,
// element signedness and mutation entry point are still unknown.
struct PrmSetPayloadTreeWords {
    std::uint32_t unknown_00;
    std::uint32_t header_word_04;
    std::uint32_t header_word_08;
    std::uint32_t header_link_0c;
    std::uint32_t header_link_10;
    std::uint32_t node_count_14;
};
struct PrmSetTreeEvidenceConstants {
    static constexpr std::uint32_t node_size_bytes = 0x14;
    static constexpr std::uint32_t node_value_offset = 0x10;
    static constexpr std::uint32_t node_value_width_bytes = 0x04;
    static constexpr std::uint32_t header_sentinel_offset = 0x04;
    static constexpr std::uint32_t node_count_offset = 0x14;
    static constexpr std::uint32_t value_copy_helper_vma = 0x000ecd7a;
    static constexpr std::uint32_t value_compare_helper_vma = 0x000efe6c;
};
static_assert(offsetof(PrmSetPayloadTreeWords, header_word_04) == 4);
static_assert(offsetof(PrmSetPayloadTreeWords, node_count_14) == 20);
static_assert(sizeof(PrmSetPayloadTreeWords) == 24);

// Additional static layouts recovered from the 3.21 ParamBase family.  The
// collection members are deliberately named storage/words: their allocator,
// iterator and ownership ABI has not been proven and these are not live views.
struct VectorUint32Words {
    std::uint32_t begin_address;
    std::uint32_t end_address;
    std::uint32_t capacity_address;
};
struct PrmNumberListSnapshotWords {
    std::uint32_t vptr_address, discriminator_word, key_word;
    VectorUint32Words values;
};
static_assert(sizeof(VectorUint32Words) == 12);
static_assert(offsetof(PrmNumberListSnapshotWords, values) == 12);
static_assert(sizeof(PrmNumberListSnapshotWords) == 24);

struct PrmCntInfoListSnapshotWords {
    std::uint32_t vptr_address, discriminator_word, key_word;
    // Each region occupies 0x28 bytes in the object.  The word-level fields
    // are intentionally unnamed: the private helper bodies prove 32-bit
    // loads/stores and metadata updates, but do not prove std::vector,
    // allocator, iterator, or ownership semantics.
    struct CollectionWords {
        std::uint32_t unknown_word[10];
    } collection_0c, collection_34;
};
static_assert(offsetof(PrmCntInfoListSnapshotWords, collection_0c) == 12);
static_assert(offsetof(PrmCntInfoListSnapshotWords, collection_34) == 52);
static_assert(sizeof(PrmCntInfoListSnapshotWords) == 92);

struct PrmObjMsgSnapshotWords {
    std::uint32_t vptr_address, discriminator_word, key_word;
    // The primary ELF destructor calls MWF::ObjMsg D1 and object delete for a
    // non-zero value.  This is an address candidate in an offline snapshot,
    // not a host pointer and not proof that arbitrary constructor inputs may
    // be transferred safely.
    std::uint32_t obj_msg_address;
};
static_assert(offsetof(PrmObjMsgSnapshotWords, obj_msg_address) == 12);
static_assert(sizeof(PrmObjMsgSnapshotWords) == 16);

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
