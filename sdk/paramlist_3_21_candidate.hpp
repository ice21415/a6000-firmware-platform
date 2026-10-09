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
    // +0x0c..+0x5b contains two dynamic collection regions.  Their complete
    // element/allocator representation is not yet a verified public ABI.
    std::uint32_t unknown_collection_storage[20];
};
static_assert(offsetof(PrmCntInfoListSnapshotWords, unknown_collection_storage) == 12);
static_assert(sizeof(PrmCntInfoListSnapshotWords) == 92);

struct PrmObjMsgSnapshotWords {
    std::uint32_t vptr_address, discriminator_word, key_word;
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
