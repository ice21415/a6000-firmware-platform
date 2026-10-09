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
