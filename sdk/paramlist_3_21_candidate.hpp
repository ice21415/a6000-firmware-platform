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

// ParamBase constructor/clone field-access audit metadata from the
// SHA-pinned 3.21 primary ELF. These values describe evidence boundaries only;
// they are not constructors, clone functions, host pointers or live-object
// accessors. The audit found no direct +0x08 key access in the ten bounded
// constructor bodies or ten bounded clone bodies.
struct ParamBaseLifecycleEvidenceConstants {
    static constexpr std::uint32_t family_count = 10;
    static constexpr std::uint32_t key_offset = 0x08;
    static constexpr std::uint32_t payload_offset = 0x0c;
    static constexpr std::uint32_t key_assignment_setter_vma = 0x007eda84;
    static constexpr std::uint32_t direct_key_accesses_in_constructors = 0;
    static constexpr std::uint32_t direct_key_accesses_in_clones = 0;
    static constexpr std::uint32_t clones_with_direct_payload_access = 9;
};

// ParamBase D1/D0 cleanup metadata from the SHA-pinned 3.21 primary ELF.
// These are static call/relocation witnesses only. They do not authorize
// invoking a destructor, deleting a live object, or assuming allocator or
// ownership compatibility outside the firmware process.
struct ParamBaseDestructorEvidenceConstants {
    static constexpr std::uint32_t key_offset = 0x08;
    static constexpr std::uint32_t parambase_nondeleting_destructor_vma = 0x000e4734;
    static constexpr std::uint32_t operator_delete_plt_vma = 0x000dd620;
    static constexpr std::uint32_t operator_array_delete_plt_vma = 0x000df098;
    static constexpr std::uint32_t objmsg_payload_destructor_vma = 0x000ddd94;
    static constexpr std::uint32_t family_count = 10;
    static constexpr std::uint32_t deleting_wrappers_with_d1_and_delete = 10;
    static constexpr std::uint32_t payload_cleanup_call_candidates = 6;
};

// ParamList::add mutation witnesses from the SHA-pinned 3.21 primary ELF.
// These are evidence locators only.  The replacement body is unnamed in the
// stripped image, and none of these values is a host pointer or callable API.
struct ParamListAddEvidenceConstants {
    static constexpr std::uint32_t add_vma = 0x007ee0e6;
    static constexpr std::uint32_t add_size_bytes = 0x30;
    static constexpr std::uint32_t replacement_candidate_vma = 0x007ededa;
    static constexpr std::uint32_t key_setter_vma = 0x007eda84;
    static constexpr std::uint32_t key_offset = 0x08;
    static constexpr std::uint32_t discriminator_offset = 0x04;
    static constexpr std::uint32_t payload_offset = 0x0c;
    static constexpr std::uint32_t remove_slot_vma = 0x007ede7a;
    static constexpr std::uint32_t storage_append_vma = 0x007ee0b8;
};

// ParamList construction, shared-counter and last-owner cleanup witnesses
// from the SHA-pinned 3.21 primary ELF.  These are descriptive ELF VMAs and
// field offsets only; they are not a host-side implementation or safe ABI.
struct ParamListLifetimeEvidenceConstants {
    static constexpr std::uint32_t container_pointer_offset = 0x00;
    static constexpr std::uint32_t shared_counter_pointer_offset = 0x04;
    static constexpr std::uint32_t container_begin_offset = 0x00;
    static constexpr std::uint32_t container_end_offset = 0x04;
    static constexpr std::uint32_t container_capacity_offset = 0x08;
    static constexpr std::uint32_t element_pointer_width_bytes = 4;

    static constexpr std::uint32_t constructor_vma = 0x007edc3e;
    static constexpr std::uint32_t clear_vma = 0x007edb76;
    static constexpr std::uint32_t clear_helper_vma = 0x007edb40;
    static constexpr std::uint32_t container_initializer_vma = 0x007edc14;
    static constexpr std::uint32_t container_release_vma = 0x007edca2;
    static constexpr std::uint32_t container_release_wrapper_vma = 0x007edcb8;
    static constexpr std::uint32_t shared_rebind_candidate_vma = 0x007edcc6;
    static constexpr std::uint32_t destructor_vma = 0x007edd08;
    static constexpr std::uint32_t allocator_plt_vma = 0x000dc100;
    static constexpr std::uint32_t object_delete_plt_vma = 0x000dd620;
};

// External construction/use witnesses from the SHA-pinned primary ELF. These
// constants identify evidence locations only; they are not a callable API.
struct ParamListOwnerUseEvidenceConstants {
    static constexpr std::uint32_t input_status_entry_vma = 0x00114104;
    static constexpr std::uint32_t input_status_size_bytes = 0x164;
    static constexpr std::uint32_t first_lookup_key = 0x17005003;
    static constexpr std::uint32_t second_lookup_key = 0x17005008;
    static constexpr std::uint32_t local_list_one_offset = 0x18;
    static constexpr std::uint32_t local_list_two_offset = 0x20;
    static constexpr std::uint32_t local_list_one_constructor_callsite = 0x00114176;
    static constexpr std::uint32_t local_list_two_constructor_callsite = 0x0011416e;
    static constexpr std::uint32_t number_allocation_callsite = 0x00114186;
    static constexpr std::uint32_t number_constructor_callsite = 0x0011418e;
    static constexpr std::uint32_t add_callsite = 0x0011419a;
    static constexpr std::uint32_t rebind_callsite = 0x001141e2;
    static constexpr std::uint32_t local_list_one_destructor_callsite = 0x001141f6;
    static constexpr std::uint32_t local_list_two_destructor_callsite = 0x001141fe;
};

// Direct-call index targets from the SHA-pinned primary ELF. These are
// evidence locators only; unresolved callers, CFG reachability, loader
// binding, ownership and runtime safety remain unknown.
struct ParamQueryCallsiteEvidenceConstants {
    static constexpr std::uint32_t view_initializer_vma = 0x0042abcc;
    static constexpr std::uint32_t adjacent_lookup_vma = 0x0042abdc;
    static constexpr std::uint32_t word_lookup_vma = 0x0042ac00;
    static constexpr std::uint32_t paramlist_get_forwarder_vma = 0x000e5b20;
    static constexpr std::uint32_t param_payload_getter_vma = 0x000e5b18;
    static constexpr std::uint32_t bool_get_forwarder_vma = 0x00120970;
    static constexpr std::uint32_t point_get_forwarder_vma = 0x000fe9be;
    static constexpr std::uint32_t word_lookup_to_get_callsite = 0x0042ac0c;
    static constexpr std::uint32_t word_lookup_to_payload_callsite = 0x0042ac12;
    static constexpr std::uint32_t adjacent_to_get_callsite = 0x0042abe8;
    static constexpr std::uint32_t adjacent_to_payload_callsite = 0x0042abee;
    static constexpr std::uint32_t paramlist_get_vma = 0x007edaca;
    static constexpr std::uint32_t paramlist_get_symbol_thumb = 0x007edacb;
    static constexpr std::uint32_t paramlist_get_size_bytes = 0x4c;
    static constexpr std::uint32_t lookup_key_offset = 0x08;
    static constexpr std::uint32_t discriminator_offset = 0x04;
    static constexpr std::uint32_t payload_offset = 0x0c;
};

// Query-wrapper words observed in the primary ELF.  These declarations are
// descriptive ABI evidence, not host pointers or callable firmware wrappers.
struct ParamLookupViewWords {
    std::uint32_t selector_word;
    std::uint32_t param_list_address;
};
static_assert(offsetof(ParamLookupViewWords, param_list_address) == 4);
static_assert(sizeof(ParamLookupViewWords) == 8);

struct ParamLookupWordAbiEvidenceConstants {
    static constexpr std::uint32_t view_initializer_vma = 0x0042abcc;
    static constexpr std::uint32_t adjacent_lookup_vma = 0x0042abdc;
    static constexpr std::uint32_t word_lookup_vma = 0x0042ac00;
    static constexpr std::uint32_t output_register = 2;
    static constexpr std::uint32_t output_width_bytes = 4;
    static constexpr std::uint32_t success_status = 0;
    static constexpr std::uint32_t observed_failure_status = 1;
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

// Scalar-family lifecycle evidence from the SHA-pinned 3.21 libObj.so.  These
// are ELF VMAs and bounded static-analysis locators only.  They are not host
// function pointers, constructors that may be called by an application, or a
// promise that the firmware allocator/runtime is available.
struct ParamScalarEvidenceConstants {
    static constexpr std::uint32_t key_offset = 0x08;
    static constexpr std::uint32_t payload_offset = 0x0c;

    static constexpr std::uint32_t prm_bool_rtti_vma = 0x00fe6e18;
    static constexpr std::uint32_t prm_bool_vtable_vma = 0x00fe6e00;
    static constexpr std::uint32_t prm_bool_constructor_vma = 0x000e50e8;
    static constexpr std::uint32_t prm_bool_clone_vma = 0x000e5110;
    static constexpr std::uint32_t prm_bool_destructor_vma = 0x000e4750;
    static constexpr std::uint32_t prm_bool_deleting_destructor_vma = 0x000e4840;
    static constexpr std::uint32_t prm_bool_setter_vma = 0x00426acc;
    static constexpr std::uint32_t prm_bool_discriminator = 5;
    static constexpr std::uint32_t prm_bool_payload_width = 1;

    static constexpr std::uint32_t prm_number_rtti_vma = 0x00fe8938;
    static constexpr std::uint32_t prm_number_vtable_vma = 0x00fe8920;
    static constexpr std::uint32_t prm_number_constructor_vma = 0x000f0fb0;
    static constexpr std::uint32_t prm_number_clone_vma = 0x000f1034;
    static constexpr std::uint32_t prm_number_destructor_vma = 0x000f0f2c;
    static constexpr std::uint32_t prm_number_deleting_destructor_vma = 0x000f0f5c;
    static constexpr std::uint32_t prm_number_setter_vma = 0x0010f9fc;
    static constexpr std::uint32_t prm_number_discriminator = 1;
    static constexpr std::uint32_t prm_number_payload_width = 4;
};

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

// PrmSet RTTI/vtable metadata recovered from the SHA-pinned 3.21 ELF.  The
// function addresses are ELF VMAs and the odd values below are Thumb-tagged
// words read from the file-backed vtable; they are not host function pointers.
struct PrmSetEvidenceConstants {
    static constexpr std::uint32_t rtti_vma = 0x01019d08;
    static constexpr std::uint32_t vtable_prefix_vma = 0x01019d18;
    static constexpr std::uint32_t vtable_address_point = 0x01019d20;
    static constexpr std::uint32_t clone_candidate_vma = 0x007efbb4;
    static constexpr std::uint32_t nondeleting_destructor_vma = 0x007efb2c;
    static constexpr std::uint32_t deleting_destructor_vma = 0x007efb58;
    static constexpr std::uint32_t clone_candidate_raw_thumb = 0x007efbb5;
    static constexpr std::uint32_t nondeleting_destructor_raw_thumb = 0x007efb2d;
    static constexpr std::uint32_t deleting_destructor_raw_thumb = 0x007efb59;
};

// ARM EHABI and bounded cleanup locators for the PrmSet copy/clone paths.
// These are static-analysis metadata only: they are not exception tables,
// host function pointers, or proof that an external caller may construct or
// destroy a live firmware object.
struct PrmSetExceptionEvidenceConstants {
    static constexpr std::uint32_t copy_constructor_candidate_vma = 0x007efb6c;
    static constexpr std::uint32_t copy_cleanup_landing_pad_vma = 0x007efb9c;
    static constexpr std::uint32_t clone_candidate_vma = 0x007efbb4;
    static constexpr std::uint32_t clone_cleanup_landing_pad_vma = 0x007efbce;
    static constexpr std::uint32_t cxa_end_cleanup_plt_vma = 0x000dd4f8;
};

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
// Layout-compatible candidate for the separately allocated tree node.  The
// field names intentionally remain generic: the exact PrmSet element type,
// comparator and allocator ownership are not proven by the primary ELF.
struct PrmSetTreeNodeWords {
    std::uint32_t node_word_00;
    std::uint32_t node_link_04;
    std::uint32_t node_link_08;
    std::uint32_t node_link_0c;
    std::uint32_t value_word_10;
};
static_assert(offsetof(PrmSetTreeNodeWords, node_link_08) == 8);
static_assert(offsetof(PrmSetTreeNodeWords, value_word_10) == 16);
static_assert(sizeof(PrmSetTreeNodeWords) == 20);

struct PrmSetTreeEvidenceConstants {
    static constexpr std::uint32_t node_size_bytes = 0x14;
    static constexpr std::uint32_t node_value_offset = 0x10;
    static constexpr std::uint32_t node_value_width_bytes = 0x04;
    static constexpr std::uint32_t header_sentinel_offset = 0x04;
    static constexpr std::uint32_t node_count_offset = 0x14;
    static constexpr std::uint32_t payload_header_base_offset = 0x04;
    static constexpr std::uint32_t payload_root_offset = 0x08;
    static constexpr std::uint32_t payload_header_link_0c_offset = 0x0c;
    static constexpr std::uint32_t payload_header_link_10_offset = 0x10;
    static constexpr std::uint32_t node_link_08_offset = 0x08;
    static constexpr std::uint32_t node_link_0c_offset = 0x0c;
    static constexpr std::uint32_t value_copy_helper_vma = 0x000ecd7a;
    static constexpr std::uint32_t value_compare_helper_vma = 0x000efe6c;
};
static_assert(offsetof(PrmSetPayloadTreeWords, header_word_04) == 4);
static_assert(offsetof(PrmSetPayloadTreeWords, node_count_14) == 20);
static_assert(sizeof(PrmSetPayloadTreeWords) == 24);

// Cross-ELF static evidence from libScalarDaemon.so.  These are callsite
// locators in the dependent ELF and are not function pointers.  The chain is
// descriptive: runtime loader binding, returned C++ types, ownership and
// thread safety remain unknown.
struct PrmSetCrossElfEvidenceConstants {
    static constexpr std::uint32_t caller_dispatch_system_event_vma = 0x000d5b5c;
    static constexpr std::uint32_t get_callsite_vma = 0x000d5b7a;
    static constexpr std::uint32_t get_set_callsite_vma = 0x000d5b80;
    static constexpr std::uint32_t parameter_id = 0x19;
    static constexpr std::uint32_t get_set_plt_vma = 0x000cb224;
    static constexpr std::uint32_t get_plt_vma = 0x000d30b8;
};

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

// ParamList::clear virtual-dispatch evidence from the SHA-pinned 3.21 ELF.
// These are file/VMA offsets used by offline tooling, never host pointers.
// The clear body loads an element vptr and calls the word at vptr + 0x08;
// the ten known ParamBase-family vtables place their deleting-destructor
// entry at that address point-relative slot.  This does not prove that an
// arbitrary pointer is a valid element or establish allocation ownership.
struct ParamListVirtualDispatchEvidenceConstants {
    static constexpr std::uint32_t clear_helper_vma = 0x007edb40;
    static constexpr std::uint32_t clear_dispatch_load_vma = 0x007edb60;
    static constexpr std::uint32_t clear_dispatch_slot_load_vma = 0x007edb62;
    static constexpr std::uint32_t clear_dispatch_call_vma = 0x007edb64;
    static constexpr std::uint32_t element_vptr_offset = 0x00;
    static constexpr std::uint32_t virtual_slot_from_vptr = 0x08;
    static constexpr std::uint32_t vtable_prefix_to_address_point = 0x08;
    static constexpr std::uint32_t deleting_destructor_slot_from_prefix = 0x10;
    static constexpr std::uint32_t verified_family_count = 10;
    static constexpr std::uint32_t exact_deleting_slot_matches = 10;
};

// Runtime dynamic type, null/invalid object policy beyond the bounded null
// slot guard, double-destroy behavior, locking, concurrent safety and
// callable/runtime verification remain unknown.  No wrapper is provided.
}
