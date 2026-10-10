#pragma once

#include <cstddef>
#include <cstdint>
#include <type_traits>

// Descriptive, static-only Camera Core evidence for ILCE-6000 firmware 3.21.
// The declarations preserve observed ARM/AAPCS register roles and positional
// fields.  They are not callable firmware wrappers and must not be used with
// a live camera.  UNKNOWN fields intentionally remain unknown until an
// independent ABI and runtime validation exists.
namespace a6000_research::camera_core_3_21 {

// All *_arm32 fields below describe a 32-bit ARM firmware word.  They are
// intentionally not C++ pointers: this header is a static evidence schema,
// not a callable ABI wrapper, and must retain the target layout on 64-bit
// analysis hosts.
using Arm32Word = std::uint32_t;

enum class EvidenceLevel : std::uint8_t {
  PrimaryElfVerified,
  StaticInferred,
  Unknown,
  RuntimeVerified,
};

struct ParamList;  // Opaque; no complete public layout is claimed here.

// Register roles observed at ViewBase::requestModelExecute (0x12106e) and
// viewManagerIf::requestModelExecute (0x1250c0).
struct RequestModelExecuteObservation {
  Arm32Word model_name_r1_arm32;
  Arm32Word selector_r2;
  Arm32Word param_list_r3_arm32;
  Arm32Word receiver_r0_arm32;
  EvidenceLevel evidence;
};

// Host-only view for tooling that has already resolved an ARM32 word to a
// local object.  Its pointer layout is deliberately separate from the
// target-width observation above and has no firmware ABI meaning.
struct RequestModelExecuteHostObservation {
  const char* model_name_r1_host;
  std::uint32_t selector_r2;
  const ParamList* param_list_r3_host;
  const void* receiver_r0_host;
  EvidenceLevel evidence;
};

// The factory creates an Event with id 0x11004003 and adds keys 7 and 8.  The
// values are positional observations; their receiver-side interpretation is
// UNKNOWN.
struct RequestEventEnvelopeObservation {
  static constexpr std::uint32_t event_id = 0x11004003;
  static constexpr std::uint32_t model_key = 7;
  static constexpr std::uint32_t selector_key = 8;
  Arm32Word model_identifier;
  Arm32Word transformed_selector;
  Arm32Word optional_param_list_arm32;
  EvidenceLevel evidence;
};

// Host-only interpretation view.  This is not layout-compatible with the
// ARM32 observation and must not be passed to firmware code.
struct RequestEventEnvelopeHostObservation {
  Arm32Word model_identifier;
  Arm32Word transformed_selector;
  const ParamList* optional_param_list_host;
  EvidenceLevel evidence;
};

// View::requestApplicationExecute adds an application parameter with key 6,
// then submits through an opaque owner/manager field at View +0x24.
struct ViewEventSubmissionObservation {
  static constexpr std::size_t application_parameter_source_offset = 0x18;
  static constexpr std::size_t owner_candidate_offset = 0x24;
  static constexpr std::size_t event_manager_candidate_offset = 0x10;
  std::uint32_t application_parameter_value;
  std::uint32_t opaque_owner;
  EvidenceLevel evidence;
};

// EventManager::push loads an indirect dispatch target from a state object
// reached through its receiver.  The callback target and C++ object type are
// deliberately not named.
struct EventManagerDispatchObservation {
  static constexpr std::size_t completion_callback_offset = 0x04;
  static constexpr std::size_t dispatch_state_offset = 0x00;
  static constexpr std::size_t dispatch_function_offset = 0x08;
  std::uint32_t opaque_event_manager;
  std::uint32_t opaque_event;
  bool completion_requested;
  EvidenceLevel evidence;
};

// ModelCamera's selector dispatch compares against 0x0f01 and calls
// pvt_ActionSetInit (0x4cf7a8) with the payload in r1.  The event consumer
// that would supply this payload is still UNKNOWN.
struct ModelCameraActionObservation {
  static constexpr std::uint32_t selector = 0x0f01;
  static constexpr std::uint32_t action_set_init_vma = 0x004cf7a8;
  static constexpr std::uint32_t ee_neutral_vma = 0x004b1a20;
  static constexpr std::uint32_t ee_neutral_sender_vma = 0x00443d14;
  std::uint32_t payload_r1;
  EvidenceLevel evidence;
};

static_assert(sizeof(Arm32Word) == 4);
static_assert(std::is_standard_layout_v<RequestEventEnvelopeObservation>);
static_assert(sizeof(RequestEventEnvelopeObservation) == 16);

}  // namespace a6000_research::camera_core_3_21
