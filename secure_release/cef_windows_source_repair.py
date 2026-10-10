"""Twenty-three reviewed Windows source corrections, bound to a new build contract.

The baseline CEF checkout and native checkpoint codec stay unchanged. Only the
exact reviewed producers below may cross into this profile, after authenticated
restore under its OLD contract. New checkpoints carry the NEW contract and a
verified source marker covering all twenty-three files. Neither receipts nor fixtures
constitute runtime proof.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import stat
import tempfile
import time

from .crypto import canonical, parse

CHROMIUM = "79460ebecaa5625e57a5fb679a735659e73dc687"
V8 = "4323497a6a73839e6d5260f6acd7ec0212cb3321"
HEADER = "download/chromium/src/net/websockets/websocket_handshake_challenge.h"
MARKER = "cef-windows-source-repair.json"
BEFORE = "e9c2a8404032abb4080a5f6855ca396a5ecee841f017e932d49b9bbc2574e184"
AFTER = "38eb8b609bea01c37e3799feaba074c79f189568ff9b7df8c6943707433ef713"
PAINT_HEADER = "download/chromium/src/ui/gfx/paint_vector_icon.h"
PAINT_BEFORE = "8e9d9819abc21afcd225345eb0ae679731b909e6f23fc4c2dc04ce1f66c6a58d"
PAINT_AFTER = "89e65e86fa4d5de9a72567de96c41659b6610e02cb50a063942e458e0fda70cd"
AUTOFILL_SOURCE = "download/chromium/src/components/autofill/core/common/form_field_data.cc"
AUTOFILL_BEFORE = "0edba08fcad529c1980260493296da86db429684b98fdaf7765ae8c083397e32"
AUTOFILL_AFTER = "fd5dcc844aa6250b7b5bb702965e7abeba4cb57f655aec2ff43f078be471b490"
ATOMIC_SOURCE = "download/chromium/src/third_party/blink/renderer/platform/wtf/text/atomic_string.cc"
ATOMIC_BEFORE = "a4c0cc1f34fd6b692337331b8192096e77ada0a13a3b6c6598770bbb8711a871"
ATOMIC_AFTER = "554274d3e6d39eb924fa276f1a747e26f54453a00c1e644dde9a1b7cc8cb5b42"
HEAP_HEADER = "download/chromium/src/v8/src/heap/cppgc-internal/heap-object-header.h"
HEAP_BEFORE = "397f2555d0498e92eb5d40872e8066b1a08a9cba993a4457256b8fb0375251ee"
HEAP_AFTER = "901a8ce9d296f6d3b701d348fc09478f31465e659e9925696dd358871757d94d"
TORQUE_SOURCE = "download/chromium/src/v8/src/torque/implementation-visitor.cc"
TORQUE_BEFORE = "bb857f343d860a65c111e9e178df67d3f9cf251f92eaa017202265a533c63abe"
TORQUE_AFTER = "c53c5fda569a1d033cbdeb6213fb49474b714afa8fb1d750243e3193f1b951a3"
TEMPLATE_HEADER = "download/chromium/src/v8/include/v8-template.h"
TEMPLATE_BEFORE = "5ff060cc76e892c0c345a699c0438fe09e23f643a64572f738ec9ff1cfd2d122"
TEMPLATE_AFTER = "f4d4c4515727cedb7a5fba1a1b496a35bd9c6a9ee255cb7b23ed35ea8625b164"
BIND_HEADER = "download/chromium/src/v8/src/base/functional/bind-internal.h"
BIND_BEFORE = "0848488073fd36b6b75088d66518cd7b9bbe0f60190b47e12590d1748abae796"
BIND_AFTER = "e08f2225e93df5a1afc02a1c375e87645449fd7e82b5d7b520c4e7aa31ce501b"
ACCESSIBILITY_HEADER = "download/chromium/src/ui/accessibility/platform/browser_accessibility.h"
ACCESSIBILITY_HEADER_BEFORE = "4892eaa5acd222a0c672d9b5990f0a77009a210649fa8c775bc80e803cfd5f1d"
ACCESSIBILITY_HEADER_AFTER = "ce013afbf9a06a045260b9b38c2aacfe645090e4fb6e110429903a3f6cd725c1"
ACCESSIBILITY_SOURCE = "download/chromium/src/ui/accessibility/platform/browser_accessibility.cc"
ACCESSIBILITY_SOURCE_BEFORE = "f7e3cf4414bf31a8de222ea1a40b147f9fa4014d7e7604192ba3963e307f629a"
ACCESSIBILITY_SOURCE_AFTER = "2db1d2329a419e61c4409b630447c3c56e63987c76a1c76c34bbfac6e097ffe8"
WTF_STRING_HEADER = "download/chromium/src/third_party/blink/renderer/platform/wtf/text/wtf_string.h"
WTF_STRING_BEFORE = "1b4a503d160ffc0480c49710f65d3b6656c498e8ac23dbaaedee491e92ae71ef"
WTF_STRING_AFTER = "cfe2cf6bbb93d0ef053d0c8cf51d8d8071d54876fc53ca5f1f57d00231925d57"
INLINE_HEADER = "download/chromium/src/third_party/blink/renderer/core/layout/inline/inline_node.h"
INLINE_BEFORE = "2aa20d294ebe0a6ae3c7d3a168bb9763d5ce73c0916f7270fde93eb967aebfcc"
INLINE_AFTER = "3fa4cfb6be4f52f090fbc4c05e0958c120b72065fca623473cf53faa0d888019"
DOM_HEADER = "download/chromium/src/services/data_decoder/xml/dom_builder.h"
DOM_BEFORE = "969acc87746001c86ef0d98eeb2a15de80e02e56b6a2727d0d3b7dc73cc37882"
DOM_AFTER = "596393505d3d16f2ffe7bd3cd6b7c51c7c534d16896028739bcbd05c48bc0e4a"
INLINE_ITEMS_SOURCE = "download/chromium/src/third_party/blink/renderer/core/layout/inline/inline_items_data.cc"
INLINE_ITEMS_BEFORE = "efe6e5d17a2d676a4c7868ff496b95a90c11bb77aa964738a517e1329934661f"
INLINE_ITEMS_AFTER = "f2c8be99df3cbd16e07e7b1d9a377570b1884b3e5debe081d97f444d3616dccb"
API_KEY_HEADER = "download/chromium/src/google_apis/common/api_key_request_util.h"
API_KEY_BEFORE = "acccec39b6828f168e8f51c523cd8a07479094f46de3854c6fbf6697bc6bdfbc"
API_KEY_AFTER = "02b32aaf140ccaa8feb78159aef9f8c2a199d91714aa8cd3a552731617838269"
CREDIT_CARD_HEADER = "download/chromium/src/components/autofill/core/common/credit_card_number_validation.h"
CREDIT_CARD_BEFORE = "c53deafa5e5e2ec30949db20be0dec9f46493d49f9555a155a6c419bdb2607f4"
CREDIT_CARD_AFTER = "e11c6be830cbd52303ea11826a84bccf1838746276b25809bdf878c7aa7d3a50"
FRAME_TREE_HEADER = "download/chromium/src/content/browser/renderer_host/frame_tree.h"
FRAME_TREE_BEFORE = "6dff457016eb06cc710a53012c80884d089665bbf1346cf8933b4535c060b17f"
FRAME_TREE_AFTER = "968192391f2275c7732e37b1547261e01a424df9633db7e1993d1ff899ecbd77"
LOCK_MANAGER_HEADER = "download/chromium/src/content/browser/locks/lock_manager.h"
LOCK_MANAGER_BEFORE = "5da1667d945bccc542dcef1268139f1c923dae0d1d2cd6559840055d1c78a2fd"
LOCK_MANAGER_AFTER = "e5bc278ffcaf644f3741e7d6d7102d50b533a1c6eede695647b9010524a4f6f0"
AFFILIATED_MATCH_SOURCE = "download/chromium/src/components/password_manager/core/browser/affiliation/affiliated_match_helper.cc"
AFFILIATED_MATCH_BEFORE = "efeb49da7d34594d877dad553efab6a14aef33e209b0aa48780e810785e1301b"
AFFILIATED_MATCH_AFTER = "ce5b8a9575fd441afef0b6416af40596d3d0e040d40b28457a031831870d03f7"
BACKEND_ERROR_HEADER = "download/chromium/src/components/password_manager/core/browser/password_store/password_store_backend_error.h"
BACKEND_ERROR_SOURCE = "download/chromium/src/components/password_manager/core/browser/password_store/password_store_backend_error.cc"
BACKEND_ERROR_HEADER_BEFORE = "670caf88a0a98fc25d516d672ca7d3a28d56f9d414580efa9bd057d1e239f291"
BACKEND_ERROR_HEADER_AFTER = "61f89eaf1043c024a3605ee38a33fa67e7a95f60b479129edeb26db293235ad2"
BACKEND_ERROR_SOURCE_BEFORE = "4b19a74de291fd09caf9e516033114f5ae8348fdd69e81eecbacacd4658b6cdf"
BACKEND_ERROR_SOURCE_AFTER = "8b99f25b7c099934136e7d337c2ba8b4420ecb92fca5d52ba7762896c5ef3833"
PERMISSION_MANAGER_HEADER = "download/chromium/src/components/permissions/permission_request_manager.h"
PERMISSION_MANAGER_BEFORE = "bc14a8e3f644138477b2450cafa2931061f583dcdf244e644546e1e913018289"
PERMISSION_MANAGER_AFTER = "a021f5322a869f393d2077313e8ef26f3167b9677efc7e92596ec71227b4c570"
WATERMARK_HEADER = "download/chromium/src/chrome/browser/enterprise/watermark/settings.h"
WATERMARK_BEFORE = "d7a0cd34ef3fc8bd33a1d13c88699d5ec5a31ee614c12dedc1b72a08cd9c3233"
WATERMARK_AFTER = "2810e40f606ff37a20ebccfa00610b2fae1d5377fcea20c08d2b7be39e8676a8"
# Ordered, closed set of corrections; no caller-selected paths or patches.
CORRECTIONS = (
    (HEADER, BEFORE, AFTER, (
        (b"#include <string_view>\n",
         b"#include <string>\n#include <string_view>\n"),
    )),
    (PAINT_HEADER, PAINT_BEFORE, PAINT_AFTER, (
        (b'#include "base/component_export.h"\n',
         b'#include <string>\n\n#include "base/component_export.h"\n'),
    )),
    (AUTOFILL_SOURCE, AUTOFILL_BEFORE, AUTOFILL_AFTER, (
        (b'#include "base/notreached.h"\n',
         b'#include "base/no_destructor.h"\n#include "base/notreached.h"\n'),
        (b'    static const std::optional<AutocompleteParsingResult> kNoParsingResult =\n'
         b'        std::nullopt;\n',
         b'    static const base::NoDestructor<std::optional<AutocompleteParsingResult>>\n'
         b'        kNoParsingResult(std::nullopt);\n'),
        (b'!e.contains(kNotRefillRelated) ? f.parsed_autocomplete_ : kNoParsingResult,',
         b'!e.contains(kNotRefillRelated) ? f.parsed_autocomplete_ : *kNoParsingResult,'),
    )),
    (ATOMIC_SOURCE, ATOMIC_BEFORE, ATOMIC_AFTER, (
        (b'#include "third_party/blink/renderer/platform/wtf/text/case_map.h"\n',
         b'#include "third_party/blink/renderer/platform/wtf/text/case_map.h"\n'
         b'#include "third_party/blink/renderer/platform/wtf/text/code_point_iterator.h"\n'),
    )),
    (HEAP_HEADER, HEAP_BEFORE, HEAP_AFTER, (
        (b'std::atomic_ref(const_cast<uint16_t&>(half)).load(memory_order)',
         b'std::atomic_ref<uint16_t>(const_cast<uint16_t&>(half)).load(memory_order)'),
    )),
    (TORQUE_SOURCE, TORQUE_BEFORE, TORQUE_AFTER, (
        (b'    if (type->IsLayoutDefinedInCpp()) {\n      return "sizeof(" + parent_name + ")";\n    }\n',
         b'    if (type->IsLayoutDefinedInCpp()) {\n      // A packed subclass may reuse its parent\'s tail padding on the MS ABI.\n      // Use Torque\'s fixed logical size, as TypeVisitor does, rather than the\n      // standalone C++ sizeof. Keep the layout assertions independent of C++.\n      if (parent && parent->IsLayoutDefinedInCpp() && parent->HasStaticSize()) {\n        return std::to_string(*parent->size().SingleValue());\n      }\n      return "sizeof(" + parent_name + ")";\n    }\n'),
        (b'          << "::" << f.name_and_type.name << " in C++ do not match\\");\\n";\n',
         b'          << "::" << f.name_and_type.name << " in C++ do not match\\");\\n";\n    if (!f.index.has_value()) {\n      // Check the data extent independently so tail-padding rounding cannot\n      // hide a wrong scalar field width, including the final base-class byte.\n      impl_ << "  static_assert(" << field_offset << "End + 1 == "\n            << cpp_field_offset << " + sizeof(" << name_ << "::"\n            << f.name_and_type.name << "_));\\n";\n    }\n'),
        (b'    impl_ << "  static_assert(kSize == sizeof(" + name_ + "));\\n";\n',
         b'    // Torque\'s kSize is the logical data end. A standalone C++ object also\n    // includes tail padding required by its alignment, unlike a base subobject.\n    // Keep an equality check for the entire object, including that padding.\n    impl_ << "  static_assert((kSize + alignof(" << name_\n          << ") - 1) / alignof(" << name_ << ") * alignof(" << name_\n          << ") == sizeof(" << name_ << "));\\n";\n'),
    )),
    (TEMPLATE_HEADER, TEMPLATE_BEFORE, TEMPLATE_AFTER, (
        (b'#include "v8-function-callback.h"  // NOLINT(build/include_directory)\n',
         b'#include "v8-fast-api-calls.h"      // NOLINT(build/include_directory)\n'
         b'#include "v8-function-callback.h"  // NOLINT(build/include_directory)\n'),
    )),
    (BIND_HEADER, BIND_BEFORE, BIND_AFTER, (
        (b'#define BIND_INTERNAL_EXTRACT_CALLABLE_RUN_TYPE_WITH_QUALS(quals)     \\\n  template <typename Callable, typename R, typename... Args>          \\\n  struct ExtractCallableRunTypeImpl<Callable,                         \\\n                                    R (Callable::*)(Args...) quals> { \\\n    using Type = R(Args...);                                          \\\n  }',
         b'// An inherited call operator belongs to its declaring base, not Callable.\n#define BIND_INTERNAL_EXTRACT_CALLABLE_RUN_TYPE_WITH_QUALS(quals)       \\\n  template <typename Callable, typename Receiver, typename R,          \\\n            typename... Args>                                         \\\n  struct ExtractCallableRunTypeImpl<Callable,                          \\\n                                    R (Receiver::*)(Args...) quals> { \\\n    using Type = R(Args...);                                           \\\n  }'),
    )),
    (ACCESSIBILITY_HEADER, ACCESSIBILITY_HEADER_BEFORE, ACCESSIBILITY_HEADER_AFTER, (
        (b'    PlatformChildIterator(const BrowserAccessibility* parent,\n',
         b'    // A singular iterator, comparable with other value-initialized iterators.\n    PlatformChildIterator();\n    PlatformChildIterator(const BrowserAccessibility* parent,\n'),
    )),
    (ACCESSIBILITY_SOURCE, ACCESSIBILITY_SOURCE_BEFORE, ACCESSIBILITY_SOURCE_AFTER, (
        (b'BrowserAccessibility::PlatformChildIterator::PlatformChildIterator(\n    const PlatformChildIterator& it)\n',
         b'BrowserAccessibility::PlatformChildIterator::PlatformChildIterator()\n    : parent_(nullptr), platform_iterator(nullptr, nullptr) {}\n\nBrowserAccessibility::PlatformChildIterator::PlatformChildIterator(\n    const PlatformChildIterator& it)\n'),
        (b'BrowserAccessibility::PlatformChildIterator::GetIndexInParent() const {\n',
         b'BrowserAccessibility::PlatformChildIterator::GetIndexInParent() const {\n  // Singular iterators have no parent or index. Do not dereference either.\n  if (!parent_) {\n    return std::nullopt;\n  }\n\n'),
    )),
    (WTF_STRING_HEADER, WTF_STRING_BEFORE, WTF_STRING_AFTER, (
        (b'#include "third_party/blink/renderer/platform/wtf/allocator/allocator.h"\n',
         b'#include "third_party/blink/renderer/platform/wtf/allocator/allocator.h"\n'
         b'#include "third_party/blink/renderer/platform/wtf/text/code_point_iterator.h"\n'),
    )),
    (INLINE_HEADER, INLINE_BEFORE, INLINE_AFTER, (
        (b'#include "base/gtest_prod_util.h"\n',
         b'#include "base/gtest_prod_util.h"\n#include "base/no_destructor.h"\n'),
        (b'    static const std::optional<TextOffsetMap> kEmpty;\n',
         b'    static const base::NoDestructor<std::optional<TextOffsetMap>> kEmpty;\n'),
        (b'    return kEmpty;\n',
         b'    return *kEmpty;\n'),
    )),
    (DOM_HEADER, DOM_BEFORE, DOM_AFTER, (
        (b'#include "third_party/rust/cxx/v1/cxx.h"\n',
         b'#include <memory>\n\n#include "third_party/rust/cxx/v1/cxx.h"\n'),
    )),
    (INLINE_ITEMS_SOURCE, INLINE_ITEMS_BEFORE, INLINE_ITEMS_AFTER, (
        (b'#include "third_party/blink/renderer/core/layout/inline/inline_items_data.h"\n',
         b'#include "third_party/blink/renderer/core/layout/inline/inline_items_data.h"\n\n'
         b'#include "base/no_destructor.h"\n'),
        (b'  static const std::optional<TextOffsetMap> kEmpty;\n',
         b'  static const base::NoDestructor<std::optional<TextOffsetMap>> kEmpty;\n'),
        (b'  return kEmpty;\n', b'  return *kEmpty;\n'),
    )),
    (API_KEY_HEADER, API_KEY_BEFORE, API_KEY_AFTER, (
        (b'#include <optional>\n#include <string_view>\n',
         b'#include <optional>\n#include <string>\n#include <string_view>\n'),
    )),
    (CREDIT_CARD_HEADER, CREDIT_CARD_BEFORE, CREDIT_CARD_AFTER, (
        (b'#include <string_view>\n',
         b'#include <string>\n#include <string_view>\n'),
    )),
    (FRAME_TREE_HEADER, FRAME_TREE_BEFORE, FRAME_TREE_AFTER, (
        (b'    NodeIterator(const NodeIterator& other);\n    ~NodeIterator();\n',
         b'    NodeIterator(const NodeIterator& other);\n'
         b'    NodeIterator& operator=(const NodeIterator&) = default;\n'
         b'    ~NodeIterator();\n'),
        (b'    RAW_PTR_EXCLUSION const FrameTreeNode* const root_of_subtree_to_skip_;\n\n'
         b'    const bool should_descend_into_inner_trees_;\n'
         b'    const bool include_delegate_nodes_for_inner_frame_trees_;\n',
         b'    RAW_PTR_EXCLUSION const FrameTreeNode* root_of_subtree_to_skip_;\n\n'
         b'    bool should_descend_into_inner_trees_;\n'
         b'    bool include_delegate_nodes_for_inner_frame_trees_;\n'),
    )),
    (LOCK_MANAGER_HEADER, LOCK_MANAGER_BEFORE, LOCK_MANAGER_AFTER, (
        (b'  base::flat_map<std::string, std::list<Lock>> resource_names_to_requests_;\n',
         b'  std::map<std::string, std::list<Lock>> resource_names_to_requests_;\n'),
    )),
    (AFFILIATED_MATCH_SOURCE, AFFILIATED_MATCH_BEFORE, AFFILIATED_MATCH_AFTER, (
        (b'      base::BindOnce(std::move(result_callback), std::move(forms)));\n',
         b'      base::BindOnce(std::move(result_callback),\n'
         b'                     LoginsResultOrError(std::in_place_type<LoginsResult>,\n'
         b'                                         std::move(forms))));\n'),
    )),
    (BACKEND_ERROR_HEADER, BACKEND_ERROR_HEADER_BEFORE, BACKEND_ERROR_HEADER_AFTER, (
        (b'  PasswordStoreBackendError(PasswordStoreBackendError&& rhs);\n',
         b'  PasswordStoreBackendError(PasswordStoreBackendError&& rhs) noexcept;\n'),
        (b'  PasswordStoreBackendError& operator=(PasswordStoreBackendError&& rhs);\n',
         b'  PasswordStoreBackendError& operator=(PasswordStoreBackendError&& rhs) noexcept;\n'),
    )),
    (BACKEND_ERROR_SOURCE, BACKEND_ERROR_SOURCE_BEFORE, BACKEND_ERROR_SOURCE_AFTER, (
        (b'PasswordStoreBackendError::PasswordStoreBackendError(\n'
         b'    PasswordStoreBackendError&& rhs) = default;\n',
         b'PasswordStoreBackendError::PasswordStoreBackendError(\n'
         b'    PasswordStoreBackendError&& rhs) noexcept = default;\n'),
        (b'PasswordStoreBackendError& PasswordStoreBackendError::operator=(\n'
         b'    PasswordStoreBackendError&& rhs) = default;\n',
         b'PasswordStoreBackendError& PasswordStoreBackendError::operator=(\n'
         b'    PasswordStoreBackendError&& rhs) noexcept = default;\n'),
    )),
    (PERMISSION_MANAGER_HEADER, PERMISSION_MANAGER_BEFORE, PERMISSION_MANAGER_AFTER, (
        (b'  std::map<base::raw_ref<PermissionRequest>, PermissionRequestSource>\n',
         b'  std::map<base::raw_ref<const PermissionRequest>, PermissionRequestSource>\n'),
    )),
    (WATERMARK_HEADER, WATERMARK_BEFORE, WATERMARK_AFTER, (
        (b'#include "third_party/skia/include/core/SkColor.h"\n',
         b'#include <string>\n\n#include "third_party/skia/include/core/SkColor.h"\n'),
    )),
)
BASE_KEY = "60a369f6b051ba651cb301af299e7dadcc99608d0db6894bccab87b953817602"
LEGACY = {
    "run": 37007852614, "attempt": 1,
    "producer_sha": "312f6ca48ab6a26982a4bb21ec0e1514af38e859",
    "artifact_id": 11237383883,
    "artifact_sha256": "3a3788d8b2c6ed29daeba5ac357f751aa374a6b05ba9aab94591001165ea402f",
    "summary_artifact_id": 11237488572,
    "summary_artifact_sha256": "343ce6fe1876f7cf5bf295ad626c2f88a52973667dc6d92797421d004af518e3",
    "build_key": BASE_KEY,
}

V11_KEY = "3236c681bbaa2549857e41479929c717a41e6e44ae5bfb496d2849d3c55c4f94"
UPGRADE_V11 = {
    "run": 37246298528,
    "attempt": 1,
    "producer_sha": "a1878e179eeeea98e9e1453046c1ee8b8bb76238",
    "artifact_id": 11325301513,
    "artifact_sha256": "7d5c828da84f2e959016a7accc87b0cbfb38c862d6a2673be6ebd8a5d3af7fae",
    "summary_artifact_id": 11324997284,
    "summary_artifact_sha256": "fb9d7f5eb91c8e60b3b0ddfebef2ce1dbfe8c9786cb123bdccdebf5db55a1065",
    "build_key": "3236c681bbaa2549857e41479929c717a41e6e44ae5bfb496d2849d3c55c4f94"
}


V13_KEY = "21e5ba94783f13de5fc21d179fec40a299d5cd5b9a0230f6979aaa68bde14217"
UPGRADE_V13 = {
    "run": 37320000155, "attempt": 1,
    "producer_sha": "729c5303990e7948e0a85d7fe680efe5190d11c6",
    "artifact_id": 11361733253,
    "artifact_sha256": "23cfaa837c997018880ba97509e78beb656b234e94a9a3a1113e0736f09b1527",
    "summary_artifact_id": 11362750324,
    "summary_artifact_sha256": "ed71941302937d1c4891ffc7965c11d694990b2987208d0ee2d8f9aac04f8ecf",
    "build_key": V13_KEY,
}

V14_KEY = "378126b8abd73d31b865dd7bab7fc0d9b344a0d207ecf6b7b26429b5cb587acd"
UPGRADE_V14 = {
    "run": 37441180545, "attempt": 1,
    "producer_sha": "6bbe92014dba81e24713af905ae6be3de0c71157",
    "artifact_id": 11415367897,
    "artifact_sha256": "9e7de2213e8108033f32d1a99bc3fac412a2103cfa616e4a30a63ccc6f978d61",
    "summary_artifact_id": 11415317880,
    "summary_artifact_sha256": "f9eabc75abbb7a059fa0bf06071edbd9f2cce676f11b74e69e9c387b2afbe6d2",
    "build_key": V14_KEY,
}


V15_KEY = "0e6e30c138ce2acc75aa738d800acd20d6f26258413692b2eef1b9814ee01ab2"
UPGRADE_V15 = {
    "run": 37723049328, "attempt": 1,
    "producer_sha": "1b063cb7f4f418ec83c2e5302a3cea20dbf64127",
    "artifact_id": 11534009465,
    "artifact_sha256": "2b491a1e7b2c0fafdfd8491a10f61c9e0e64189e0f81e97d516f0a83e56c8ebe",
    "summary_artifact_id": 11534820603,
    "summary_artifact_sha256": "923d10b2fd9fab0299120227f8c803516577fc77fd4423e56e3b5dbebe1bdd07",
    "build_key": V15_KEY,
}


V16_KEY = "a82f375c37244173719bea5cec2324bf8e1e48dca684cc41710689db6078e0b5"
UPGRADE_V16 = {
    "run": 37817304632,
    "attempt": 1,
    "producer_sha": "fc6f9a4dca65fdcf7d1ccfe35a4b684cb488e37a",
    "artifact_id": 11579487539,
    "artifact_sha256": "7a5864a6cdf114735f542e39217d972f79c120d8949ad853220c9c01f4f7619e",
    "summary_artifact_id": 11579487543,
    "summary_artifact_sha256": "b64341f9fb579ad67ea6d2be6fabec948eea9be862986f5abe0cc42b96562a3a",
    "build_key": "a82f375c37244173719bea5cec2324bf8e1e48dca684cc41710689db6078e0b5"
}



V19_KEY = "1c37bef0e74b261ca8520fa2c98413f13d905c894afcd97558c95d3aec41bb69"
UPGRADE_V19 = {
    "run": 38044124418, "attempt": 1,
    "producer_sha": "8e3a700e34fd004bf1a3effcbe52049455f7ba8e",
    "artifact_id": 11670614648,
    "artifact_sha256": "c28ed4ac43e47adf182a6a2335d1ede7fb07a47b2c71a14b6a766258505c0460",
    "summary_artifact_id": 11670574716,
    "summary_artifact_sha256": "8dc30b29490833852363800faa4371cbe6ae4c824c5fb5d79377aa6c3e81539d",
    "build_key": V19_KEY,
}


V21_KEY = "829652636524483559f552ce0cb6e12dc9033eadd8b3851587410636db38c39a"
UPGRADE_V21 = {
    "run": 38073597639, "attempt": 1,
    "producer_sha": "56849f25f39c1e99aa101392807538b07808242f",
    "artifact_id": 11682106537,
    "artifact_sha256": "f1d7eb93e743a4400ffdf2cbdd078079e5246453579f0a6c262073ad1469f0bd",
    "summary_artifact_id": 11681782053,
    "summary_artifact_sha256": "436c8d3fb1f350c0600aa1d649aedf5ae96348734eaedda1a0d997a04668d5fd",
    "build_key": V21_KEY,
}


def v11_profile() -> dict:
    value = {
        "schema": 2, "id": "windows-blink-string-codepoint-iterator-v11",
        "chromium_commit": CHROMIUM, "v8_commit": V8,
        "corrections": [{"path": path.removeprefix("download/chromium/src/"),
                         "before_sha256": before, "after_sha256": after}
                        for path, before, after, _ in CORRECTIONS[:11]],
        "implementation_sha256": "4fee03fa893a82324554c0bd12a790a8487bd3b030aa77438968f1fde494a48d",
    }
    digest = hashlib.sha256(canonical({"schema": 2, "base_build_key": BASE_KEY,
                                       "source_repair": value})).hexdigest()
    if digest != V11_KEY:
        raise ValueError("Historical Windows v11 source profile changed")
    return value


def v13_profile() -> dict:
    """Historical independently hash-bound v13 profile of qualified #49."""
    value = {
        "schema": 2, "id": "windows-xml-dom-memory-v13",
        "chromium_commit": CHROMIUM, "v8_commit": V8,
        "corrections": [{"path": path.removeprefix("download/chromium/src/"),
                         "before_sha256": before, "after_sha256": after}
                        for path, before, after, _ in CORRECTIONS[:13]],
        "implementation_sha256": "6a922529c5c8399d114decaf8e7ea7ffeda686cc65116b5d8b45cbbb18fe4898",
    }
    digest = hashlib.sha256(canonical({"schema": 2, "base_build_key": BASE_KEY,
                                       "source_repair": value})).hexdigest()
    if digest != V13_KEY:
        raise ValueError("Previous Windows v13 source profile changed")
    return value



def prior_profile() -> dict:
    """The immutable, independently hash-bound v14 profile of qualified #51."""
    value = {
        "schema": 2, "id": "windows-inline-items-offset-lifetime-v14",
        "chromium_commit": CHROMIUM, "v8_commit": V8,
        "corrections": [{"path": path.removeprefix("download/chromium/src/"),
                         "before_sha256": before, "after_sha256": after}
                        for path, before, after, _ in CORRECTIONS[:14]],
        "implementation_sha256": "70fa5a0db5c70e48b78f83c498d78db687f7cb76d0e1d1ddd3ee6b3b6f7e7703",
    }
    digest = hashlib.sha256(canonical({"schema": 2, "base_build_key": BASE_KEY,
                                       "source_repair": value})).hexdigest()
    if digest != V14_KEY:
        raise ValueError("Previous Windows v14 source profile changed")
    return value

def v15_profile() -> dict:
    """Immutable independently hash-bound V15 profile selected by #59."""
    value = {
        "schema": 2, "id": "windows-api-key-string-include-v15",
        "chromium_commit": CHROMIUM, "v8_commit": V8,
        "corrections": [
            {"path": path.removeprefix("download/chromium/src/"),
             "before_sha256": before, "after_sha256": after}
            for path, before, after, _ in CORRECTIONS[:15]
        ],
        "implementation_sha256": "8c133ac986230d3d5b18f08aa95ca9ab21adb6bdb9db4e8a0dbcf3c449872b8f",
    }
    digest = hashlib.sha256(canonical({
        "schema": 2, "base_build_key": BASE_KEY, "source_repair": value,
    })).hexdigest()
    if digest != V15_KEY:
        raise ValueError("Previous Windows v15 source profile changed")
    return value


def v16_profile() -> dict:
    """Immutable independently hash-bound V16 profile of qualified checkpoint #61."""
    value = {
        "schema": 2, "id": "windows-credit-card-number-string-include-v16",
        "chromium_commit": CHROMIUM, "v8_commit": V8,
        "corrections": [
            {"path": path.removeprefix("download/chromium/src/"),
             "before_sha256": before, "after_sha256": after}
            for path, before, after, _ in CORRECTIONS[:16]
        ],
        "implementation_sha256": "3f9edeb27f84f38437c690d3fb23f283650f2e295b2aba63fc13ac36fe80d176",
    }
    digest = hashlib.sha256(canonical({
        "schema": 2, "base_build_key": BASE_KEY, "source_repair": value,
    })).hexdigest()
    if digest != V16_KEY:
        raise ValueError("Previous Windows v16 source profile changed")
    return value


def v19_profile() -> dict:
    """Immutable, independently hash-bound source profile of qualified V19 checkpoint."""
    value = {
        "schema": 2, "id": "windows-affiliated-result-in-place-v19",
        "chromium_commit": CHROMIUM, "v8_commit": V8,
        "corrections": [
            {"path": path.removeprefix("download/chromium/src/"),
             "before_sha256": before, "after_sha256": after}
            for path, before, after, _ in CORRECTIONS[:19]
        ],
        "implementation_sha256": "7d161a04fdb755642b1530a98c64e2c53247384b48f3e0a92d71d04253cd3f65",
    }
    digest = hashlib.sha256(canonical({
        "schema": 2, "base_build_key": BASE_KEY, "source_repair": value,
    })).hexdigest()
    if digest != V19_KEY:
        raise ValueError("Previous Windows v19 source profile changed")
    return value


def v21_profile() -> dict:
    """Immutable, independently hash-bound profile of qualified V21 checkpoint."""
    value = {
        "schema": 2, "id": "windows-permission-source-const-key-v21",
        "chromium_commit": CHROMIUM, "v8_commit": V8,
        "corrections": [
            {"path": path.removeprefix("download/chromium/src/"),
             "before_sha256": before, "after_sha256": after}
            for path, before, after, _ in CORRECTIONS[:22]
        ],
        "implementation_sha256": "6a10914d5d6222c2ff34aa46ab7af5d193c75a88beeaddeeb27c882c14e6ae39",
    }
    digest = hashlib.sha256(canonical({
        "schema": 2, "base_build_key": BASE_KEY, "source_repair": value,
    })).hexdigest()
    if digest != V21_KEY:
        raise ValueError("Previous Windows v21 source profile changed")
    return value


def profile() -> dict:
    return {
        "schema": 2, "id": "windows-watermark-string-include-v22",
        "chromium_commit": CHROMIUM,
        "v8_commit": V8,
        "corrections": [
            {"path": path.removeprefix("download/chromium/src/"),
             "before_sha256": before, "after_sha256": after}
            for path, before, after, _ in CORRECTIONS
        ],
        "implementation_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
    }


def build_key(base_key: str) -> str:
    if base_key != BASE_KEY:
        raise ValueError("Windows source repair requires the reviewed baseline")
    return hashlib.sha256(canonical({
        "schema": 2, "base_build_key": base_key, "source_repair": profile(),
    })).hexdigest()


def restore_contract(selected: dict | None, base_key: str) -> tuple[str, str]:
    current = build_key(base_key)
    if selected is None:
        return current, "fresh"
    if not isinstance(selected, dict):
        raise ValueError("Invalid Windows source repair checkpoint")
    # Canonical comparison distinguishes booleans from integer identifiers.
    if canonical(selected) == canonical(UPGRADE_V21):
        v21_profile()
        return V21_KEY, "upgrade-v21"
    if canonical(selected) == canonical(UPGRADE_V19):
        v19_profile()
        return V19_KEY, "upgrade-v19"
    if canonical(selected) == canonical(UPGRADE_V16):
        v16_profile()
        return V16_KEY, "upgrade-v16"
    if canonical(selected) == canonical(UPGRADE_V15):
        v15_profile()
        return V15_KEY, "upgrade-v15"
    if canonical(selected) == canonical(UPGRADE_V14):
        prior_profile()
        return V14_KEY, "upgrade-v14"
    if canonical(selected) == canonical(LEGACY):
        return BASE_KEY, "legacy"
    if selected.get("build_key") == current:
        return current, "resume"
    raise ValueError("No reviewed Windows source repair checkpoint transition")


def verify_summary(value: dict, selected: dict) -> None:
    _, origin = restore_contract(selected, BASE_KEY)
    if origin == "legacy":
        if "source_repair" in value:
            raise ValueError("Legacy Windows checkpoint claims a repaired profile")
        return
    expected_profile = (
        v21_profile() if origin == "upgrade-v21"
        else v19_profile() if origin == "upgrade-v19"
        else v16_profile() if origin == "upgrade-v16"
        else v15_profile() if origin == "upgrade-v15"
        else prior_profile() if origin == "upgrade-v14"
        else profile()
    )
    if (value.get("base_build_key") != BASE_KEY
            or value.get("source_repair_verified") is not True
            or canonical(value.get("source_repair")) != canonical(expected_profile)):
        raise ValueError("Windows checkpoint lacks the exact source repair proof")


def normalized(raw: bytes) -> tuple[bytes, bytes]:
    newline = b"\r\n" if b"\r\n" in raw else b"\n"
    text = raw.replace(b"\r\n", b"\n")
    if b"\r" in text or (newline == b"\r\n" and b"\n" in raw.replace(b"\r\n", b"")):
        raise ValueError("Unreviewed Windows header newline encoding")
    return text, newline


def transform(raw: bytes, relative: str = HEADER) -> bytes:
    correction = next((item for item in CORRECTIONS if item[0] == relative), None)
    if correction is None:
        raise ValueError("Unreviewed Windows header correction path")
    _, before, after, edits = correction
    text, newline = normalized(raw)
    digest = hashlib.sha256(text).hexdigest()
    if digest == after:
        return raw
    if digest != before:
        raise ValueError("Unreviewed Windows header; refusing source correction")
    changed = text
    for anchor, replacement in edits:
        if changed.count(anchor) != 1:
            raise ValueError("Windows source correction anchor mismatch")
        changed = changed.replace(anchor, replacement, 1)
    if hashlib.sha256(changed).hexdigest() != after:
        raise ValueError("Windows source correction digest mismatch")
    return changed.replace(b"\n", newline)


def _object_snapshot(info) -> tuple:
    # CPython 3.12 win32_xstat copies birthtime to ctime; fstat retains
    # ChangeTime. Compare the same birthtime field ACROSS the APIs instead.
    # Keep ctime in the full snapshots checked WITHIN each API below.
    return (info.st_dev, info.st_ino, info.st_mode, info.st_nlink,
            info.st_size, info.st_mtime_ns,
            getattr(info, "st_birthtime_ns", info.st_ctime_ns))


def _snapshot(info) -> tuple:
    return (info.st_dev, info.st_ino, info.st_mode, info.st_nlink,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _path(work: Path, relative: str) -> Path:
    current = work
    for part in relative.split("/"):
        current = current / part
        info = current.lstat()
        if (stat.S_ISLNK(info.st_mode)
                or getattr(info, "st_file_attributes", 0) & 0x400):
            raise ValueError("Redirected Windows source repair path")
    if not current.resolve(strict=True).is_relative_to(work):
        raise ValueError("Windows source repair escaped workspace")
    return current


def _read(work: Path, relative: str, limit: int = 65536) -> tuple[Path, bytes, object]:
    path = _path(work, relative)
    before = path.lstat()
    if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
            or not 0 < before.st_size <= limit):
        raise ValueError("Invalid Windows source repair input")
    with path.open("rb") as stream:
        opened = os.fstat(stream.fileno())
        if _object_snapshot(opened) != _object_snapshot(before):
            raise ValueError("Windows source repair input changed before read")
        data = stream.read(limit + 1)
        after = os.fstat(stream.fileno())
    if (len(data) != before.st_size or _snapshot(after) != _snapshot(opened)
            or _snapshot(path.lstat()) != _snapshot(before)):
        raise ValueError("Windows source repair input changed during read")
    return path, data, before


def source_limit(relative: str) -> int:
    if relative == TORQUE_SOURCE:
        return 262144
    if relative == ACCESSIBILITY_SOURCE:
        return 131072
    return 65536


def apply(work: Path, contract: str, origin: str) -> str:
    if origin not in {"fresh", "legacy", "resume", "upgrade-v11", "upgrade-v13", "upgrade-v14", "upgrade-v15", "upgrade-v16", "upgrade-v19", "upgrade-v21"} or contract != build_key(BASE_KEY):
        raise ValueError("Invalid Windows source repair invocation")
    if not work.is_absolute() or work != work.resolve(strict=True):
        raise ValueError("Noncanonical Windows source repair workspace")
    expected = canonical({"schema": 1, "kind": "cef-windows-source-repair",
                          "build_key": contract, "source_repair": profile()})
    marker = work / MARKER
    # Validate the complete set BEFORE writing any source. A bad later
    # file must not cause a seemingly valid partial source transition.
    inputs = []
    for relative, _, _, _ in CORRECTIONS:
        path, original, before = _read(work, relative, source_limit(relative))
        inputs.append((relative, path, original, before, transform(original, relative)))
    if origin == "upgrade-v21":
        return _upgrade_v21(work, expected, inputs)
    if origin == "upgrade-v19":
        return _upgrade_v19(work, expected, inputs)
    if origin == "upgrade-v16":
        return _upgrade_v16(work, expected, inputs)
    if origin == "upgrade-v15":
        return _upgrade_v15(work, expected, inputs)
    if origin == "upgrade-v14":
        return _upgrade_v14(work, expected, inputs)
    if origin == "upgrade-v13":
        return _upgrade_v13(work, expected, inputs)
    if origin == "upgrade-v11":
        return _upgrade_v11(work, expected, inputs)
    if origin == "resume":
        _, data, _ = _read(work, MARKER, 8192)
        if (canonical(parse(data)) != expected
                or any(original != changed for _, _, original, _, changed in inputs)):
            raise ValueError("Repaired Windows checkpoint source/marker mismatch")
        return "already-applied"
    # No prior repaired checkpoint was qualified. Only the exact legacy producer may
    # transition; reject old markers and partially applied source sets.
    if os.path.lexists(marker) or any(original == changed for _, _, original, _, changed in inputs):
        raise ValueError("Unexpected source correction in baseline checkpoint")
    for relative, path, original, before, changed in inputs:
        fd, name = tempfile.mkstemp(prefix=".cef-header-", dir=path.parent)
        temporary = Path(name)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(changed)
            temporary.chmod(stat.S_IMODE(before.st_mode))
            # Retime only this changed INPUT, never existing objects/deps or
            # already-corrected headers. Ninja invalidates its dependents.
            new_time = max(time.time_ns(), before.st_mtime_ns + 1_000_000)
            os.utime(temporary, ns=(new_time, new_time))
            if _path(work, relative) != path or _snapshot(path.lstat()) != _snapshot(before):
                raise ValueError("Windows source repair input changed before replacement")
            os.replace(temporary, path)
        finally:
            temporary.unlink(missing_ok=True)
    # Publish the marker only after ALL corrections verify. An interrupted
    # transition fails closed; it cannot produce a qualified checkpoint.
    for relative, _, _, before, changed in inputs:
        _, result, after = _read(work, relative, source_limit(relative))
        if result != changed or after.st_mtime_ns <= before.st_mtime_ns:
            raise ValueError("Windows header correction or input clock verification failed")
    with marker.open("xb") as stream:
        stream.write(expected + b"\n")
    return "applied"


def _upgrade_v11(work: Path, expected: bytes, inputs: list) -> str:
    """Upgrade only the complete authenticated v11 source state; fail on partial edits.

    The worker restores the exact selected producer under V11_KEY before calling
    this function. Existing sources and output files are never retimed/relabelled.
    The source marker is replaced only after the entire new source set verifies.
    """
    marker, marker_data, marker_before = _read(work, MARKER, 8192)
    previous = canonical({"schema": 1, "kind": "cef-windows-source-repair",
                          "build_key": V11_KEY, "source_repair": v11_profile()})
    if (canonical(parse(marker_data)) != previous or len(inputs) != 23
            or tuple(item[0] for item in inputs[11:]) != (INLINE_HEADER, DOM_HEADER, INLINE_ITEMS_SOURCE, API_KEY_HEADER, CREDIT_CARD_HEADER, FRAME_TREE_HEADER, LOCK_MANAGER_HEADER, AFFILIATED_MATCH_SOURCE, BACKEND_ERROR_HEADER, BACKEND_ERROR_SOURCE, PERMISSION_MANAGER_HEADER, WATERMARK_HEADER)
            or any(original != changed for _, _, original, _, changed in inputs[:11])
            or any(original == changed for _, _, original, _, changed in inputs[11:])):
        raise ValueError("Windows v11 source/marker transition mismatch")

    def verify_marker():
        path, data, info = _read(work, MARKER, 8192)
        if (path != marker or data != marker_data
                or _snapshot(info) != _snapshot(marker_before)):
            raise ValueError("Windows v11 marker changed during upgrade")

    def verify_sources(replaced=0):
        for index, (relative, path, original, before, changed) in enumerate(inputs):
            current, data, info = _read(work, relative, source_limit(relative))
            is_new = 11 <= index < 11 + replaced
            if (current != path or data != (changed if is_new else original)
                    or (not is_new and _snapshot(info) != _snapshot(before))
                    or (is_new and info.st_mtime_ns <= before.st_mtime_ns)):
                raise ValueError("Windows v11 source changed during upgrade")

    # All twelve later sources were validated before any write. After each replacement,
    # recheck the complete source set and old marker; a partial upgrade is fatal.
    for replaced, (relative, path, original, before, changed) in enumerate(inputs[11:]):
        fd, name = tempfile.mkstemp(prefix=".cef-header-", dir=path.parent)
        temporary = Path(name)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(changed)
                stream.flush()
                os.fsync(stream.fileno())
            temporary.chmod(stat.S_IMODE(before.st_mode))
            new_time = max(time.time_ns(), before.st_mtime_ns + 1_000_000)
            os.utime(temporary, ns=(new_time, new_time))
            verify_sources(replaced)
            verify_marker()
            os.replace(temporary, path)
        finally:
            temporary.unlink(missing_ok=True)
        verify_sources(replaced + 1)
        verify_marker()
    fd, name = tempfile.mkstemp(prefix=".cef-marker-", dir=work)
    temporary = Path(name)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(expected + b"\n")
            stream.flush()
            os.fsync(stream.fileno())
        temporary.chmod(stat.S_IMODE(marker_before.st_mode))
        verify_sources(replaced=12)
        verify_marker()
        os.replace(temporary, marker)
    finally:
        temporary.unlink(missing_ok=True)
    _, data, _ = _read(work, MARKER, 8192)
    if canonical(parse(data)) != expected:
        raise ValueError("Windows upgraded marker verification failed")
    verify_sources(replaced=12)
    return "upgraded-v11"


def _upgrade_v13(work: Path, expected: bytes, inputs: list) -> str:
    """Historical v13 transition for regression only; production selects v16."""
    marker, marker_data, marker_before = _read(work, MARKER, 8192)
    previous = canonical({"schema": 1, "kind": "cef-windows-source-repair",
                          "build_key": V13_KEY, "source_repair": v13_profile()})
    if (canonical(parse(marker_data)) != previous or len(inputs) != 23
            or tuple(item[0] for item in inputs[13:]) != (INLINE_ITEMS_SOURCE, API_KEY_HEADER, CREDIT_CARD_HEADER, FRAME_TREE_HEADER, LOCK_MANAGER_HEADER, AFFILIATED_MATCH_SOURCE, BACKEND_ERROR_HEADER, BACKEND_ERROR_SOURCE, PERMISSION_MANAGER_HEADER, WATERMARK_HEADER)
            or any(original != changed for _, _, original, _, changed in inputs[:13])
            or any(original == changed for _, _, original, _, changed in inputs[13:])):
        raise ValueError("Windows v13 source/marker transition mismatch")

    def verify_marker():
        path, data, info = _read(work, MARKER, 8192)
        if path != marker or data != marker_data or _snapshot(info) != _snapshot(marker_before):
            raise ValueError("Windows v13 marker changed during upgrade")

    def verify_sources(replaced=0):
        for index, (relative, path, original, before, changed) in enumerate(inputs):
            current, data, info = _read(work, relative, source_limit(relative))
            is_new = 13 <= index < 13 + replaced
            if (current != path or data != (changed if is_new else original)
                    or (not is_new and _snapshot(info) != _snapshot(before))
                    or (is_new and info.st_mtime_ns <= before.st_mtime_ns)):
                raise ValueError("Windows v13 source changed during upgrade")

    for replaced, (relative, path, original, before, changed) in enumerate(inputs[13:]):
        fd, name = tempfile.mkstemp(prefix=".cef-header-", dir=path.parent)
        temporary = Path(name)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(changed); stream.flush(); os.fsync(stream.fileno())
            temporary.chmod(stat.S_IMODE(before.st_mode))
            new_time = max(time.time_ns(), before.st_mtime_ns + 1_000_000)
            os.utime(temporary, ns=(new_time, new_time))
            verify_sources(replaced); verify_marker(); os.replace(temporary, path)
        finally:
            temporary.unlink(missing_ok=True)
        verify_sources(replaced + 1); verify_marker()

    fd, name = tempfile.mkstemp(prefix=".cef-marker-", dir=work)
    temporary = Path(name)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(expected + b"\n"); stream.flush(); os.fsync(stream.fileno())
        temporary.chmod(stat.S_IMODE(marker_before.st_mode))
        verify_sources(replaced=10); verify_marker(); os.replace(temporary, marker)
    finally:
        temporary.unlink(missing_ok=True)
    _, data, _ = _read(work, MARKER, 8192)
    if canonical(parse(data)) != expected:
        raise ValueError("Windows upgraded marker verification failed")
    verify_sources(replaced=10)
    return "upgraded-v13"


def _upgrade_v14(work: Path, expected: bytes, inputs: list) -> str:
    """Upgrade exact authenticated v14 state through its nine later corrections."""
    marker, marker_data, marker_before = _read(work, MARKER, 8192)
    previous = canonical({"schema": 1, "kind": "cef-windows-source-repair",
                          "build_key": V14_KEY, "source_repair": prior_profile()})
    if (canonical(parse(marker_data)) != previous or len(inputs) != 23
            or tuple(item[0] for item in inputs[14:]) != (API_KEY_HEADER, CREDIT_CARD_HEADER, FRAME_TREE_HEADER, LOCK_MANAGER_HEADER, AFFILIATED_MATCH_SOURCE, BACKEND_ERROR_HEADER, BACKEND_ERROR_SOURCE, PERMISSION_MANAGER_HEADER, WATERMARK_HEADER)
            or any(original != changed for _, _, original, _, changed in inputs[:14])
            or any(original == changed for _, _, original, _, changed in inputs[14:])):
        raise ValueError("Windows v14 source/marker transition mismatch")
    def verify_marker():
        path, data, info = _read(work, MARKER, 8192)
        if path != marker or data != marker_data or _snapshot(info) != _snapshot(marker_before):
            raise ValueError("Windows v14 marker changed during upgrade")
    def verify_sources(replaced=0):
        for index, (relative, path, original, before, changed) in enumerate(inputs):
            current, data, info = _read(work, relative, source_limit(relative))
            is_new = 14 <= index < 14 + replaced
            if (current != path or data != (changed if is_new else original)
                    or (not is_new and _snapshot(info) != _snapshot(before))
                    or (is_new and info.st_mtime_ns <= before.st_mtime_ns)):
                raise ValueError("Windows v14 source changed during upgrade")
    for replaced, (relative, path, original, before, changed) in enumerate(inputs[14:]):
        fd, name = tempfile.mkstemp(prefix=".cef-header-", dir=path.parent)
        temporary = Path(name)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(changed); stream.flush(); os.fsync(stream.fileno())
            temporary.chmod(stat.S_IMODE(before.st_mode))
            new_time = max(time.time_ns(), before.st_mtime_ns + 1_000_000)
            os.utime(temporary, ns=(new_time, new_time))
            verify_sources(replaced); verify_marker(); os.replace(temporary, path)
        finally:
            temporary.unlink(missing_ok=True)
        verify_sources(replaced + 1); verify_marker()
    fd, name = tempfile.mkstemp(prefix=".cef-marker-", dir=work)
    temporary = Path(name)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(expected + b"\n"); stream.flush(); os.fsync(stream.fileno())
        temporary.chmod(stat.S_IMODE(marker_before.st_mode))
        verify_sources(replaced=9); verify_marker(); os.replace(temporary, marker)
    finally:
        temporary.unlink(missing_ok=True)
    _, data, _ = _read(work, MARKER, 8192)
    if canonical(parse(data)) != expected:
        raise ValueError("Windows upgraded marker verification failed")
    verify_sources(replaced=9)
    return "upgraded-v14"


def _upgrade_v15(work: Path, expected: bytes, inputs: list) -> str:
    """Upgrade exact authenticated v15 state through its eight later corrections."""
    marker, marker_data, marker_before = _read(work, MARKER, 8192)
    previous = canonical({"schema": 1, "kind": "cef-windows-source-repair",
                          "build_key": V15_KEY, "source_repair": v15_profile()})
    if (canonical(parse(marker_data)) != previous or len(inputs) != 23
            or tuple(item[0] for item in inputs[15:]) != (CREDIT_CARD_HEADER, FRAME_TREE_HEADER, LOCK_MANAGER_HEADER, AFFILIATED_MATCH_SOURCE, BACKEND_ERROR_HEADER, BACKEND_ERROR_SOURCE, PERMISSION_MANAGER_HEADER, WATERMARK_HEADER)
            or any(original != changed for _, _, original, _, changed in inputs[:15])
            or any(original == changed for _, _, original, _, changed in inputs[15:])):
        raise ValueError("Windows v15 source/marker transition mismatch")
    def verify_marker():
        path, data, info = _read(work, MARKER, 8192)
        if path != marker or data != marker_data or _snapshot(info) != _snapshot(marker_before):
            raise ValueError("Windows v15 marker changed during upgrade")
    def verify_sources(replaced=0):
        for index, (relative, path, original, before, changed) in enumerate(inputs):
            current, data, info = _read(work, relative, source_limit(relative))
            is_new = 15 <= index < 15 + replaced
            if (current != path or data != (changed if is_new else original)
                    or (not is_new and _snapshot(info) != _snapshot(before))
                    or (is_new and info.st_mtime_ns <= before.st_mtime_ns)):
                raise ValueError("Windows v15 source changed during upgrade")
    for replaced, (relative, path, original, before, changed) in enumerate(inputs[15:]):
        fd, name = tempfile.mkstemp(prefix=".cef-header-", dir=path.parent)
        temporary = Path(name)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(changed); stream.flush(); os.fsync(stream.fileno())
            temporary.chmod(stat.S_IMODE(before.st_mode))
            new_time = max(time.time_ns(), before.st_mtime_ns + 1_000_000)
            os.utime(temporary, ns=(new_time, new_time))
            verify_sources(replaced); verify_marker(); os.replace(temporary, path)
        finally:
            temporary.unlink(missing_ok=True)
        verify_sources(replaced + 1); verify_marker()
    fd, name = tempfile.mkstemp(prefix=".cef-marker-", dir=work)
    temporary = Path(name)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(expected + b"\n"); stream.flush(); os.fsync(stream.fileno())
        temporary.chmod(stat.S_IMODE(marker_before.st_mode))
        verify_sources(replaced=8); verify_marker(); os.replace(temporary, marker)
    finally:
        temporary.unlink(missing_ok=True)
    _, data, _ = _read(work, MARKER, 8192)
    if canonical(parse(data)) != expected:
        raise ValueError("Windows upgraded marker verification failed")
    verify_sources(replaced=8)
    return "upgraded-v15"


def _upgrade_v16(work: Path, expected: bytes, inputs: list) -> str:
    """Upgrade exact authenticated V16 state through its seven later corrections."""
    marker, marker_data, marker_before = _read(work, MARKER, 8192)
    previous = canonical({"schema": 1, "kind": "cef-windows-source-repair",
                          "build_key": V16_KEY, "source_repair": v16_profile()})
    if (canonical(parse(marker_data)) != previous or len(inputs) != 23
            or tuple(item[0] for item in inputs[16:]) != (FRAME_TREE_HEADER, LOCK_MANAGER_HEADER, AFFILIATED_MATCH_SOURCE, BACKEND_ERROR_HEADER, BACKEND_ERROR_SOURCE, PERMISSION_MANAGER_HEADER, WATERMARK_HEADER)
            or any(original != changed for _, _, original, _, changed in inputs[:16])
            or any(original == changed for _, _, original, _, changed in inputs[16:])):
        raise ValueError("Windows v16 source/marker transition mismatch")
    def verify_marker():
        path, data, info = _read(work, MARKER, 8192)
        if path != marker or data != marker_data or _snapshot(info) != _snapshot(marker_before):
            raise ValueError("Windows v16 marker changed during upgrade")
    def verify_sources(replaced=0):
        for index, (relative, path, original, before, changed) in enumerate(inputs):
            current, data, info = _read(work, relative, source_limit(relative))
            is_new = 16 <= index < 16 + replaced
            if (current != path or data != (changed if is_new else original)
                    or (not is_new and _snapshot(info) != _snapshot(before))
                    or (is_new and info.st_mtime_ns <= before.st_mtime_ns)):
                raise ValueError("Windows v16 source changed during upgrade")
    for replaced, (relative, path, original, before, changed) in enumerate(inputs[16:]):
        fd, name = tempfile.mkstemp(prefix=".cef-header-", dir=path.parent)
        temporary = Path(name)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(changed); stream.flush(); os.fsync(stream.fileno())
            temporary.chmod(stat.S_IMODE(before.st_mode))
            new_time = max(time.time_ns(), before.st_mtime_ns + 1_000_000)
            os.utime(temporary, ns=(new_time, new_time))
            verify_sources(replaced); verify_marker(); os.replace(temporary, path)
        finally:
            temporary.unlink(missing_ok=True)
        verify_sources(replaced + 1); verify_marker()
    fd, name = tempfile.mkstemp(prefix=".cef-marker-", dir=work)
    temporary = Path(name)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(expected + b"\n"); stream.flush(); os.fsync(stream.fileno())
        temporary.chmod(stat.S_IMODE(marker_before.st_mode))
        verify_sources(replaced=7); verify_marker(); os.replace(temporary, marker)
    finally:
        temporary.unlink(missing_ok=True)
    _, data, _ = _read(work, MARKER, 8192)
    if canonical(parse(data)) != expected:
        raise ValueError("Windows upgraded marker verification failed")
    verify_sources(replaced=7)
    return "upgraded-v16"


def _upgrade_v19(work: Path, expected: bytes, inputs: list) -> str:
    """Upgrade qualified V19 state through its four later source corrections."""
    marker, marker_data, marker_before = _read(work, MARKER, 8192)
    previous = canonical({"schema": 1, "kind": "cef-windows-source-repair",
                          "build_key": V19_KEY, "source_repair": v19_profile()})
    if (canonical(parse(marker_data)) != previous or len(inputs) != 23
            or tuple(item[0] for item in inputs[19:]) != (BACKEND_ERROR_HEADER, BACKEND_ERROR_SOURCE, PERMISSION_MANAGER_HEADER, WATERMARK_HEADER)
            or any(original != changed for _, _, original, _, changed in inputs[:19])
            or any(original == changed for _, _, original, _, changed in inputs[19:])):
        raise ValueError("Windows v19 source/marker transition mismatch")
    def verify_marker():
        path, data, info = _read(work, MARKER, 8192)
        if path != marker or data != marker_data or _snapshot(info) != _snapshot(marker_before):
            raise ValueError("Windows v19 marker changed during upgrade")
    def verify_sources(replaced=0):
        for index, (relative, path, original, before, changed) in enumerate(inputs):
            current, data, info = _read(work, relative, source_limit(relative))
            is_new = 19 <= index < 19 + replaced
            if (current != path or data != (changed if is_new else original)
                    or (not is_new and _snapshot(info) != _snapshot(before))
                    or (is_new and info.st_mtime_ns <= before.st_mtime_ns)):
                raise ValueError("Windows v19 source changed during upgrade")
    for replaced, (relative, path, original, before, changed) in enumerate(inputs[19:]):
        fd, name = tempfile.mkstemp(prefix=".cef-header-", dir=path.parent)
        temporary = Path(name)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(changed); stream.flush(); os.fsync(stream.fileno())
            temporary.chmod(stat.S_IMODE(before.st_mode))
            new_time = max(time.time_ns(), before.st_mtime_ns + 1_000_000)
            os.utime(temporary, ns=(new_time, new_time))
            verify_sources(replaced); verify_marker(); os.replace(temporary, path)
        finally:
            temporary.unlink(missing_ok=True)
        verify_sources(replaced + 1); verify_marker()
    fd, name = tempfile.mkstemp(prefix=".cef-marker-", dir=work)
    temporary = Path(name)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(expected + b"\n"); stream.flush(); os.fsync(stream.fileno())
        temporary.chmod(stat.S_IMODE(marker_before.st_mode))
        verify_sources(replaced=4); verify_marker(); os.replace(temporary, marker)
    finally:
        temporary.unlink(missing_ok=True)
    _, data, _ = _read(work, MARKER, 8192)
    if canonical(parse(data)) != expected:
        raise ValueError("Windows upgraded marker verification failed")
    verify_sources(replaced=4)
    return "upgraded-v19"


def _upgrade_v21(work: Path, expected: bytes, inputs: list) -> str:
    """Upgrade qualified V21 state by adding only the watermark string include."""
    marker, marker_data, marker_before = _read(work, MARKER, 8192)
    previous = canonical({"schema": 1, "kind": "cef-windows-source-repair",
                          "build_key": V21_KEY, "source_repair": v21_profile()})
    if (canonical(parse(marker_data)) != previous or len(inputs) != 23
            or inputs[-1][0] != WATERMARK_HEADER
            or any(original != changed for _, _, original, _, changed in inputs[:22])
            or inputs[-1][2] == inputs[-1][4]):
        raise ValueError("Windows v21 source/marker transition mismatch")
    def verify_marker():
        path, data, info = _read(work, MARKER, 8192)
        if path != marker or data != marker_data or _snapshot(info) != _snapshot(marker_before):
            raise ValueError("Windows v21 marker changed during upgrade")
    def verify_sources(replaced=False):
        for index, (relative, path, original, before, changed) in enumerate(inputs):
            current, data, info = _read(work, relative, source_limit(relative))
            is_new = replaced and index == 22
            if (current != path or data != (changed if is_new else original)
                    or (not is_new and _snapshot(info) != _snapshot(before))
                    or (is_new and info.st_mtime_ns <= before.st_mtime_ns)):
                raise ValueError("Windows v21 source changed during upgrade")
    relative, path, original, before, changed = inputs[-1]
    fd, name = tempfile.mkstemp(prefix=".cef-header-", dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(changed); stream.flush(); os.fsync(stream.fileno())
        temporary.chmod(stat.S_IMODE(before.st_mode))
        new_time = max(time.time_ns(), before.st_mtime_ns + 1_000_000)
        os.utime(temporary, ns=(new_time, new_time))
        verify_sources(); verify_marker(); os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)
    verify_sources(replaced=True); verify_marker()
    fd, name = tempfile.mkstemp(prefix=".cef-marker-", dir=work)
    temporary = Path(name)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(expected + b"\n"); stream.flush(); os.fsync(stream.fileno())
        temporary.chmod(stat.S_IMODE(marker_before.st_mode))
        verify_sources(replaced=True); verify_marker(); os.replace(temporary, marker)
    finally:
        temporary.unlink(missing_ok=True)
    _, data, _ = _read(work, MARKER, 8192)
    if canonical(parse(data)) != expected:
        raise ValueError("Windows upgraded marker verification failed")
    verify_sources(replaced=True)
    return "upgraded-v21"
