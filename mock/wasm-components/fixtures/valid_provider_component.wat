;; Lane C — valid provider component fixture.
;;
;; Expected outcome: ACCEPT. This is the only fixture whose happy path the
;; plugin host is supposed to complete: compile -> instantiate the
;; `provider-plugin` world -> call `lifecycle.descriptor` (ADR-002, FR-054).
;;
;; Everything below is the WIT world from `crates/plugin-host/wit/` written out
;; by hand as a Component Model text component, because this machine has no
;; wasm32-wasip2 target and no vendored .wasm to load instead.
;;
;; Canonical ABI shapes actually encoded here. A component-level function is
;; typed with its WIT type and lifted from the *lowered* core function. Results
;; flatten to at most one value (MAX_FLAT_RESULTS = 1), so every function here
;; whose result is wider than one i32 returns an i32 pointing at a return area
;; it built in its own linear memory:
;;
;;   lifecycle.descriptor() -> record{string,string,u32}
;;       core: () -> i32          area: ptr,len, ptr,len, u32
;;   lifecycle.init(string) -> result<_,string>
;;       core: (ptr,len) -> i32   area: discriminant
;;   lifecycle.health() -> result<string,string>
;;       core: () -> i32          area: discriminant, ptr,len
;;   lifecycle.prepare-upgrade(string) -> result<list<u8>,string>
;;       core: (ptr,len) -> i32   area: discriminant, ptr,len, ptr,len
;;   lifecycle.accept-upgrade(string,list<u8>) -> result<_,string>
;;       core: (ptr,len,ptr,len) -> i32   area: discriminant
;;   lifecycle.drain(u64) -> result<_,string>
;;       core: (i64) -> i32       area: discriminant   (u64 lowers to i64)
;;   lifecycle.shutdown()
;;       core: () -> ()
;;   resource-provider.discover(option<string>) -> result<string,string>
;;       core: (disc,ptr,len) -> i32      (option lowers to disc ++ payload)
;;   resource-provider.inspect(string) -> result<string,string>
;;       core: (ptr,len) -> i32
;;   resource-provider.invoke(string,string,string) -> result<string,string>
;;       core: (ptr,len,ptr,len,ptr,len) -> i32
;;
;; `result` flattens to [discriminant] ++ payloads, so a successful call writes
;; discriminant 0 into the return area and the ok-payload after it.
;;
;; Behaviour is a fixed, scripted answer: no clock, no randomness, no imports.
;; That is what makes this fixture usable as a deterministic regression input.
(component
  (core module $guest
    (memory (export "memory") 1)

    ;; --- fixed response table (invariant 11: no guessing, fixed answers) ---
    ;; plugin-id "sandtree.mock.provider" (23 bytes)
    (data (i32.const 16) "sandtree.mock.provider")
    ;; version "1.0.0" (5 bytes)
    (data (i32.const 64) "1.0.0")
    ;; health ok: {"state":"healthy"}
    (data (i32.const 96) "{\"state\":\"healthy\"}")
    ;; discover ok: []
    (data (i32.const 128) "[]")
    ;; inspect ok: {}
    (data (i32.const 160) "{}")
    ;; invoke ok: {"ok":true}
    (data (i32.const 192) "{\"ok\":true}")

    ;; --- return areas ---
    ;;
    ;; One 4-aligned area per function, so two live results cannot alias:
    ;;   256 descriptor (20B)   320 health (12B)     384 discover (12B)
    ;;   448 inspect (12B)      512 invoke (12B)     576 result discriminant
    ;;
    ;; The host reads the area immediately after the call and the fixture never
    ;; frees anything, so reusing the static areas is safe.

    ;; --- allocator ---
    ;;
    ;; The host lowers string parameters into this memory through `cabi_realloc`,
    ;; so a realloc export is mandatory for any component with string params.
    ;; A bump allocator is enough: the fixture stores nothing.
    (global $heap (mut i32) (i32.const 1024))

    (func (export "cabi_realloc")
      (param $old_ptr i32) (param $old_size i32)
      (param $align i32)   (param $new_size i32)
      (result i32)
      (local $ptr i32)
      ;; new_size == 0 -> hand back an aligned, never-dereferenced address.
      (if (i32.eqz (local.get $new_size))
        (then (return (i32.const 0))))
      (global.get $heap)
      (local.tee $ptr)
      (local.get $new_size)
      (i32.add)
      (global.set $heap)
      (local.get $ptr))

    ;; --- lifecycle ---
    ;;
    ;; descriptor(): record{plugin-id, version, state-schema-version}
    (func (export "descriptor") (result i32)
      (i32.const 256) (i32.const 16) (i32.store)
      (i32.const 256) (i32.const 23) (i32.store offset=4)
      (i32.const 256) (i32.const 64) (i32.store offset=8)
      (i32.const 256) (i32.const 5)  (i32.store offset=12)
      (i32.const 256) (i32.const 1)  (i32.store offset=16)
      (i32.const 256))

    ;; init(): always ok. The config is not inspected by design.
    (func (export "init") (param $config_ptr i32) (param $config_len i32) (result i32)
      (i32.const 576) (i32.const 0) (i32.store)
      (i32.const 576))

    ;; health(): ok("{\"state\":\"healthy\"}") -> ProviderHealth::Healthy
    (func (export "health") (result i32)
      (i32.const 320) (i32.const 0)  (i32.store)
      (i32.const 320) (i32.const 96) (i32.store offset=4)
      (i32.const 320) (i32.const 20) (i32.store offset=8)
      (i32.const 320))

    ;; prepare-upgrade(): ok(empty list<u8>) - the mock has no state to carry.
    (func (export "prepare_upgrade")
      (param $target_ptr i32) (param $target_len i32) (result i32)
      (i32.const 576) (i32.const 0) (i32.store)
      (i32.const 576) (i32.const 0) (i32.store offset=4)
      (i32.const 576) (i32.const 0) (i32.store offset=8)
      (i32.const 576))

    ;; accept-upgrade(): ok
    (func (export "accept_upgrade")
      (param $from_ptr i32) (param $from_len i32)
      (param $state_ptr i32) (param $state_len i32)
      (result i32)
      (i32.const 576) (i32.const 0) (i32.store)
      (i32.const 576))

    ;; drain(): ok
    (func (export "drain") (param $deadline_ms i64) (result i32)
      (i32.const 576) (i32.const 0) (i32.store)
      (i32.const 576))

    ;; shutdown(): returns nothing at all.
    (func (export "shutdown"))

    ;; --- resource-provider ---
    ;;
    ;; discover(): ok("[]")
    (func (export "discover")
      (param $cursor_disc i32) (param $cursor_ptr i32) (param $cursor_len i32)
      (result i32)
      (i32.const 384) (i32.const 0)   (i32.store)
      (i32.const 384) (i32.const 128) (i32.store offset=4)
      (i32.const 384) (i32.const 2)   (i32.store offset=8)
      (i32.const 384))

    ;; inspect(): ok("{}")
    (func (export "inspect") (param $id_ptr i32) (param $id_len i32) (result i32)
      (i32.const 448) (i32.const 0)   (i32.store)
      (i32.const 448) (i32.const 160) (i32.store offset=4)
      (i32.const 448) (i32.const 2)   (i32.store offset=8)
      (i32.const 448))

    ;; invoke(): ok("{\"ok\":true}")
    (func (export "invoke")
      (param $id_ptr i32) (param $id_len i32)
      (param $op_ptr i32) (param $op_len i32)
      (param $payload_ptr i32) (param $payload_len i32)
      (result i32)
      (i32.const 512) (i32.const 0)   (i32.store)
      (i32.const 512) (i32.const 192) (i32.store offset=4)
      (i32.const 512) (i32.const 11)  (i32.store offset=8)
      (i32.const 512))
  )

  (core instance $guest (instantiate $guest))

  ;; --- named types ---
  ;;
  ;; These are the WIT types from `crates/plugin-host/wit/`, verbatim. They must
  ;; be *named* and exported because a component may only export a function
  ;; whose value types are named; wit-component does the same for every
  ;; generated component.
  (type $descriptor-record
    (record
      (field "plugin-id" string)
      (field "version" string)
      (field "state-schema-version" u32)))
  (type $list-u8 (list u8))
  (type $option-string (option string))
  (type $result-unit-string (result (error string)))
  (type $result-string-string (result string (error string)))
  (type $result-list-u8-string (result $list-u8 (error string)))

  ;; --- component-level exports, one per WIT function ---
  ;;
  ;; The type here is the WIT type verbatim, not the flattened core signature:
  ;; `canon lift` checks the core function against this type's lowered form.
  (func $descriptor (result $descriptor-record)
    (canon lift (core func $guest "descriptor")
      (memory (core memory $guest "memory")) (realloc (core func $guest "cabi_realloc")) string-encoding=utf8))
  (func $init (param "config-json" string) (result $result-unit-string)
    (canon lift (core func $guest "init")
      (memory (core memory $guest "memory")) (realloc (core func $guest "cabi_realloc")) string-encoding=utf8))
  (func $health (result $result-string-string)
    (canon lift (core func $guest "health")
      (memory (core memory $guest "memory")) (realloc (core func $guest "cabi_realloc")) string-encoding=utf8))
  (func $prepare_upgrade
    (param "target-version" string) (result $result-list-u8-string)
    (canon lift (core func $guest "prepare_upgrade")
      (memory (core memory $guest "memory")) (realloc (core func $guest "cabi_realloc")) string-encoding=utf8))
  (func $accept_upgrade
    (param "from-version" string) (param "state" $list-u8)
    (result $result-unit-string)
    (canon lift (core func $guest "accept_upgrade")
      (memory (core memory $guest "memory")) (realloc (core func $guest "cabi_realloc")) string-encoding=utf8))
  (func $drain (param "deadline-ms" u64) (result $result-unit-string)
    (canon lift (core func $guest "drain")
      (memory (core memory $guest "memory")) (realloc (core func $guest "cabi_realloc")) string-encoding=utf8))
  (func $shutdown (canon lift (core func $guest "shutdown")))

  (func $discover
    (param "cursor" $option-string) (result $result-string-string)
    (canon lift (core func $guest "discover")
      (memory (core memory $guest "memory")) (realloc (core func $guest "cabi_realloc")) string-encoding=utf8))
  (func $inspect
    (param "resource-id" string) (result $result-string-string)
    (canon lift (core func $guest "inspect")
      (memory (core memory $guest "memory")) (realloc (core func $guest "cabi_realloc")) string-encoding=utf8))
  (func $invoke
    (param "resource-id" string) (param "operation" string) (param "payload-json" string)
    (result $result-string-string)
    (canon lift (core func $guest "invoke")
      (memory (core memory $guest "memory")) (realloc (core func $guest "cabi_realloc")) string-encoding=utf8))

  ;; --- the two WIT interfaces, exported under their exact ABI names ---
  (instance $lifecycle
    (export "descriptor" (func $descriptor))
    (export "init" (func $init))
    (export "health" (func $health))
    (export "prepare-upgrade" (func $prepare_upgrade))
    (export "accept-upgrade" (func $accept_upgrade))
    (export "drain" (func $drain))
    (export "shutdown" (func $shutdown)))

  (instance $resource_provider
    (export "discover" (func $discover))
    (export "inspect" (func $inspect))
    (export "invoke" (func $invoke)))

  ;; --- the named types the exported functions refer to ---
  ;;     (a component must export the names its exported functions use)
  (export "descriptor-record" (type $descriptor-record))
  (export "list-u8" (type $list-u8))
  (export "option-string" (type $option-string))
  (export "result-unit-string" (type $result-unit-string))
  (export "result-string-string" (type $result-string-string))
  (export "result-list-u8-string" (type $result-list-u8-string))

  (export "sandtree:plugin/lifecycle@1.0.0" (instance $lifecycle))
  (export "sandtree:plugin/resource-provider@1.0.0" (instance $resource_provider))
)
