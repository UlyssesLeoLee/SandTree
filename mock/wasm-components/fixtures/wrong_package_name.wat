;; Lane C — wrong-package-name component fixture.
;;
;; Expected outcome: REJECT. `verify_component_package("evil:plugin@1.0.0")`
;; must fail with ST-PLG-001, and the `provider-plugin` world must not
;; instantiate because it exports neither required interface.
;;
;; This file is byte-for-byte the valid fixture except for the two interface
;; export names, which carry a foreign namespace. That is deliberate: the only
;; thing wrong with this package is its namespace, so any other difference
;; would make the fixture ambiguous about *why* it is rejected.
;; `fixtures_differ_from_the_valid_one_only_where_intended` locks that down.
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
    (func (export "descriptor") (param $ret i32)
      (local.get $ret) (i32.const 16)  (i32.store)
      (local.get $ret) (i32.const 23)  (i32.store offset=4)
      (local.get $ret) (i32.const 64)  (i32.store offset=8)
      (local.get $ret) (i32.const 5)   (i32.store offset=12)
      (local.get $ret) (i32.const 1)   (i32.store offset=16))

    ;; init(): always ok. The config is not inspected by design.
    (func (export "init") (param $ptr i32) (param $len i32) (param $ret i32)
      (local.get $ret) (i32.const 0) (i32.store))

    ;; health(): ok("{\"state\":\"healthy\"}") -> ProviderHealth::Healthy
    (func (export "health") (param $ret i32)
      (local.get $ret) (i32.const 0)  (i32.store)
      (local.get $ret) (i32.const 96) (i32.store offset=4)
      (local.get $ret) (i32.const 20) (i32.store offset=8))

    ;; prepare-upgrade(): ok(empty list<u8>) - the mock has no state to carry.
    (func (export "prepare_upgrade")
      (param $ptr i32) (param $len i32) (param $ret i32)
      (local.get $ret) (i32.const 0) (i32.store)
      (local.get $ret) (i32.const 0) (i32.store offset=4)
      (local.get $ret) (i32.const 0) (i32.store offset=8))

    ;; accept-upgrade(): ok
    (func (export "accept_upgrade")
      (param $from_ptr i32) (param $from_len i32)
      (param $state_ptr i32) (param $state_len i32)
      (param $ret i32)
      (local.get $ret) (i32.const 0) (i32.store))

    ;; drain(): ok
    (func (export "drain")
      (param $deadline_lo i32) (param $deadline_hi i32) (param $ret i32)
      (local.get $ret) (i32.const 0) (i32.store))

    ;; shutdown(): returns nothing at all.
    (func (export "shutdown"))

    ;; --- resource-provider ---
    ;;
    ;; discover(): ok("[]")
    (func (export "discover")
      (param $cursor_disc i32) (param $cursor_ptr i32) (param $cursor_len i32)
      (param $ret i32)
      (local.get $ret) (i32.const 0)   (i32.store)
      (local.get $ret) (i32.const 128) (i32.store offset=4)
      (local.get $ret) (i32.const 2)   (i32.store offset=8))

    ;; inspect(): ok("{}")
    (func (export "inspect") (param $id_ptr i32) (param $id_len i32) (param $ret i32)
      (local.get $ret) (i32.const 0)   (i32.store)
      (local.get $ret) (i32.const 160) (i32.store offset=4)
      (local.get $ret) (i32.const 2)   (i32.store offset=8))

    ;; invoke(): ok("{\"ok\":true}")
    (func (export "invoke")
      (param $id_ptr i32) (param $id_len i32)
      (param $op_ptr i32) (param $op_len i32)
      (param $payload_ptr i32) (param $payload_len i32)
      (param $ret i32)
      (local.get $ret) (i32.const 0)   (i32.store)
      (local.get $ret) (i32.const 192) (i32.store offset=4)
      (local.get $ret) (i32.const 11)  (i32.store offset=8))
  )

  (core instance $guest (instantiate $guest))

  ;; --- component-level exports, one per WIT function ---
  (func $descriptor (param i32)
    (canon lift (core func $guest "descriptor")
      (memory (memory $guest "memory")) (realloc (core func $guest "cabi_realloc")) string-encoding=utf8))
  (func $init (param i32 i32 i32)
    (canon lift (core func $guest "init")
      (memory (memory $guest "memory")) (realloc (core func $guest "cabi_realloc")) string-encoding=utf8))
  (func $health (param i32)
    (canon lift (core func $guest "health")
      (memory (memory $guest "memory")) (realloc (core func $guest "cabi_realloc")) string-encoding=utf8))
  (func $prepare_upgrade (param i32 i32 i32)
    (canon lift (core func $guest "prepare_upgrade")
      (memory (memory $guest "memory")) (realloc (core func $guest "cabi_realloc")) string-encoding=utf8))
  (func $accept_upgrade (param i32 i32 i32 i32 i32)
    (canon lift (core func $guest "accept_upgrade")
      (memory (memory $guest "memory")) (realloc (core func $guest "cabi_realloc")) string-encoding=utf8))
  (func $drain (param i32 i32 i32)
    (canon lift (core func $guest "drain")
      (memory (memory $guest "memory")) (realloc (core func $guest "cabi_realloc")) string-encoding=utf8))
  (func $shutdown (canon lift (core func $guest "shutdown")))

  (func $discover (param i32 i32 i32 i32)
    (canon lift (core func $guest "discover")
      (memory (memory $guest "memory")) (realloc (core func $guest "cabi_realloc")) string-encoding=utf8))
  (func $inspect (param i32 i32 i32)
    (canon lift (core func $guest "inspect")
      (memory (memory $guest "memory")) (realloc (core func $guest "cabi_realloc")) string-encoding=utf8))
  (func $invoke (param i32 i32 i32 i32 i32 i32 i32)
    (canon lift (core func $guest "invoke")
      (memory (memory $guest "memory")) (realloc (core func $guest "cabi_realloc")) string-encoding=utf8))

  ;; --- the two WIT interfaces, under a namespace this host does not own ---
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

  (export "evil:plugin/lifecycle@1.0.0" (instance $lifecycle))
  (export "evil:plugin/resource-provider@1.0.0" (instance $resource_provider))
)
