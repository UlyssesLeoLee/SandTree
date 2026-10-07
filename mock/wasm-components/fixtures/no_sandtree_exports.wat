;; Lane C — no-sandtree-exports component fixture.
;;
;; Expected outcome: REJECT with ST-PLG-001. A perfectly valid Component Model
;; component that exports nothing SandTree knows about: no `lifecycle`, no
;; `resource-provider`, no import. It compiles, so it exercises the stage the
;; other fixtures cannot — "valid WASM, wrong ABI" as opposed to "not WASM at
;; all". It is the floor case behind the host's "needs lifecycle and
;; resource-provider@1.0.0" message.
(component
  (core module $guest
    (memory (export "memory") 1)
    (func (export "ping") (result i32)
      (i32.const 42)))
  (core instance $guest (instantiate $guest))
  (func $ping (result i32)
    (canon lift (core func $guest "ping")))
  (export "ping" (func $ping))
)
