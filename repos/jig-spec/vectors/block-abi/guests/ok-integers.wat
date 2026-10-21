;; Returns ok with a 20-byte body: ingest-seq and ingest-hlc.wall-ms as little-endian
;; u64s, then ingest-hlc.logical as a little-endian u32, so integer lowering shows up.
;;
;; A `jig:block/renderer@0.1.0` component written by hand: one core module behind the
;; canonical ABI. `render` receives the invocation's 13 flattened parameters:
;;   0-1 block-cid, 2-3 sender-did, 4-5 channel-cid (pointer, length),
;;   6 ingest-seq (i64), 7 ingest-hlc.wall-ms (i64), 8 ingest-hlc.logical (i32),
;;   9-10 input.media-type, 11-12 input.body (pointer, length)
;; and returns a pointer to the lowered `result<payload, block-error>`: discriminant byte at +0,
;; then at +4 either the payload (media-type pointer, length, body pointer, length) or the
;; block-error (case byte at +4, message pointer and length at +8 and +12).
(component
  (type $hlc (record (field "wall-ms" u64) (field "logical" u32)))
  (type $payload (record (field "media-type" string) (field "body" (list u8))))
  (type $invocation (record
    (field "block-cid" string)
    (field "sender-did" string)
    (field "channel-cid" string)
    (field "ingest-seq" u64)
    (field "ingest-hlc" $hlc)
    (field "input" $payload)))
  (type $block-error (variant (case "invalid-input" string) (case "failed" string)))
  (type $render (func (param "inv" $invocation)
    (result (result $payload (error $block-error)))))

  (core module $m
    (memory (export "memory") 1 1)
    (global $bump (mut i32) (i32.const 4096))
    ;; A bump allocator, enough for the host to lower the invocation.
    (func (export "realloc") (param i32 i32 i32 i32) (result i32)
      (local $p i32)
      (local.set $p (global.get $bump))
      (global.set $bump (i32.add (global.get $bump) (local.get 3)))
      (local.get $p))
    (func (export "render")
      (param i32 i32 i32 i32 i32 i32 i64 i64 i32 i32 i32 i32 i32)
      (result i32)
      (i64.store (i32.const 512) (local.get 6))
      (i64.store (i32.const 520) (local.get 7))
      (i32.store (i32.const 528) (local.get 8))
      (i32.store8 (i32.const 256) (i32.const 0))
      (i32.store (i32.const 268) (i32.const 512))
      (i32.store (i32.const 272) (i32.const 20))
      (i32.const 256)))
  (core instance $i (instantiate $m))
  (alias core export $i "memory" (core memory $mem))
  (func $render-lifted (type $render)
    (canon lift (core func $i "render")
      (memory $mem) (realloc (core func $i "realloc"))))
  (instance $exports
    (export "hlc" (type $hlc))
    (export "payload" (type $payload))
    (export "invocation" (type $invocation))
    (export "block-error" (type $block-error))
    (export "render" (func $render-lifted)))
  (export "jig:block/render@0.1.0" (instance $exports)))
