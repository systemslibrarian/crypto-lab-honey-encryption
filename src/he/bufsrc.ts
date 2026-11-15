/**
 * WebCrypto's TypeScript surface wants `ArrayBufferView<ArrayBuffer>`, while a
 * plain `Uint8Array` is typed over `ArrayBufferLike` (which also admits a
 * SharedArrayBuffer). Every array in this lab is backed by a real ArrayBuffer,
 * so the narrowing is sound; it is collected here rather than scattered as
 * inline casts so there is one place to look at it.
 */
export function buf(a: Uint8Array): BufferSource {
  return a as unknown as BufferSource;
}
