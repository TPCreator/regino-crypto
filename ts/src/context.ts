/**
 * Structured contexts (since 0.17.0, audit validation 2026-11-25, L-01): one unambiguous context string
 * from several parts – the same bytes as `regino_keys::context::structured` in Rust.
 *
 * A context made by joining ids with a separator (`<app>|event|<id>`) is unambiguous only if no id can
 * contain the separator; `a|b` + `c` and `a` + `b|c` would otherwise give the same context. Here every part
 * carries its length in UTF-8 bytes, so any text – separators included – is safe:
 *
 * `rg-ctx1` ‖ for every part: `|` ‖ decimal byte length ‖ `:` ‖ part
 *
 * e.g. `["gazda", "event", "7f3a"]` → `rg-ctx1|5:gazda|5:event|4:7f3a`. Shared vectors:
 * `testvectors/regino/context-0.17.0.json`.
 *
 * This is an **addition**: existing contexts of the apps stay as they are (changing the context of stored data
 * makes it unreadable). An app uses it for new kinds of data, or migrates by re-sealing.
 */

/** Prefix of every structured context. */
export const CONTEXT_PREFIX = 'rg-ctx1';

/** At most this many bytes of UTF-8 in the whole context (as `MAX_CONTEXT` of signatures). */
export const MAX_CONTEXT_LEN = 1024;

const enc = new TextEncoder();
const dec = new TextDecoder('utf-8', { ignoreBOM: true });

/**
 * Builds the context from `parts`: at least one, every part a non-empty well-formed string (a lone surrogate
 * would be encoded as U+FFFD and could collide with another part), the result at most `MAX_CONTEXT_LEN` bytes.
 */
export function structuredContext(parts: readonly string[]): string {
  if (!Array.isArray(parts) || parts.length === 0) throw new Error('A structured context needs at least one part.');
  let out = CONTEXT_PREFIX;
  let len = CONTEXT_PREFIX.length;
  for (const p of parts) {
    if (typeof p !== 'string' || p === '') throw new Error('A part of a context must be a non-empty string.');
    const b = enc.encode(p);
    if (dec.decode(b) !== p) throw new Error('A part of a context must be valid text.');
    const piece = `|${b.length}:`;
    len += piece.length + b.length;
    if (len > MAX_CONTEXT_LEN) throw new Error(`A context may have at most ${MAX_CONTEXT_LEN} bytes.`);
    out += piece + p;
  }
  return out;
}
