"""Full ciphertext scan: encoding layers, symbol class, and family affinity scoring."""

from __future__ import annotations

import base64
import re
from dataclasses import dataclass, field
from typing import Any, Literal

from cipherops.analysis.autokey_solver import _english_score, brute_force_autokey_seed
from cipherops.analysis.coset_ic import coset_ic_profile
from cipherops.analysis.deck_parse import parse_integer_decks
from cipherops.analysis.fingerprint import ENGLISH_IC, RANDOM_IC_26, fingerprint_metrics
from cipherops.analysis.kasiski import kasiski_examination
from cipherops.analysis.stream import normalize_stream
from cipherops.ciphers import encoding
from cipherops.ciphers.classical import caesar

ScanLayerKind = Literal["raw", "encoding", "payload"]


@dataclass
class ScanHit:
    family: str
    label: str
    score: float
    layer: ScanLayerKind
    metrics: dict[str, Any] = field(default_factory=dict)
    reasoning: list[str] = field(default_factory=list)
    needs_conversion: bool = False
    inner_payload: str | None = None
    propagator: str | None = None
    dash_mode: str = "custom"
    dataset_slug: str | None = None
    hypothesis: dict[str, Any] = field(default_factory=dict)
    deck_size: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "family": self.family,
            "label": self.label,
            "score": round(self.score, 4),
            "layer": self.layer,
            "metrics": self.metrics,
            "reasoning": self.reasoning,
            "needs_conversion": self.needs_conversion,
            "inner_payload": self.inner_payload,
            "propagator": self.propagator,
            "dash_mode": self.dash_mode,
            "dataset_slug": self.dataset_slug,
            "hypothesis": self.hypothesis,
            "deck_size": self.deck_size,
        }


def _ic_band(ic: float, *, alphabet_size: int = 26) -> str:
    random_ic = 1.0 / alphabet_size if alphabet_size > 1 else RANDOM_IC_26
    if ic >= ENGLISH_IC - 0.008:
        return "language_like"
    if ic <= random_ic + 0.012:
        return "flat_polyalphabetic"
    return "intermediate"


def _coset_lift_score(text: str) -> float:
    """0–1 score: high when a period shows English-like coset IC (Vigenère signal)."""
    profile = coset_ic_profile(text, max_period=20)
    best_ic = profile.get("best_mean_ic")
    if best_ic is None:
        return 0.0
    # Lift above random toward English
    lift = (best_ic - RANDOM_IC_26) / (ENGLISH_IC - RANDOM_IC_26)
    return max(0.0, min(1.0, lift))


def _probe_encoding_layers(raw: str) -> list[ScanHit]:
    hits: list[ScanHit] = []
    stripped = re.sub(r"\s+", "", raw)

    # Hex — must decode to plausible UTF-8 inner text
    if re.fullmatch(r"[0-9a-fA-F]+", stripped) and len(stripped) >= 8 and len(stripped) % 2 == 0:
        try:
            inner = encoding.hex_decode(raw)
            inner_score = _english_score(inner) / 6.0 if inner.isalpha() or " " in inner else 0.5
            hits.append(
                ScanHit(
                    family="hex",
                    label="Hex encoding (validated decode)",
                    score=min(0.95, 0.55 + inner_score * 0.35),
                    layer="encoding",
                    needs_conversion=True,
                    inner_payload=inner[:200],
                    metrics={"decode_ok": True, "inner_english": round(_english_score(inner), 4)},
                    reasoning=[
                        "Even-length hex decodes to UTF-8",
                        "Re-classify inner payload after decode",
                    ],
                )
            )
        except (ValueError, UnicodeDecodeError):
            hits.append(
                ScanHit(
                    family="hex_rejected",
                    label="Hex-shaped but decode failed",
                    score=0.08,
                    layer="encoding",
                    metrics={"decode_ok": False},
                    reasoning=["Matches [0-9A-F] but is not valid byte-pair hex encoding"],
                )
            )

    # Base64
    if re.fullmatch(r"[A-Za-z0-9+/=]+", stripped) and len(stripped) >= 8:
        try:
            inner = encoding.base64_decode(stripped)
            inner_score = _english_score(inner) / 6.0 if any(ch.isalpha() for ch in inner) else 0.4
            hits.append(
                ScanHit(
                    family="base64",
                    label="Base64 encoding (validated decode)",
                    score=min(0.93, 0.5 + inner_score * 0.4),
                    layer="encoding",
                    needs_conversion=True,
                    inner_payload=inner[:200],
                    metrics={"decode_ok": True, "inner_english": round(_english_score(inner), 4)},
                    reasoning=["Base64 decodes to UTF-8 — scan inner layer next"],
                )
            )
        except Exception:
            pass

    # PAM-5 / 0-3 symbol stream
    if re.fullmatch(r"[0-3]+", stripped) and len(stripped) >= 4:
        try:
            inner = encoding.pam5_decode(stripped)
            hits.append(
                ScanHit(
                    family="pam5",
                    label="PAM-5 dibit encoding (0–3 alphabet)",
                    score=0.88,
                    layer="encoding",
                    needs_conversion=True,
                    inner_payload=inner[:200],
                    metrics={"decode_ok": True, "symbol_range": "0-3"},
                    reasoning=["Symbols 0–3 decode via PAM-5 dibit framing"],
                )
            )
        except ValueError:
            hits.append(
                ScanHit(
                    family="pam5_raw",
                    label="PAM-5 symbol stream (0–3, not framed payload)",
                    score=0.72,
                    layer="raw",
                    metrics={"symbol_range": "0-3", "decode_ok": False},
                    reasoning=["Alphabet size 4 — integer deck or PAM-5 without length prefix"],
                )
            )

    return hits


def _scan_integer_decks(decks: list[list[int]], deck_size: int) -> list[ScanHit]:
    hits: list[ScanHit] = []
    n_msgs = len(decks)
    flat = [v for row in decks for v in row]
    stream = normalize_stream(flat, deck_size=deck_size)
    fp = fingerprint_metrics(stream.text, symbol_class="integer")
    ic = fp.get("index_of_coincidence", 0.0)

    base_reason = [
        f"{n_msgs} message(s), deck size ≈ {deck_size}",
        f"symbol range 0–{max(flat) if flat else 0}",
        f"IC={ic:.4f} on pooled symbols",
    ]

    if deck_size == 83 and n_msgs >= 2:
        hits.append(
            ScanHit(
                family="noita_shared_keystream",
                label="Noita-style shared depth keystream (mod 83)",
                score=0.92 if n_msgs == 9 else 0.82,
                layer="payload",
                propagator="shared_keystream",
                dash_mode="noita" if n_msgs == 9 else "custom",
                deck_size=83,
                hypothesis={"combiner": "add", "family": "shared_keystream"},
                metrics={"num_messages": n_msgs, "deck_size": deck_size, "index_of_coincidence": ic},
                reasoning=base_reason + ["Deck size 83 matches Noita eye corpus"],
            )
        )
    else:
        hits.append(
            ScanHit(
                family="shared_keystream",
                label=f"Integer deck / shared keystream (mod {deck_size})",
                score=0.78 if n_msgs >= 2 else 0.65,
                layer="payload",
                propagator="shared_keystream",
                dash_mode="custom",
                deck_size=deck_size,
                hypothesis={"combiner": "add"},
                metrics={"num_messages": n_msgs, "deck_size": deck_size, "index_of_coincidence": ic},
                reasoning=base_reason,
            )
        )

    if deck_size <= 5:
        hits.append(
            ScanHit(
                family="small_alphabet_deck",
                label=f"Small-integer alphabet (mod {deck_size}) — not hex",
                score=0.85,
                layer="raw",
                metrics={"deck_size": deck_size, "not_hex": True},
                reasoning=[
                    f"Values use alphabet 0–{deck_size - 1}",
                    "Not hexadecimal byte encoding (no A–F, not nybble pairs)",
                ],
            )
        )

    return hits


def _scan_alpha_payload(text: str, *, layer: ScanLayerKind = "payload") -> list[ScanHit]:
    hits: list[ScanHit] = []
    stream = normalize_stream(text)
    if stream.symbol_class != "alpha":
        return hits

    alpha = stream.text
    fp = fingerprint_metrics(alpha, symbol_class="alpha")
    kas = kasiski_examination(alpha)
    ic = fp.get("index_of_coincidence", 0.0)
    band = _ic_band(ic)
    coset_lift = _coset_lift_score(alpha)
    periods = kas.get("candidate_key_lengths") or []
    top_period = kas.get("strongest_period") or (periods[0] if periods else None)

    metrics_base = {
        "index_of_coincidence": round(ic, 4),
        "ic_band": band,
        "coset_lift": round(coset_lift, 4),
        "kasiski_period": top_period,
        "shannon_entropy_bits": fp.get("shannon_entropy_bits"),
    }

    if band == "language_like":
        best_shift, best_score = 0, float("-inf")
        for shift in range(26):
            plain = caesar(text, -shift)
            sc = _english_score(plain)
            if sc > best_score:
                best_score, best_shift = sc, shift
        hits.append(
            ScanHit(
                family="monoalphabetic",
                label="Monoalphabetic / transposition (language-like IC)",
                score=0.7 + min(0.2, (ic - 0.06) * 2),
                layer=layer,
                dash_mode="fingerprinted",
                dataset_slug="substitution-qwerty",
                metrics={**metrics_base, "best_caesar_shift": best_shift, "caesar_score": round(best_score, 4)},
                reasoning=[f"IC={ic:.4f} ≈ English", f"Best ROT score={best_score:.2f} @ shift {best_shift}"],
            )
        )
        hits.append(
            ScanHit(
                family="caesar",
                label=f"Caesar / ROT (best shift {best_shift})",
                score=0.45 + min(0.35, best_score / 15.0),
                layer=layer,
                dash_mode="fingerprinted",
                dataset_slug="caesar-rot13",
                metrics={**metrics_base, "best_caesar_shift": best_shift, "caesar_score": round(best_score, 4)},
                reasoning=[f"Language-like IC — ROT{best_shift} English score {best_score:.2f}"],
            )
        )

    if band == "flat_polyalphabetic":
        if top_period and coset_lift >= 0.35:
            hits.append(
                ScanHit(
                    family="vigenere",
                    label=f"Vigenère / periodic (period ≈ {top_period}, coset lift {coset_lift:.2f})",
                    score=0.55 + coset_lift * 0.25,
                    layer=layer,
                    dash_mode="fingerprinted",
                    dataset_slug="vigenere-keyword",
                    metrics={**metrics_base, "coset_lift": round(coset_lift, 4)},
                    reasoning=[
                        f"IC={ic:.4f} flat",
                        f"Kasiski period {top_period}",
                        f"Coset IC lift {coset_lift:.2f} supports periodic polyalphabetic",
                    ],
                )
            )

        ak_hits: list[dict] = []
        if len(alpha) >= 12:
            try:
                ak_hits = brute_force_autokey_seed(text, 3, top_n=1)
            except ValueError:
                ak_hits = []
        ak_score = ak_hits[0]["score"] if ak_hits else 0.0
        hits.append(
            ScanHit(
                family="autokey",
                label="Autokey / non-periodic polyalphabetic",
                score=0.48 + min(0.25, ak_score / 20.0) if not top_period else 0.38,
                layer=layer,
                propagator="stream_extension",
                dash_mode="custom",
                hypothesis={"family": "autokey", "variant": "standard", "extension": "plaintext", "seed_length": 3},
                metrics={**metrics_base, "autokey_probe_score": round(ak_score, 4)},
                reasoning=[
                    f"IC={ic:.4f} flat",
                    f"Autokey seed-3 probe English score {ak_score:.2f}",
                    "Weak/no coset lift" if coset_lift < 0.35 else "Coset lift weaker than Vigenère",
                ],
            )
        )
        hits.append(
            ScanHit(
                family="gak",
                label="GAK / dynamic permutation (Eyes)",
                score=0.32 + (0.1 if coset_lift < 0.2 else 0.0),
                layer=layer,
                propagator="dynamic_perm",
                dash_mode="custom",
                hypothesis={"mode": "ctak_right"},
                metrics=metrics_base,
                reasoning=["Flat IC compatible with dynamic perm — needs plaintext/seed to confirm"],
            )
        )

    if band == "intermediate":
        hits.append(
            ScanHit(
                family="polyalphabetic_mixed",
                label="Polyalphabetic (intermediate IC)",
                score=0.5,
                layer=layer,
                propagator="stream_extension",
                dash_mode="custom",
                hypothesis={"family": "autokey", "seed_length": 3},
                metrics=metrics_base,
                reasoning=[f"IC={ic:.4f} between random and English — short text or mixed regime"],
            )
        )

    if not hits:
        hits.append(
            ScanHit(
                family="unknown_alpha",
                label="Alphabetic — insufficient family signal",
                score=0.25,
                layer=layer,
                metrics=metrics_base,
                reasoning=[f"IC={ic:.4f}, length={len(alpha)}"],
            )
        )

    return hits


def full_scan(ciphertext: str | list | None = None, *, deck_size: int | None = None) -> dict[str, Any]:
    """
    Scan raw input through encoding-layer probes and family affinity metrics.

    Returns ranked hits plus ``has_more`` when an encoding wrapper should be peeled first.
    """
    if ciphertext is None or (isinstance(ciphertext, str) and not str(ciphertext).strip()):
        return {"hits": [], "profile": {"error": "empty input"}, "has_more": False, "layers": []}

    raw = str(ciphertext).strip() if isinstance(ciphertext, str) else ciphertext
    all_hits: list[ScanHit] = []
    layers_trace: list[dict[str, Any]] = [{"stage": "raw", "preview": str(raw)[:120]}]

    # Integer decks first (fixes 0-4 vs hex)
    parsed = parse_integer_decks(raw if isinstance(raw, str) else raw)
    if parsed is not None:
        decks, inferred = parsed
        size = deck_size or inferred
        int_hits = _scan_integer_decks(decks, size)
        all_hits.extend(int_hits)
        layers_trace.append({"stage": "integer_deck", "deck_size": size, "messages": len(decks)})
        hits_sorted = sorted(all_hits, key=lambda h: h.score, reverse=True)
        return _package_scan(hits_sorted, layers_trace, symbol_class="integer")

    text = str(raw)
    stream = normalize_stream(text)
    layers_trace.append({"stage": "symbol_class", "class": stream.symbol_class, "alphabet_size": stream.alphabet_size})

    # Encoding probes (only when not already classified as integer)
    enc_hits = _probe_encoding_layers(text)
    all_hits.extend(enc_hits)

    # Scan inner payloads from successful encoding decodes
    for enc in enc_hits:
        if enc.needs_conversion and enc.inner_payload and enc.metrics.get("decode_ok"):
            inner_hits = _scan_alpha_payload(enc.inner_payload, layer="payload")
            for ih in inner_hits:
                ih.score *= 0.95  # slight discount — depends on outer peel
                ih.reasoning = [f"Inner payload after {enc.family}"] + ih.reasoning
            all_hits.extend(inner_hits)
            layers_trace.append({"stage": "inner", "via": enc.family, "preview": enc.inner_payload[:80]})

    if stream.symbol_class == "alpha":
        all_hits.extend(_scan_alpha_payload(text, layer="payload"))
    elif stream.symbol_class == "hex":
        # Should rarely happen now; keep low-confidence reject if no valid decode hit
        if not any(h.family == "hex" and h.metrics.get("decode_ok") for h in enc_hits):
            all_hits.append(
                ScanHit(
                    family="hex_rejected",
                    label="Hex-shaped input — decode not validated",
                    score=0.1,
                    layer="raw",
                    reasoning=["Treat as integer deck or raw digits unless UTF-8 decode succeeds"],
                )
            )
    elif stream.symbol_class not in ("base64",):
        all_hits.append(
            ScanHit(
                family="unknown",
                label=f"Unclassified ({stream.symbol_class})",
                score=0.3,
                layer="raw",
                reasoning=[f"Symbol class: {stream.symbol_class}"],
            )
        )

    hits_sorted = sorted(all_hits, key=lambda h: h.score, reverse=True)
    return _package_scan(hits_sorted, layers_trace, symbol_class=stream.symbol_class)


def _package_scan(hits: list[ScanHit], layers: list[dict], *, symbol_class: str) -> dict[str, Any]:
    top = hits[0] if hits else None
    has_more = any(h.needs_conversion for h in hits if h.score >= 0.5)
    encoding_peel = next((h for h in hits if h.needs_conversion and h.metrics.get("decode_ok")), None)

    profile: dict[str, Any] = {
        "symbol_class": symbol_class,
        "scan_mode": "full",
        "hit_count": len(hits),
        "has_more_layers": has_more,
    }
    if encoding_peel:
        profile["peel_first"] = encoding_peel.family
        profile["inner_preview"] = (encoding_peel.inner_payload or "")[:120]

    if top:
        profile.update(top.metrics)

    return {
        "hits": [h.to_dict() for h in hits[:12]],
        "hypotheses": [_hit_to_hypothesis(h) for h in hits[:6]],
        "top": _hit_to_hypothesis(top) if top else None,
        "profile": profile,
        "layers": layers,
        "has_more": has_more,
    }


def _hit_to_hypothesis(h: ScanHit) -> dict[str, Any]:
    return {
        "family": h.family,
        "label": h.label,
        "confidence": h.score,
        "propagator": h.propagator or "none",
        "dash_mode": h.dash_mode,
        "dash_propagator": h.propagator,
        "dataset_slug": h.dataset_slug,
        "deck_size": h.deck_size,
        "hypothesis": h.hypothesis,
        "reasoning": h.reasoning,
        "actions": _actions_for_hit(h),
        "needs_conversion": h.needs_conversion,
        "inner_payload": h.inner_payload,
        "metrics": h.metrics,
    }


def _actions_for_hit(h: ScanHit) -> list[str]:
    if h.needs_conversion:
        return [f"Decode {h.family} layer, then re-scan inner payload"]
    if h.propagator == "shared_keystream":
        return ["Route → shared_keystream propagator", "Add crib pins at known depths"]
    if h.propagator == "stream_extension":
        return ["Route → autokey propagator", "Brute short seed or add plaintext crib"]
    if h.propagator == "dynamic_perm":
        return ["Route → GAK propagator", "Provide plaintext trial + PRNG seed sweep"]
    if h.dataset_slug:
        return [f"Open fingerprinted corpus {h.dataset_slug}"]
    return ["Review metrics and try next hypothesis"]
