"""Step 0: provider smoke test. 10-token call per model; report live/dead."""
import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).parent))
import providers as P

def main():
    out = {}
    for key in P.MODELS:
        r = P.call_model(
            key, "Reply with one word.", [{"role": "user", "content": "Say OK."}],
            payload_id="smoke", turn=0, max_tokens=10, use_cache=False, max_retries=2,
        )
        live = r["error"] is None and r["text"].strip() != ""
        out[key] = {
            "live": live,
            "api_model": P.MODELS[key]["api_model"],
            "provider": P.MODELS[key]["provider"],
            "family": P.MODELS[key]["family"],
            "text": r["text"].strip()[:60],
            "error": r["error"],
        }
        print(f"{'LIVE' if live else 'DEAD'}  {key:20s} {P.MODELS[key]['api_model']:42s} {r['text'].strip()[:40] or r['error']}")
    p = P.ROOT / "results" / "smoke.json"
    p.write_text(json.dumps(out, indent=2))
    print(f"\ncalls used: {P.calls_used()}/{P.CALL_BUDGET}")
    return out

if __name__ == "__main__":
    main()
