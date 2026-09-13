# Limitations

- **We measure attempt, not success past network controls.** The oracle detects that the
  agent placed the canary in an outbound tool argument. Whether that request would actually
  egress depends on network controls (allow-lists, DLP, egress proxies) that a real
  deployment may or may not have. We deliberately enforce nothing; the claim is about the
  model's *behavior*, not about end-to-end data loss.

- **Simulated tool surface.** Tools return canned data and never touch the network. A real
  contact-center integration would present richer, noisier tool outputs and additional
  egress channels (email, ticket updates, webhooks) that could raise or lower the observed
  rate.

- **Single trial per cell at temperature 0.** Each cell is run once. Hosted inference at
  temperature 0 is not perfectly deterministic (we observed one such case directly), so a
  single trial can miss behavior that repeated sampling would reveal. Variance is estimated
  by resampling the payload corpus, not the sampling process, so the reported CIs capture
  payload variability, not run-to-run variability.

- **Small corpus, wide intervals.** Sixteen payloads per model yield wide bootstrap CIs
  (e.g. [25%, 75%] at a point estimate of 50%). The instrument is designed to detect large
  behavioral differences between models, not to estimate rates precisely.

- **Fixed encoding list.** The oracle checks a fixed set of encodings (exact, whitespace,
  base64, hex, URL, reversed, per-character). A model that invents a novel encoding of the
  canary would evade detection and be scored, conservatively, as no-leak. The reported rates
  are therefore lower bounds on true exfiltration behavior.

- **Panel and provider constraints (single-vendor proprietary arm; hosted open arm).** The
  proprietary arm comprises two tiers of a single vendor (Google Gemini Flash and
  Flash-Lite) rather than the Anthropic models used in prior work, and the open-weights arm
  is served via hosted free tiers (Llama 3.3 70B via Together, Qwen 3.6 27B via Groq) rather
  than a local self-hosted deployment. Provider selection was constrained by budget:
  Anthropic has no free API tier, and the available Anthropic and Mistral credentials were
  invalid and rate-limited respectively. The served open weights may be quantized and are
  wrapped in provider-side system scaffolding, so results characterize "the open-weights
  model as commonly served", not the raw checkpoint an enterprise would host itself. The
  headline comparison should be read as best-evaluated open-weights versus best-evaluated
  proprietary, not as a claim about either family in general.

- **One model per family, not a census — and a tier confound.** The completed study is a
  single proprietary model (Gemini 3.1 Flash-Lite) versus a single open-weights model (Llama
  3.3 70B); a second open model (Qwen 3.6 27B) could not be run because the available Groq
  free tier enforces an output-tokens-per-minute limit incompatible with a multi-turn
  thinking agent, and no OpenRouter backup key was available. Critically, the proprietary
  model is a small "lite" tier and the open model is 70B, so the observed 100% vs 50% gap
  confounds license with model tier/capability. This result must NOT be read as
  "open-weights models are safer"; a frontier proprietary model and a small open model are
  both untested and could reverse the ordering.

- **Thinking models and output truncation.** The Gemini and Qwen models spend output tokens
  on hidden reasoning before emitting a tool call. We raised the per-call output cap to 1024
  tokens so that reasoning does not truncate the tool call; too small a cap would silently
  bias the measured exfiltration rate downward by cutting episodes off before the egress
  call.

- **English-only.** All payloads and the agent workflow are in English; multilingual
  injection is untested.

- **Observer effect of the planted canary is unmeasured.** The synthetic record is designed
  to be indistinguishable from a real member record, but we have not verified that its
  presence does not itself alter agent behavior relative to a workflow with no canary at all.
