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

- **Open models are served quantized via hosted APIs.** We test the open-weights models
  through Together and Mistral, not a local self-hosted deployment. The served weights may be
  quantized and are wrapped in provider-side system scaffolding, so results characterize
  "the open-weights model as commonly served", not the raw checkpoint an enterprise would
  host itself.

- **Four models across two families, not a census.** Two proprietary and two open-weights
  models cannot establish a property of "open-weights models" in general; they sample two
  points from each family. (In the run captured here, only one open-weights model was
  reachable, further narrowing the sample — see BLOCKERS.md.)

- **English-only.** All payloads and the agent workflow are in English; multilingual
  injection is untested.

- **Observer effect of the planted canary is unmeasured.** The synthetic record is designed
  to be indistinguishable from a real member record, but we have not verified that its
  presence does not itself alter agent behavior relative to a workflow with no canary at all.
