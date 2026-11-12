# Comparative paper review: v5 draft and current assembled paper

## Scope and basis

This review compares `federated_paper_v5.tex` (the master draft) with `paper/main.tex` and its section files at the current `master` tip. The repositioning (#10), related-work (#11), real-data evaluation (#14), and threat-model layout (#16) changes were already merged when reviewed; the requested PR #7 branch is also merged. References below use physical source line numbers from the checked-out files, so they remain directly findable. Numerical claims were checked against `matrix_results.json`, `fed_model.json`, `poisoning_results.json`, `bandwidth_results.json`, `eval_deployed_results.json`, `real_data_results.json`, and `poisoning_v2_results.json` where applicable. I did not edit either manuscript.

## Executive assessment

The current paper is substantially more candid and reproducible in its experimental framing than v5: it distinguishes the controlled D=64 matrix from the augmented D=256 shipped model, separates threshold-0.5 metrics from the deployed threshold, and admits stale plots, absent hardware result files, the unintegrated KEM, and the K=2 Byzantine limit. It gains a serious system/security account and a useful account of failure modes. Its principal loss is a clean, narrow argument. The new text is a stitched system description plus a measurement paper, with substantial implementation history and security process detail interrupting the central federation result. The most important factual problem is no longer hidden: the live model channel is plain HTTP, so the title and repeated “quantum-resistant” framing overpromise. The strongest defensible paper is a measurement study of federated HTTP-payload classification under two constructed non-IID axes, with a prototype authenticated control plane—not a demonstrated end-to-end zero-trust, quantum-resistant WAF.

The central result supported by current artifacts is modest: on this particular public-list and augmentation pipeline, the D=256 federated model is statistically close to the best silo, protects the weaker domain silo, and improves some cross-domain metrics; it does not uniformly beat the best silo. The controlled D=64 matrix says the same thing: the n-gram domain split ROC-AUCs are 0.9918 federated and 0.9916 Edge B, while SQLi recall remains below Edge B (0.833 vs. 0.850). Claims should foreground that result and its narrow scope.

## 1. Content comparison

### Structure and claims

| Area | v5 (`federated_paper_v5.tex`) | Current (`paper/`) | Assessment |
|---|---|---|---|
| Story/structure | Conventional introduction, related work, architecture, privacy/PQC, setup, evaluation, discussion, conclusion. The flow is compact (v5 lines 33–50, 52–77, 151–191, 346–368). | More modular and much longer: background, system and algorithms, five-question evaluation, a dedicated security analysis, deployment status, future work (intro lines 8–34; system lines 13–119; eval lines 4–196; security lines 1–124; main lines 46–69). | Added clarity about implementation and scope, but security/audit/deployment material now competes with the experiment as the paper’s subject.
| Main contribution | Federation helps specifically when sites differ in benign profile, not attack campaign; hashed trigrams; median defense; ARM/PQC cost and bandwidth (v5 lines 40–48). | Adds authenticated aggregator, explicit Byzantine tolerance reporting, request-context inspection, anchor replay, operational controls, and more related-work positioning (intro lines 10–30; system lines 45–68; security lines 43–106). | These system contributions are not matched by equally strong evaluation: security test outputs are not archived; live PQ encryption is absent; deployed-threshold metrics are absent.
| Threat/security | Gradient leakage and a DP design provision; median poisoning experiment; unintegrated KEM disclosure (v5 lines 139–149, 258–271, 354–356). | Explicit A1–A4 threat model, HMAC/replay/rate/norm checks, test-case catalogue, detailed boundaries (security lines 9–20, 25–41, 43–88, 111–124). | Big documentation gain. However, a threat model and expected test status table are not evidence that those controls passed in a recorded run.
| Evaluation | Matrix, headline detection, sweep/convergence, poisoning, ARM, PQC, and bandwidth (v5 lines 194–344). | Keeps matrix, production metrics, poisoning, hardware, bandwidth; separates controls and lists evidence limitations (evaluation lines 46–196). Adds real-data and deployed-pipeline artifacts in the repository, but these are not actually reported in the current evaluation section. | Paper has not absorbed the most consequential new evidence files. This is a major content seam (details below).
| Conclusion | Detailed numerical conclusions, then focused future work (v5 lines 358–368). | Broad conclusion and a new deployment-status inventory of code features (main lines 49–66). | Deployment inventory reads like release notes; make it a concise implementation-status table in methods/supplement or remove it from the scientific conclusion.

### What the new paper gained

- A more defensible definition of the threat model and honest distinctions between authentication, robust aggregation, privacy, and confidentiality (security lines 9–20, 111–124).
- Description of the deployed gateway’s URL/header/body contexts, threshold, shadow mode, failure policy, synchronization, and anchor-set replay (system lines 53–68).
- Separation of the controlled design-space experiment from the production augmented experiment, which prevents invalid numerical cross-comparisons (evaluation lines 31–44).
- Explicit provenance warnings for the stale dimension sweep and old hardware/PQC measurements (evaluation lines 96–116, 145–152).
- A more qualified reading of the modest federation gain and the single-seed figure (evaluation lines 96–109, 183–195).
- Broader related work, including zero-trust concepts, PAYL, character n-grams, FedProx, and post-quantum signature/KEM distinction (background lines 6–42).

### What was lost, weakened, or left unused

- V5’s 0.839 SQLi recall and “Edge A 0.801 to 0.839” comparison (v5 lines 348–350) are not the current production result. New evaluation reports 0.865 federation versus 0.879 Edge B and admits federation is worse on that class (evaluation lines 90–103). Retain the old number only as a clearly labeled earlier pipeline result, or omit it; never blend it with the current model.
- V5’s stronger statement that federation gives “zero false positives on both benign domains” (v5 line 360) has been rightly abandoned. Current table reports default-threshold FPRs 0.0005 web and 0.0007 API (evaluation lines 89–93), while matched-budget metrics and FPR columns are different operating points.
- V5’s 99.94% reduction is qualified in current text with 98.88% at the deployed 15-second interval and 75.0% for the full training accounting (evaluation lines 164–181). Preserve all three contexts; 99.94% is only the 5-minute, 452 req/s scenario, not the deployed interval.
- The older v5 corpus table says 260 SQLi and 523 XSS (v5 lines 172–176); current evaluation gives 681 SQLi and 523 XSS, with disjoint test split 476/205 and 366/157 respectively (evaluation lines 21–25). Current is right for `fed_model.json`; old 260-SQLi results belong to an earlier corpus.
- New repository evidence is omitted: the current paper’s evaluation does not include `eval_deployed_results.json`, `real_data_results.json`, or `poisoning_v2_results.json`. In particular, it acknowledges that the deployed 0.15 threshold has no held-out metrics (evaluation lines 183–195), while the real-data artifact now explicitly evaluates threshold 0.15 and CSIC/leave-one-corpus-out. Report its results or state why it is excluded. The newer poisoning-v2 sweep also supersedes the sole-seed, naive-sign-flip characterization as the only available poisoning study; incorporate its relevant gate-on/off and attack-family results with precise scope.
- The omitted real-data result is materially adverse: `real_data_results.json` reports a CSIC-2010 normal pooled all-context flag rate of 100% at both 0.5 and 0.15 because the model scores the single repeated User-Agent at 0.9992 and gateway aggregation takes the maximum over contexts. Payload-only flag rate is lower but still 16.7% at 0.5 and 19.1% at 0.15; anomaly all-context flag rate is also 100%, so this full-context behavior does not discriminate the two labels. This needs prominent discussion as a deployment failure, not a footnote.
- `eval_deployed_results.json` does supply held-out τ=0.15 metrics for a re-trained production recipe (20 seeds, three split modes and request views), but explicitly does not score the shipped `fed_model.json` because payloads overlap its training data. For example, on the primary cluster split the whole-request AUC is about 0.914 for Edge A and 0.967 for federation; at τ=0.15 the gateway view’s FPR is about 14.2% for Edge A, 67.9% for Edge B, and 11.0% for federation. The poor and view-sensitive operating points undercut a blanket “deployed threshold unevaluated” statement while still leaving the exact shipped model’s held-out operating point unresolved.
- The title is still “Quantum-Resistant” although current text states that live `/update` and `/weights` are HMAC-authenticated JSON over plain HTTP (system lines 49–52; security lines 120–122). A component benchmark is not end-to-end protection.
- The current main file lists author/affiliation placeholders (main lines 24–28), while v5 contains a named author/affiliation (v5 lines 16–21). This must be corrected before submission, though it is outside prose analysis.
- Acknowledgement in v5 is absent from the assembled paper; retain it if still applicable (v5 lines 373–374).

### Number reconciliation

| Claim | Manuscript value | Artifact / correct interpretation |
|---|---:|---|
| Corpus size | v5 abstract: 1,204 attack payloads; v5 table: 260 SQLi + 523 XSS (v5 lines 26, 175–176); current: 681 SQLi + 523 XSS (current eval lines 24–25) | The v5 abstract total 1,204 does not equal the v5 table total 783. `fed_model.json` and `real_data_results.json` identify 681 unique SQLi; current production split is 476 train / 205 test. 260 belongs to the older experiment and cannot be used for current headline metrics. |
| Current D=256 detection | Current table: Fed AUC 0.9947±0.0019; Edge B 0.9938±0.0036; SQLi 0.865 vs. 0.879 (eval lines 90–103) | `fed_model.json` supports this multi-seed result. Margin is only 0.0009 AUC and below run-to-run SD; no claim of a reliably superior best-silo result. |
| Controlled matrix | Current text: D=64 n-gram/domain Fed AUC 0.9918 vs. Edge B 0.9916; SQLi 0.833 vs. 0.850 (eval lines 58–75) | `matrix_results.json` is the source. The 0.0002 AUC difference is a practical tie, not evidence federation beats the strongest silo. |
| V5 detection numbers | Abstract says 0.9934±0.0021 and 0.9923±0.0037; body later says XSS 0.966 and SQLi 0.839 (v5 lines 26, 243–245, 360) | These are from earlier configuration/result files and do not match current production output. Current `fed_model.json` values above take precedence for the shipped augmented model. Do not substitute single-seed figure metrics for multi-seed table values. |
| Poisoning | Current evaluation says mean falls 0.9841→0.0137 and ends 0.263; median ends 0.9838; trimmed mean 0.9864 (eval lines 121–143) | Correct for `poisoning_results.json`, a single-seed K=7, f=2, ×12 sign-flip without the deployed norm gate. It does not establish the deployed pipeline’s robustness. `poisoning_v2_results.json` is a separate multi-seed, broader attack/gate experiment and should be summarized separately. |
| Hardware | Current 0.229 ms, 452.5±24.3 req/s, 10.4 MB, KEM 0.162 ms (eval lines 148–152) | Explicitly sourced only to v5 prose/stress script, not current archived measurement JSON. Treat as preliminary, not a current reproducible measured result. |
| Bandwidth | 75.0% training; 99.94% at 452 req/s/300 s; 98.88% at 452 req/s/15 s (eval lines 164–181) | `bandwidth_results.json` supports these. The 99.94% headline needs its 300-second condition adjacent; deployment interval supports 98.88%. Payload-only centralized baseline (27.4 B/request) is unusually favorable to centralization but omits headers/metadata.

## 2. Narrative thread and seams

### Story the evidence can support

**Central question:** Under payload-disjoint evaluation, when does federating a lightweight HTTP payload classifier help across sites with different benign traffic profiles or attack mixtures, and what costs and security limits accompany that benefit?

**Argument chain:** Site-specific benign traffic and data-sovereignty constraints motivate local training → FedAvg may help or hurt depending on which distribution differs → a hashed-trigram linear model is a low-cost test vehicle → controlled matrix and augmented production experiments show federation generally lifts the weaker silo and reduces cross-domain errors but does not reliably beat the strongest silo → poisoning and system measurements show prototype behavior under bounded conditions → limitations (synthetic augmentation, public corpora, threshold mismatch, two clients, unintegrated PQC, no formal privacy) constrain deployment claims.

This spine should replace the current three-headed framing of zero-trust architecture, non-IID measurement, and post-quantum/security engineering. The latter two security engineering themes can remain secondary implementation results.

### Seams, repetitions, and contradictions (with locations)

1. **Claimed target is stronger than implemented decision.** Intro defines ZTA as every request “authenticated and authorised” continuously (intro lines 4–6), but system describes a stateless payload score and does not authenticate the HTTP requester or establish identity/posture (system lines 53–62). Background’s NIST PDP/PEP description is not mapped to a policy decision point (background lines 6–9). Call this a WAF enforcement component within a ZTA deployment, not a ZTA architecture.
2. **Quantum-resistant title versus unencrypted live transport.** Intro promotes ML-KEM protection (intro lines 16–17), contribution calls it post-quantum transport (intro line 28), but system and security explicitly say the live path is plain HTTP and KEM is standalone (system lines 49–52; security lines 120–122). Remove “quantum-resistant” from title/keywords and frame the timing as a component benchmark until integrated and measured end to end.
3. **Promise “better than any silo” conflicts with results.** Problem statement asks for better-than-single-gateway or at least non-inferior performance (intro line 20); contribution 2 says one axis “matches or exceeds” silos (intro line 26). Current D=256 SQLi recall is lower than Edge B and the paper says so (evaluation lines 91–103); controlled matrix SQLi likewise loses to Edge B (lines 70–75). Use “matches the strongest on aggregate AUC within uncertainty; improves selected cross-domain outcomes.”
4. **“Only one axis makes federation outperform” overgeneralizes.** Intro line 26 says only one non-IID axis makes federation beat isolated training. Matrix supports near-tie AUC in domain/n-gram but not superiority across every metric; attack axis also lifts the weaker silo. State exact outcome by metric, feature set, and test design.
5. **Abstract omits the strongest caveat and carries unsupported performance shorthand.** Abstract says detection quality and edge footprint in “few hundred microseconds” and up-to-99.9% reduction with 5-minute sync (main lines 32–34), but fails to disclose at the point of claim that deployed threshold is unevaluated in the cited table, physical figures are stale, right-hand sweep is pre-augmentation, and KEM is not live (evaluation lines 96–116, 148–152, 183–195). Put “component benchmark” and “not integrated” next to every PQC claim; reduce bandwidth headline to 98.88% at deployed interval.
6. **Evaluation questions omit real-data/deployed evidence.** Evaluation opens with five questions and enumerates four result files (evaluation line 4), but newer `eval_deployed_results.json` and `real_data_results.json` exist. The manuscript then says no 0.15 held-out result exists (line 190). That statement is stale relative to the repository. Add sections/results or identify artifact version/hash and explain why the files are excluded.
7. **Data augmentation rationale and claim need reconciliation.** Evaluation says wrappers are intended to neutralize length/context shortcuts (lines 31–32), yet limitations calls them synthetic and reports no captured production evaluation (lines 188–195). The security section claims request contexts are handled independently by maximum score (system lines 55–59), which is not equivalent to training on contexts; explain exactly which unit is wrapped/trained and which unit is scored at inference.
8. **System method says trained through “FedAvg”; online deployment uses median.** System lines 29–43 distinguish offline FedAvg from online median, but title, intro and evaluation often call both “federation” without disambiguating. Explicitly label offline training aggregation versus deployed online aggregation in every result caption and contribution.
9. **Poisoning result bypasses a claimed deployed defense.** Security says norm gate filters scaled weights (security lines 33–35), while poisoning injects −12× weights and attributes survival to median (evaluation lines 121–143). The paper notes the experiment assumes authentication but not clearly enough that this ×12 attack should be rejected by deployed norm gating. State it as a bare-aggregator ablation and add gate-on results from poisoning-v2.
10. **Security test catalogue reads as test evidence, then disclaims evidence.** Security lines 61–88 describes ten adversarial cases and expected status codes, then says no pass count is reported and live output is not archived. Move test-case mechanics to artifact documentation; in paper report only archived pass/fail outcomes or call it a test plan.
11. **Novelty/positioning claims unsupported by citation coverage.** Intro says heterogeneity is “rarely measured for WAF traffic” (intro line 14); background says “not aware” of the exact comparison (background line 27); positioning claims a new combination (background lines 41–42). These assertions need a bounded search statement and comparison table. “Contribution is the combination” is generic and makes sections interchangeable.
12. **Contribution duplication and abstract echo.** Intro’s six numbered contributions (lines 24–30) restate the abstract (main lines 32–34), then deployment status and conclusion re-list the same implementation facts (main lines 49–66). Collapse into at most three contributions and stop repeating inventories in the conclusion.
13. **System and security duplicate threat models and limitations.** System lines 13–16 and security lines 6–20 restate network and compromised-client assumptions. Byzantine bounds, peer-keying, norm checks, HMAC workflow and limitations are repeated across system/security/evaluation (system lines 36–47; security lines 25–56; evaluation lines 121–143). Put formal threat assumptions and controls in one section; cross-reference elsewhere.
14. **Deployment-status material interrupts conclusion.** Main lines 52–56 lists request methods, headers, nonce ordering, rollback, shadow mode, fail-open policy and anchor replay after the conclusion. These are implementation details, not conclusion-level findings. Move to system implementation and shorten to one paragraph/table.
15. **Convergence inference is not propagation latency.** Evaluation says rapid convergence “bounds how long a newly learned pattern takes to propagate” (line 106), but the simulation’s rounds do not establish deployed synchronization/convergence under online adaptation; gateway anchor updates and global sync may interact. Limit the statement to the offline training trajectory.
16. **Notation and identity drift.** Intro uses “sybil” lower-case (line 11); system/security use enrolled peers/identities; “signature” is used for HMAC tags (system line 47; security line 46), though HMAC is a MAC, not a public-key signature. Use “authenticated/MAC-tagged update,” reserve “signature” for asymmetric signatures, and define K, f, D, τ, R, E once.
17. **FPR and recall operating points are easy to conflate.** Current table caption says recall at 0.1% pooled FPR but FPR columns are at threshold 0.5 (evaluation lines 84–93); deployed threshold is 0.15 (system lines 61–62). Keep operating point in every caption and show deployed threshold results from the new artifact.
18. **Threshold section conflicts with new repository evidence.** Limitations says there is no result file at τ=0.15 (evaluation line 190), while both `eval_deployed_results.json` and `real_data_results.json` contain τ=0.15 results. Clarify that deployed-pipeline evaluation retrains the recipe rather than scoring the shipped file, and report the CSIC result where the gateway’s max-over-context rule flags every normal request due to the User-Agent score. Do not imply these datasets are captured deployment traffic.
19. **Current corpus/realism labels need precision.** “Real payloads” / “real traffic” can be read as production traffic. These are SecLists and curated web/API lists (evaluation lines 12–13), with synthetic wrappers and separately generated benign test categories in the real-data artifact. Say “public corpus strings” and distinguish the CSIC dataset, synthetic probes, and captured production traffic.
20. **Bibliographic and structural rough edges.** Background cites multiple concepts but current paper’s opening paragraph (“This section fixes…”) is empty signposting (background line 4). Section ordering puts Evaluation before Security even though intro says evaluation then security (consistent mechanically), but system includes threat model and security repeats it. Audit citation keys and claims together; e.g. HMAC is described as a signature and “Sybil exposure” as closed membership rather than Sybil-resistance.

## 3. AI-generated-text audit

This is a stylistic assessment, not an authorship detector. Counts below are rough manual counts of conspicuous occurrences in source prose; a keyword count is not proof of machine authorship. LaTeX body/captions are included; bibliography/code identifiers are excluded. The same broad IEEE cadence and shared vocabulary occur in both papers.

| Habit | v5 rough count and examples | Current rough count and examples |
|---|---|---|
| Stock vocabulary from requested list | ~7 notable: “robust” repeated heavily (v5 lines 26, 36, 46); “shared threat landscape” (26, 40); “comprehensive” only in cited title is not prose; “effectively free” (26, 149); “primary value” (245, 348). No clear “delve,” “seamless,” “pivotal,” or “novel framework.” | ~8: “robust” frequent; “landscape” (intro 6; background 18); “comprehensive” occurs in citation title only; “primary” appears in evaluation; “effectively free” no longer in current body. No clear “delve,” “seamless,” “pivotal,” or “novel framework.” |
| “Not only X but also Y” | 0 exact; the abstract uses a long “while… and…” stack (v5 line 26). | 0 exact; several “rather than” / paired clauses, especially background 9 and intro 11.
| Rule-of-three / symmetrical lists | ~8 prominent: three features (v5 99–103); three contribution-like claims; “inference latency, resident memory, sustained throughput” (47); three future-work directions (366). | ~12: three concerns (intro 8–17), six contribution bullets, enumerated evaluation questions, many three-part feature/control lists (system 55–68; security 48–55), seven future items (main 60–66). Patterned enumeration is useful in methods but overused in narrative prose.
| Em-dash/dash interruption | ~12 em/en dash uses, concentrated in abstract and conclusion; many are typographic double hyphens rendered as em dash. | ~15, mostly conventional compound terms/LaTeX dashes; fewer rhetorical parenthetical em dashes. Not a strong individual signal.
| Empty signposting | ~3: “Two methodological points…” (v5 182), “The outcome is unambiguous” (269), “Three directions follow directly” (366). | ~8: “This section fixes…” (background 4), “This paper makes…” (intro 23), “We evaluate… along five questions” (evaluation 4), “We list the weaknesses…” (eval 186), “In short” (eval 75), plus multiple “Section X reports…” transitions.
| Hedging boilerplate | ~5: “we do not claim,” “we did not conduct,” “remains…,” “in principle” (v5 352–356). | ~10: “we are not aware” (background 27); “we do not claim” (intro/security/eval); “intended to,” “in principle,” “we have not,” “should be read with that in mind” (evaluation 99, 103, 190; security 35, 115). Appropriate limitations dominate, but repeated disclaimers can make prose sound templated.
| Generic motivation | ~4: industrial digitization/perimeter, static WAF, centralization violates sovereignty (v5 34–38). | ~5: same opening setup repeated and expanded across intro/background/system (intro 4–6; background 7–9; system 4, 15).
| Overclaiming adjectives/adverbs | ~7: “robust,” “lightweight,” “effectively free,” “unambiguous,” “prohibitive,” “substantial,” “quantum-resistant” (v5 26, 149, 245, 269, 362). | ~8: “robust,” “zero-trust,” “adversarial,” “current,” “unambiguous” absent, but “hard,” “closed,” “critical,” “honest,” “immediate” appear (intro 4–17; eval 29–32; main 50–56). “Quantum-resistant” in title remains the material overclaim.
| Repeated summary sentences | ~6: abstract claim repeated in introduction/conclusion (v5 26, 40, 348, 360–362); “privacy at no measurable accuracy cost” repeats. | ~9: abstract/introduction/conclusion echo; result summary repeated between table narration, limitation bullets and security summary (main 32–34, 50; intro 25–30; eval 75, 103, 189; security 37–41).
| Uniform paragraph rhythm / interchangeable sections | v5: mixed. Abstract is very dense; body mostly regular 3–5 sentence paragraphs. Roughly 3 sections (background, privacy/PQC, future work) could be swapped into another FL-edge paper with little change. | Current: mixed-to-high templating. Many paragraphs begin with section-role labels, then standard claim/citation/qualification. Roughly 4 sections are genericable (background boilerplate, setup, deployment inventory, future work), while concrete artifacts and caveats make evaluation/security more specific.

### Exact examples and locations

- **V5:** “The proliferation of the Industrial Internet of Things has dissolved traditional network perimeters” (abstract, line 26): familiar generic motivation formula.
- **V5:** “Federation's primary value lies in cross-domain generalisation” (abstract, line 26) and “Federation's primary value is providing privacy at no measurable accuracy cost” (line 245): the second repeats the same abstract takeaway.
- **V5:** “The outcome is unambiguous” (line 269): stock intensifier before numerical results.
- **V5:** “The mechanism is straightforward once stated” is absent, but “Three directions follow directly” (line 366) is empty transition language.
- **Current:** “This section fixes the concepts the rest of the paper relies on” (background line 4): empty roadmap sentence.
- **Current:** “Three concerns that are usually treated separately meet in this setting” (intro line 8): polished triad lead-in, followed by three symmetric paragraphs.
- **Current:** “The pattern is consistent, and less flattering than a federation advocate would like” (evaluation line 75): conversational rhetorical staging rather than a scientific statement.
- **Current:** “We list the weaknesses a reader should weigh” (evaluation line 186): signpost announces a list without adding meaning.
- **Current:** “A review of the code against the claims of the draft paper, followed by a hardening pass, produced the changes below” (security line 93): process narrative that could be condensed into methods/change scope.
- **Current:** “the aggregator reports the Byzantine tolerance it actually achieves rather than implying protection it cannot give” (intro line 27): self-congratulatory contrast that repeats the concrete f-reporting mechanism.

### Verdict

- **v5: mixed, leaning human-edited.** The first half of the abstract and contributions have familiar generated-sounding broad framing and an overstuffed metric sentence. The results discussion, caveats, and acknowledgment of weaker findings are specific and uneven enough to read as substantially edited by someone close to the experiments. Several claims were later shown to have stale provenance, which is a factual/reproducibility issue rather than an AI-style tell.
- **Current: mixed, with stronger templated/LLM-like surface.** It has many concrete implementation details and unusually candid limitations, but the expanded prose relies on symmetrical section scaffolding, repeated summaries, lists of three, empty signposts, and process-history narration. Nothing here supports a confident authorship attribution. The practical fix is to remove repetitive scaffolding and put evidence before evaluation adjectives.

## 4. Rewrite plan

### One-paragraph spine

Industrial gateways see site-specific benign HTTP traffic, while moving requests to a central trainer may violate data-governance constraints. This paper asks whether federated training helps a lightweight request-payload classifier when sites differ either in attack mix or in benign profile. Using unique-payload-disjoint splits and matched operating points, the controlled and augmented experiments show that federation usually helps the weaker site and can reduce cross-domain false positives, but does not reliably exceed the strongest local model; the result depends on the feature representation and the axis of heterogeneity. A prototype shows that fixed-size updates and a small linear model fit an ARM gateway, while a separate simulated poisoning study evaluates coordinate-wise aggregation under a bounded sign-flip attack. Public-list data, synthetic context augmentation, the unevaluated/live threshold gap, stale hardware artifacts, K=2 deployment, no formal privacy, and an unintegrated KEM limit the conclusions. The contribution is a careful measurement and implementation study, not proof of a complete zero-trust or quantum-resistant deployment.

### Section roles and handoffs

| Section | Role | Must hand to next section |
|---|---|---|
| Introduction | State governance constraint, exact question, two heterogeneity axes, and three bounded contributions. | A concrete gap: existing results do not isolate which non-IID axis matters for this classifier and protocol.
| Related work | Compare WAF/payload models, FL heterogeneity, privacy/poisoning, and edge deployment; avoid broad “unexplored” claims without evidence. | Why a fixed-size trigram linear model is the test vehicle and what novelty is only measurement-level.
| System and method | Define data flow, training and online aggregation separately, model features, contexts, threshold, authentication, and unintegrated KEM status. | Exact experimental objects/configurations; no result claims yet.
| Evaluation | Start with design and dataset provenance; report matrix, production model, deployed/real-data tests, poisoning, edge/bandwidth with artifact provenance and comparable operating points. | What conclusions hold and which do not.
| Security discussion | Interpret threat-model coverage, test evidence, and boundaries; avoid repeating methods/results. | Bounded deployment implications.
| Conclusion | Answer the central question in two or three sentences, then state the most important limits and next experiment. | No new code inventory or new claims.

### Style rules for rewriters

**Do**

- Put the population, split, threshold, aggregation method, seed count, and artifact next to each result.
- Use “matches within observed seed variation” only when the reported uncertainty supports it; avoid significance language unless tested.
- Call HMAC a message authentication code/tag, not a signature; call the shipped classification a request-payload score, not behavioral authentication.
- Distinguish public corpus payloads, synthetic augmentation, CSIC samples, synthetic benign probes, and production traffic.
- Use “offline FedAvg” and “online median aggregation” as distinct terms.
- State every performance number with the condition that produces it: 98.88% at 15 s; 99.94% at 300 s.
- Use one precise limitation paragraph per limitation; cross-reference rather than repeat.
- Keep implementation history out of results unless it changes the experiment or explains a failure.

**Don’t**

- Don’t call the system quantum-resistant while live transport is plaintext or call it a complete ZTA.
- Don’t claim federation beats the best silo based on a tiny AUC difference or a single favorable seed.
- Don’t blend the old 260-SQLi pipeline, current 681-SQLi pipeline, and current augmented production model.
- Don’t call synthetic wrappers “realistic traffic” without a validation study.
- Don’t claim an attack suite passed when its output is not archived.
- Don’t repeat the abstract in the contribution list, section summaries, discussion, and conclusion.
- Don’t use “robust,” “unambiguous,” “effectively free,” “novel,” or “comprehensive” where a measured bound or direct description is available.
- Don’t introduce a three-part list merely to create cadence; enumerate only actual experimental dimensions.

### Ten before/after examples

1. **Generic opening (v5 abstract, line 26)**  
   Before: “The proliferation of the Industrial Internet of Things has dissolved traditional network perimeters…”  
   After: “Industrial gateways inspect requests from sites whose benign traffic differs, while governance rules may prevent those requests from leaving the site.”

2. **Overclaiming federation (v5 abstract, line 26)**  
   Before: “Federation's primary value lies in cross-domain generalisation…”  
   After: “In the domain-split experiment, federation improves the weaker silo’s selected cross-domain metrics; its SQLi recall remains below the stronger silo.”

3. **Unqualified PQC benefit (v5 abstract, line 26; current system lines 49–52)**  
   Before: “making post-quantum protection of the weight channel effectively free.”  
   After: “ML-KEM-512 encapsulation takes 0.162 ms in a component benchmark; the live weight endpoint still uses plaintext HTTP, so end-to-end post-quantum confidentiality has not been measured.”

4. **Contribution overstatement (current intro, line 26)**  
   Before: “only one of them makes federation outperform local training.”  
   After: “In the tested D=64 matrix, the domain split produces a near-tie in ROC-AUC with the best silo and lower cross-domain API FPR; the attack split lifts the weaker silo but remains below the stronger one.”

5. **“Zero-trust” breadth (current intro, line 4)**  
   Before: “requires every request to be authenticated and authorised on its own merits, continuously and regardless of origin.”  
   After: “requires access decisions to be made per request; this prototype contributes a gateway payload-scoring component and does not implement requester identity or posture checks.”

6. **Empty related-work signpost (current background, line 4)**  
   Before: “This section fixes the concepts the rest of the paper relies on…”  
   After: “Prior work informs four design choices: per-request enforcement, federated optimization, payload representation, and update-channel security.”

7. **Rhetorical result staging (current evaluation, line 75)**  
   Before: “The pattern is consistent, and less flattering than a federation advocate would like.”  
   After: “Across the tested splits, federation improves the weaker silo; it does not reliably exceed the strongest silo.”

8. **Ambiguous “real traffic”/data scope (current evaluation, lines 12–13)**  
   Before: “All payloads come from the public SecLists corpus; no payload is synthesised.”  
   After: “The attack strings and benign paths are public corpus entries. Training examples are subsequently wrapped in seven synthetic request contexts; no captured production traffic is used.”

9. **Unsupported security-test implication (current security, lines 61–88)**  
   Before: “The suite replays… Table lists the cases and expected verdicts,” followed by no archived pass count.  
   After: “The repository contains ten control-plane test cases with expected status codes. Because the run output is not archived, this paper reports the cases as test coverage, not as a verified pass result.”

10. **Conclusion inventory (current main, lines 52–56)**  
    Before: “Hardening followed a tiered roadmap…” followed by a long list of operational features.  
    After: “The prototype implements request-context scoring and an authenticated update path. Its live model channel is not encrypted, and the two-gateway deployment provides no Byzantine tolerance; these limits define the next deployment study.”

## Recommended priority order

1. Reconcile the new `eval_deployed_results.json` and `real_data_results.json` into the evaluation; state the 100% CSIC normal-request false-positive result for the full gateway scorer and distinguish recipe re-training from the shipped model.
2. Add the broader poisoning-v2 result with gate-on/off scope and explicitly distinguish it from the older bare-aggregator sign-flip ablation.
3. Remove “Quantum-Resistant” from title and contribution framing until the live channel encrypts traffic with the derived key and is measured end to end.
4. Reframe zero-trust claims as a gateway component; do not imply requester authentication/authorization or behavioral authentication.
5. Replace the six-item contribution list with three claims centered on the measurement question, prototype implementation, and evidence-bounded system cost/security results.
6. Consolidate threat-model and aggregation detail, then move the deployment-status inventory out of the conclusion.
7. Regenerate stale sweep and hardware measurements, archive their raw outputs, and regenerate the figure from the actual current multi-seed results.
8. Rebuild the abstract and conclusion last, from final tables only.
