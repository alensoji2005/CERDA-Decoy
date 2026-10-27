# Unsupervised threat clustering of SSH and HTTP telemetry via emulated service sandboxes

**SUPERSEDED by `docs/paper/CERDA_manuscript.docx` (2026-10-27), which reframes the paper around the simulator and scripted-traffic evidence. Kept as the earlier plan for the real-traffic version.** **Draft 1, 2026-10-27. Working document, not for submission.** Final submission format is a single-column Word file.

Scope of this draft: Sections 1, 2, 3, 4, 5.2, 5.4, 5.5, 6.6, and the limitations in 7. Sections 1 and 3 to 7 depend only on the project report and the code (commit `1ebd3d4` plus the uncommitted pairing and simulator fixes of 2026-10-27); Section 2 rests on the literature in `docs/literature.md`. Sections 5.1, 5.3, 6.1-6.5 and 6.7-6.8 and the abstract's findings need the real-traffic deployment, and are not drafted. Text in `[DATA: ...]` is a placeholder for a value that does not exist yet. Text in `[CHECK: ...]` is a statement to verify before submission. Citations (author, year) refer to entries in `docs/literature.md`; the reference list is generated from there at the end.

Terminology note for the authors: the title is kept as in the project report. "Unsupervised" is used for the clustering step. The embedding that feeds it is trained with synthetic labels (Section 4.6), and this is stated where it matters.

---

## 1. Introduction

### 1.1 Problem

Exposed SSH and web services receive a continuous stream of automated and manual attacks: credential guessing, system reconnaissance, and attempts to download and run payloads. A honeypot, a decoy system that imitates a vulnerable service, lets defenders observe this activity without risking a production host (Srinivasa et al., 2023). The output of a honeypot is however a large collection of terminal commands, HTTP requests and login attempts, which is difficult to interpret by hand, particularly when many sessions repeat similar activity. A practical question for an analyst is which sessions were probably produced by the same operator or tool, so that activity can be tracked over time and effort can be spent on new behaviour rather than on repeats.

Previous work has grouped honeypot sessions or source addresses from what the attacker typed. Crespi et al. (2021) cluster botnet source addresses from shell commands captured by a honeypot, and Shamsi et al. (2022) cluster attackers observed on medium-interaction honeypots to find addresses likely controlled by one operator. These approaches treat the honeypot as a passive recorder.

### 1.2 Approach

We build a honeypot that is not passive with respect to time. The decoy answers commands at a controlled pace: it moves each session through four timing regimes (no added delay, a fixed delay, a random delay, and a longer delay for commands that touch the filesystem), and it measures how quickly the attacker's tool sends its next command after each response. The measurement excludes the delay that the decoy itself added. The intuition is that automated tools differ in how they wait for, retry after, or ignore slow responses, so the pattern of reaction times across regimes may carry information about the tool and its operator that command text alone does not. Reaction times are combined with simple structural features of each command and turned into a 32-dimensional embedding of the session. The embedding is reduced to a 64-bit locality-sensitive hash, which we call the Counterfactual Execution-Rhythm Fingerprint (CERF). Sessions whose hashes lie within a Hamming-distance threshold are assigned to the same threat actor, and actor identifiers are stored in a persistent registry. Signals that are shared by many unrelated attackers, such as the SSH client fingerprint, are recorded to corroborate groupings but are not part of the embedding.

The word "counterfactual" in the name refers to the decoy varying its response timing between sessions and within a session. It does not mean that the same command is observed under two regimes in one session; the schedule is fixed (Section 4.3), so comparisons are made across sessions. We keep the name used in the project and avoid causal language in the text.

### 1.3 Relation to earlier work

Deliberately changing a honeypot's behaviour and watching the attacker's reaction is not new. Wagener (2011) developed self-adaptive honeypots that block commands, return errors or insult the attacker, and used the reactions to assess attacker skills, including to separate humans from machines. Schneider et al. (2021) studied how attackers react to blocked and insulting responses in more than 200 captured sessions. What we are not aware of in earlier work is the specific combination studied here: timing perturbation, reaction time corrected for the injected delay, and a hash of the reaction profile used to link sessions to persistent actor identities. We state this as a limited observation: our literature search was not systematic (Section 2), and we do not claim that nothing similar exists.

### 1.4 Research questions and contributions

We ask three questions.

- **RQ1.** Does the attacker's reaction to timing perturbation add attribution signal beyond command structure alone?
- **RQ2.** Does the perturbation change attacker engagement, measured as session length and early disconnection, relative to a baseline-only control?
- **RQ3.** How sensitive are actor assignments to the Hamming threshold, to session length and to the order in which sessions arrive?

The contributions are:

1. A decoy that varies response timing across four regimes and records the attacker's reaction time net of its own injected delay (Sections 4.3 and 4.4).
2. A session fingerprint and a first-match clustering with a persistent actor registry, with corroborating signals kept outside the embedding (Sections 4.5 to 4.7).
3. An evaluation toolkit for traffic without ground truth: weak labels from shared dropper URLs and offered SSH keys, an all-baseline control arm, and tracking of newly appearing actors (Section 5).
4. `[DATA: an evaluation on real internet traffic with text-only and no-perturbation baselines. Not yet done; this contribution is only claimed if the experiments in Section 5 are completed.]`

The implementation is a working prototype. The results available so far come from synthetic data and from scripted traffic generated by the authors, and they are reported as such (Section 6.6).

### 1.5 Organisation

Section 2 reviews related work. Section 3 states the threat model and data-handling rules. Section 4 describes the system. Section 5 describes the experimental setup, Section 6 the results, Section 7 the limitations, and Section 8 concludes.

---

## 2. Related work

`[CHECK: Sections 2.2 and 2.3 describe Crespi et al., Shamsi et al., Zhu et al. and Schneider et al. from a reading of their full texts through an extraction tool; confirm every number against the PDFs before submission. Wagener (2011) was read through its abstract only, because the full text could not be retrieved. Descriptions of Boffa et al., Dumont et al., Udhani et al., Passino et al., Yurcik and Liu, and Wang et al. follow the project report and their titles and have not been rechecked.]`

We organise earlier work by what it does with honeypot data, and end with a comparison (Table 1) and a statement of what is, to our knowledge, not covered.

### 2.1 Honeypots and deception

Honeypots are classified by how much of a real service they implement. Low- and medium-interaction honeypots emulate a service in software and are easy to deploy and contain, but they can be recognised because they reproduce the protocol imperfectly (Vetterl and Clayton, 2018; Srinivasa et al., 2023). Surveys of deception techniques cover the area (Zhang and Thing, 2021; Fan et al., 2018). Recent work uses language models to produce shell output so that a decoy answers unseen commands convincingly (Sladić et al., 2024; Wang et al., 2026), and a survey of the field organises this work and the ways honeypots are detected (Bridges et al., 2026). Our decoy is a deterministic emulation with an optional language-model mode that is not used here; the contribution lies in what is measured, not in response realism.

### 2.2 Grouping honeypot sessions and attackers

Several studies group honeypot activity to find recurring tools or operators, using what the attacker sent. Crespi et al. (2021) analysed shell commands captured by a honeypot-as-a-service network, with 248,795 source addresses in one analysis and more than 90 million sessions in another, and grouped addresses and sessions with topic models and an autoencoder-based pipeline over command text and command order. The authors describe the findings as preliminary and report no ground truth. Shamsi et al. (2022) deployed five honeypot types between April 2019 and January 2021, with 5.55 million Cowrie sessions among them, and grouped attacking addresses with several clustering methods and a consensus step, using credentials, commands, outbound connections and the timing of connections. They reduced the result to 48 clusters, evaluated by manual review of cluster features, and note the lack of ground truth. Zhu et al. (2022) grouped 4,855 request logs from a high-interaction telnet honeypot with agglomerative clustering over byte-level text features to define eight families of bot loaders, and checked the grouping against a control run of known loaders in a sandbox; timing is not used. Boffa et al. (2022a) apply text-processing methods to honeypot logs and cluster the sessions, and a further study learns representations of honeypot logs with self-supervised pretext tasks (Boffa et al., 2022b). Passino et al. (2025) develop hierarchical topic models for detecting unusual attack patterns in honeypot terminal data, and Wang et al. (2018) cluster honeypot log sequences for an industrial protocol. Deshmukh et al. (2019) model attacker behaviour on a Cowrie honeypot with hidden Markov models to predict later actions, and Valeros et al. (2023) build behavioural profiles of attackers from geographically distributed honeypots.

Two points distinguish these studies from ours. First, they treat the honeypot as a passive recorder; what the attacker does is not influenced by the observer. Second, they have no ground truth for operator identity, which is also true of our real-traffic setting, and they say so. The evaluation we propose (Section 5) addresses this only partially, with weak labels derived from shared dropper URLs and offered SSH keys.

Several works use timing, but passively. Shamsi et al. (2022) use the intervals between probes and the timestamps of activity. Almotairi et al. (2007) group clusters of honeypot traffic by the distribution of packet inter-arrival times, which they show reveals activities with common causes. Timing of keystrokes in encrypted SSH sessions has long been studied as an information channel (Song et al., 2001), and remote-session studies show that network conditions change keystroke timing substantially (Kuzminykh et al., 2020), which we return to in Section 7. In these works the timing is whatever the network and the attacker produced.

### 2.3 Honeypots that change their behaviour

A second line of work changes the honeypot's behaviour to learn more. Wagener (2011) developed self-adaptive honeypots that block commands, return errors or insult the attacker, observed the attackers' reactions, and used them to assess skills and to separate humans from machines, with game-theoretic and reinforcement-learning methods to choose the behaviour. Schneider et al. (2021) deployed a honeypot of this kind next to a control and studied more than 200 sessions; attackers reacted in different ways, typically by repeating the previous command, and the mean session duration of the insulting-and-blocking honeypot (about 420 s) was close to that of the control (about 423 s); the authors report that blocking or insulting yielded no information gain in any observed session. They measured duration and number of commands, not the timing of individual reactions. Huang and Zhu (2019) and Guan et al. (2023) use reinforcement learning to choose honeypot responses that keep attackers engaged, the latter for IoT devices. Dykstra et al. (2025) argue for deliberately imposing friction on attackers to consume their time and resources. These works change what the honeypot says or does. We change when it answers, and we use the attacker's reaction to link sessions rather than to assess skill or to prolong the session.

### 2.4 Fingerprinting attackers and their tools

Fingerprints of clients are common outside honeypots. The SSH client's key-exchange offer can be summarised as a hash (Salesforce, n.d.), SSH keys collected from connections can be stored for threat intelligence (Dulaunoy et al., 2022), and automated web agents can be told apart from humans and crawlers by combining protocol-level and behavioural features (Kang et al., 2026). Terminal command sequences have been used to identify which model family drives an AI attack agent (Ediga and Chattopadhyay, 2026). Such fingerprints are shared by every user of the same library or model, and cross-campaign attribution studies report that actors remain hard to separate when they share practices (Weinberg, 2026). We therefore record these signals only to corroborate groupings, and do not mix them into the embedding. Human and automated attackers have also been separated by command behaviour on a long-running SSH honeypot (Udhani et al., 2019), masquerading users have been detected from command behaviour (Yurcik and Liu, 2005), and malicious remote shell sessions have been separated from benign ones using n-gram features of the commands (Dumont et al., 2019).

### 2.5 What the honeypot sees

Valeros et al. (2026) found that 99.23% of 177,622 authenticated sessions on eleven SSH honeypots over fifteen days were non-interactive, which means that a method that depends on several commands per session applies to a small share of authenticated traffic. We report the corresponding share for our own deployment (Section 5.1).

### 2.6 Comparison and gap

**Table 1.** Selected related work compared on how timing is used and whether the honeypot changes its behaviour. "Not used" means the work does not use that signal; "not checked" means the full text could not be read.

| Work | Honeypot data | What is grouped or assessed | Timing | Honeypot changes behaviour | Ground truth for operator |
|---|---|---|---|---|---|
| Almotairi et al. (2007) | Network honeypot traffic | Clusters of traffic, by inter-arrival times | Passive | No | None |
| Crespi et al. (2021) | Honeypot-as-a-service network, up to 90 million sessions | Source addresses and sessions | Timestamps for longitudinal view | No | None |
| Shamsi et al. (2022) | Five honeypot types, 5.55 million Cowrie sessions | Attacking addresses | Passive (intervals, timestamps) | No | None |
| Zhu et al. (2022) | Telnet, 4,855 request logs | Bot loader families | Not used | No | Control run of known loaders |
| Wagener (2011) | High-interaction honeypot | Attacker skill and reactions | Not checked | Yes (blocking, errors, insults) | Not applicable |
| Schneider et al. (2021) | Three honeypots, over 200 sessions | Reaction to blocking and insults | Duration and command count only | Yes (blocking, insults) | Not applicable |
| This work | SSH and HTTP decoys | Sessions linked to persistent actors | Active: reaction time to controlled delays | Yes (timing) | Weak labels only |

To our knowledge, earlier work does not combine the following elements: deliberate timing perturbation in a honeypot, reaction time corrected for the perturbation the decoy itself injected, and a hash of the reaction profile used to link sessions to persistent actor identities. Our search was not systematic (it covered preprint servers, Crossref and general web search, not all indexing services), so this is a statement about what we found, not proof that nothing similar exists.

---

## 3. Threat model, ethics and data handling

### 3.1 Threat model

The attacker connects over the internet to the decoy's SSH or HTTP port. It may be an automated tool or a person, and it is assumed to follow the protocols well enough to log in and issue commands. It may try to recognise a honeypot; low- and medium-interaction honeypots built on off-the-shelf protocol libraries have been fingerprinted at internet scale from a single packet (Vetterl and Clayton, 2018), and multi-step identification frameworks have been applied to billions of addresses (Srinivasa et al., 2023). We do not assume the decoy is undetectable. An attacker may also change its tool, its pace or its source address between visits, which weakens any behaviour-based link.

### 3.2 What the decoy does and does not do

The decoy does not execute attacker commands. Responses come from an emulated filesystem and command set in the decoy process, and the SSH service never gives access to the host (the test suite includes a test that commands do not reach the host, and the decoy code starts no operating-system processes). Download commands such as `wget` and `curl` do not fetch anything; the URL is recorded and the emulated filesystem shows a file. The only outbound connections the decoy can make are the optional alert webhook and the optional language-model mode (Section 4.2), both off by default. The decoy is intended to run on an isolated host. Operating limits (Section 4.2) bound the load an attacker can place on it.

### 3.3 Data collected and its handling

For each session the decoy records the source address, timestamps, every command or request line, every password and username tried, the offered SSH public-key fingerprints, the SSH client key-exchange fingerprint, the order of HTTP header names and the User-Agent. Logs of this kind can contain sensitive values, including real credentials that attackers have taken from other victims and typed into the decoy. We therefore treat the raw logs as sensitive.

`[DATA: retention period; whether source addresses are pseudonymised before analysis or release (for example with a salted hash, as done by Haikal et al., 2025); legal basis and the position under data-protection law for storing addresses and credentials; hosting provider's terms for running a honeypot. These decisions are open (project Stage 5) and must be made, and the paragraph rewritten, before the real-traffic deployment.]`

Credential values are not released with any dataset. Defensive deception also raises ethical questions about transparency and harm, discussed by Zhu (2023); here the decoy only responds to unsolicited connections and never initiates contact.

---

## 4. System design

### 4.1 Overview

The framework has four layers (Fig. 1): the decoy listener with its perturbation engine, a telemetry layer that records events and signals, an analytics layer that embeds sessions, computes hashes and assigns actors, and a local dashboard for the analyst. Each layer is a separate module. The implementation is in Python (asyncssh for SSH, aiohttp for HTTP, PyTorch and scikit-learn for analytics, Streamlit for the dashboard) and runs on a CPU. `[DATA: resource use has not been measured]`.

`[Fig. 1: system architecture, to be redrawn single-column from the project report's Fig. 4.1.]`

### 4.2 SSH and HTTP decoys

**SSH.** The SSH decoy speaks the real protocol through asyncssh and presents the version string `OpenSSH_8.9p1 Ubuntu-3ubuntu0.10`. It logs every password attempt and every offered public key, and it never accepts a public key. A password login succeeds if the password is one of nine common values (`123456`, `password`, `admin`, `root`, `toor`, `12345678`, `ubuntu`, `1234`, `qwerty`) or on the third attempt from the same source address, so that tools which reconnect for each guess still obtain a session. Both interactive shells and one-shot `ssh host command` execution are supported. Each source address and username pair keeps its emulated filesystem and command history for 24 hours across reconnections, for up to 10,000 clients.

The emulated shell supports directory listing and navigation, file reading, creation, removal and permission changes, `uname` options, command chaining with `;` and `&&`, pipes through common filters (`grep`, `head`, `tail`, `wc`, `sort`, `uniq`, `tee`; a pipe into `sh` executes nothing), output redirection (files written by the attacker can be read back), and a set of system commands (`ps`, `netstat`/`ss`, `ifconfig`/`ip a`, `df`, `uptime`, `w`, `who`, `date`, `env`, `last`, `crontab -l`, `lsb_release`) that describe one consistent Apache and MySQL server. An optional mode generates file contents with a language model; it is off by default and every deployment described in this paper uses the deterministic emulation. Related work has used language models to generate shell output (Sladić et al., 2024; Wang et al., 2026).

**HTTP.** The HTTP decoy (aiohttp) answers with Apache 2.4.52 Ubuntu headers and serves lookalike WordPress and phpMyAdmin login pages and a set of bait paths that return fake credentials (`/.env`, `/.git/config`, `/wp-config.php.bak`, `/config.php.bak`, `/.aws/credentials`). Form submissions are logged as login attempts and always refused. It serves plain HTTP only.

**Operating limits.** Defaults are 20 concurrent SSH connections per source address, 1,000 in total, 300 HTTP requests per minute per address (excess requests receive status 503 with the Apache header) and 2,000 commands per session. These values are untuned.

### 4.3 Timing perturbation

Each treatment session follows a fixed schedule over command indices (Table 2). The engine applies the regime's delay after the emulated command has run and before the response is sent.

**Table 2.** Perturbation regimes. Indices count commands from 0.

| Regime | Applies from command index | Added delay |
|---|---|---|
| R0 baseline | 0 | none |
| R1 slowdown | 2 | 100 ms |
| R2 jitter | 4 | random integer from 50 to 199 ms |
| R3 filesystem latency | 6 | 200 ms for commands that touch the emulated filesystem, otherwise 50 ms; in addition the SSH response is sent in at most 15 chunks with 20 to 80 ms gaps, capped at 0.3 s in total |

The 0.3 s cap on the output drip exists because slow responses make some clients time out and because Windows timers cannot honour many sub-15 ms sleeps. A reinforcement-learning scheduler that picks regimes is included as an experimental option and is not used in any experiment here. An optional TCP tarpit shrinks the socket receive buffer (to 256 bytes by default) on the listening socket; it is off by default and not used here.

A fixed share of sessions (`control_fraction`, default 0) is assigned to a control arm in which every command is answered in the baseline regime. The arm is chosen from a hash of the session identifier, so assignment is deterministic and independent of attacker behaviour. The arm is recorded with the session's signals.

Because every treatment session follows the same schedule, the regime is a function of the command index. A regime's effect on the reaction cannot be separated from the effect of position in the session within treatment sessions alone. The control arm provides the comparison that does separate them (Section 5.4).

### 4.4 Measuring the attacker's reaction time

For command *k* the decoy records Δt<sub>k</sub> as the time from the end of its response to command *k*−1 to the arrival of command *k*, using a monotonic clock. The end of a response is marked after the delay has been applied, after the output has been written (including the R3 drip) and after the connection buffer has been drained. The injected delay and drip therefore do not enter Δt.

Two consequences of this definition matter for interpretation. First, the row logged for command *k* carries the regime applied to the response to command *k*, whereas Δt<sub>k</sub> is the reaction to the response to command *k*−1. The analytics therefore pair each Δt with the regime of the previous row, the regime the attacker was reacting to; at each regime boundary the first row of the new regime holds a reaction to the previous regime's response, and this is handled by the pairing rather than by changing the log. Second, for the first command Δt is measured from the start of the shell session, which begins after authentication, so it is the time until the first command and not a reaction to a response; the analytics ignore it. With the schedule in Table 2, a session therefore yields two reactions to baseline responses (commands 1 and 2), two to slowdown responses (commands 3 and 4), two to jitter responses (commands 5 and 6), and one reaction to a filesystem-latency response for each command from 7 on.

`[CHECK: verify the per-regime counts against a logged session before submission.]`

Reaction times also depend on the network path between attacker and decoy. Congestion latency has been shown to change keystroke timing substantially in remote-desktop sessions (Kuzminykh et al., 2020), and an attacker behind a slow link may look different from the same tool on a fast one. The measurement is not corrected for this.

### 4.5 Telemetry and corroborating signals

Command events are written to a CSV file, or to an indexed SQLite table in write-ahead-log mode, with these fields: session identifier, wall-clock timestamp, source address, protocol, command index, raw command, command root, current path, regime, Δt, and whether a response was sent. Login attempts go to a separate file. Further attributes are written to a signals file as (session, kind, value) rows (Table 3) and joined to the session table by the analytics layer.

**Table 3.** Signals recorded, and their role.

| Signal | Protocol | Recorded | Role |
|---|---|---|---|
| HASSH: MD5 of the client's key-exchange, cipher, MAC and compression algorithm lists (Salesforce, n.d.) | SSH | once per connection | corroboration only |
| Offered public-key fingerprints | SSH | each offer (always refused) | corroboration; weak-label source |
| Login-attempt order | SSH | each attempt | corroboration |
| HTTP header-name order (hashed) | HTTP | once per session | corroboration |
| User-Agent | HTTP | once per session | corroboration |
| Download URLs in commands | SSH | at analysis time | corroboration; weak-label source |
| Control or treatment arm | both | when `control_fraction` > 0 | analysis |

None of these signals is part of the embedding. HASSH, User-Agent and header order are shared by every user of the same client library, so they cannot by themselves identify an operator; used inside the embedding they would merge unrelated attackers. Honeytoken reads (bait files over SSH and HTTP) and download attempts raise alerts that are appended to a JSON-lines file and optionally posted to a webhook.

`[CHECK: HASSH is cited as a software reference (GitHub, accessed 2026-10-27); build the reference with its access date. Cowrie is not cited in the text yet; add it to the related-work section if it is used.]`

### 4.6 Features and embedding

Two embedding backends produce a 32-dimensional vector per session.

**Transformer backend (default).** Each session is a sequence with one step per command. A step has 11 values: the log of Δt scaled by 20, six command-structure indicators (number of arguments starting with `-`, whether the command contains an `http://` or `https://` token, a pipe, an output redirection, a sub-shell (`$(` or a back-tick), and the number of arguments), and a four-way one-hot encoding of the regime of the response that the reaction time was a reaction to (the previous row's regime). The first step has no preceding response: its timing is 0 and its one-hot is all zeros. A linear layer projects each step to 32 dimensions, a learned position embedding is added, and a two-layer Transformer encoder (4 attention heads, feed-forward width 64; Vaswani et al., 2017) processes the sequence. The outputs are averaged over the real (non-padding) steps and L2-normalised. Command text is not used; only the six structural indicators are.

The encoder is trained with a supervised contrastive loss (temperature 0.1; Khosla et al., 2020) on batches of randomly generated attacker archetypes from the project's synthetic simulator, with the archetype as the label, using AdamW for 1,500 steps with eight archetypes and four sessions per archetype per batch (the script's defaults; `[CHECK: confirm the shipped weights were trained with these settings and seed]`). The weights are then fixed. "No labelled data" therefore holds for the clustering stage and for real traffic, but the embedding itself is trained on labels from a simulator. The simulator uses the live decoy's regime schedule and reaction pairing (Section 5.2); the final training loss was 1.13.

**PCA backend (baseline).** The session's reaction times are summarised per regime reacted to (median and spread of log Δt, with the first command's Δt left out), as ratios of each regime to the baseline, an adaptation measure (mean absolute change of consecutive reaction times and overall spread), the six command-structure indicators averaged over the session, and ten TF-IDF features of the session's command text. The vector is standardised, reduced by principal component analysis keeping 95% of the variance, and zero-padded to 32 dimensions. Each of the first three regimes contributes only two reactions per session (Section 4.4). The standardisation and principal components are fitted on the sessions in the batch being analysed.

### 4.7 CERF hash and actor assignment

The embedding is multiplied by a fixed 32 × 64 Gaussian random matrix (fixed seed) and each of the 64 signs becomes one bit, giving the CERF hash, in the manner of random-hyperplane hashing (Charikar, 2002). The Hamming distance between two hashes is the number of differing bits. A session joins the first actor, in creation order, whose stored hash lies within the threshold, and otherwise founds a new actor. The threshold is 6 bits for the PCA backend and 10 for the Transformer. The Transformer's threshold was set on a synthetic benchmark generated with seed 7, where the largest within-actor distance is 10 and the smallest between-actor distance is 11, so 10 is the only value that separates the two on that draw and has no margin. The PCA threshold is not calibrated: on the same draw its within-actor distances reach 13 while its between-actor distances start at 12, so no threshold separates them.

A SQLite registry stores each actor's founding hash, which never changes, and each session's assignment. A session is re-matched only if its number of commands has changed since it was last assigned; otherwise it keeps its actor. An actor left without sessions is removed. Actor identifiers (TA-001, TA-002, ...) therefore remain stable across analysis runs and restarts. The registry also records when each actor was created, so the number of new actors per day can be tracked as a measure of novelty or drift.

Two properties of this scheme limit its use. First, the assignment depends on arrival order, because the first match is taken rather than the nearest. Second, the registry compares hashes computed in different runs, and this is only meaningful if a session's hash does not depend on the other sessions analysed with it. We tested this on the synthetic benchmark with six archetypes (120 sessions). For the same session, the PCA hash from a batch of half the sessions and from the full batch differed on average by 9.7 of 64 bits (median 7, maximum 28), and 55% of sessions moved farther than the threshold of 6; when the first batch contained only two of the six archetypes the mean difference was 31.0 bits, about what unrelated hashes would give (32), and 98% of sessions moved beyond the threshold. The Transformer hash is identical in every case, as the encoder is not refitted. Passed through a persistent registry (two archetypes first, then all six), the PCA backend produced 20 and then 24 actors (truth: 2 and 6; adjusted Rand index 0.12 and 0.61, against 0.96 with 9 actors when the full batch was clustered at once), and the Transformer 2 and then 6 actors (index 1.00 both times). This is one dataset and one seed. We therefore treat the PCA backend as a batch method and the persistent registry as valid for the Transformer backend only.

### 4.8 Analyst tooling

A local Streamlit dashboard shows the live session registry, a network graph of sessions grouped by actor, a scatter plot of session characteristics, a timeline of an attacker's reaction time against the active regime, and a threat-intelligence export, with filters for protocol, actor, hash and date. A summary tile reports a cluster-agreement score: the adjusted Rand index (Hubert and Arabie, 1985) against weak labels, shown as "n/a" when no sessions carry such labels. The dashboard has no authentication and is bound to the local interface; remote access must go through an SSH tunnel or an authenticating reverse proxy. A blocklist and a threat-intelligence report can be exported.

---

## 5. Experimental setup (parts independent of the deployment)

### 5.2 Synthetic benchmark

The benchmark generator produces labelled sessions with known actors. Two canonical scripts, A (an impatient bot whose reaction time rises with each slowdown) and B (a scanner with a constant 500 ms reaction time), are generated with equal and unequal session length. In addition, random archetypes are drawn: each has a median reaction time per regime (log-uniform between 1 ms and 1 s), a noise level (0 to 0.5 on the log scale), and between two and four habitual commands from a pool of 18; sessions have 15 to 60 commands. The Transformer is trained on random archetypes only (seed 42), its threshold was set on seed 7, and the reported benchmark uses held-out draws from seed 1000, with ten further draws (seeds 1001 to 1010) for the six-archetype scenario. The canonical scripts are never seen in training.

The simulator reproduces the live decoy's layout: it takes the regime schedule from the same definition as the decoy (Table 2), writes each row's regime as the one applied to the response to its own command, and sets each Δt from the regime of the previous response, with 0 for the first command. An archetype's median reaction time is defined per regime reacted to. An earlier version of the simulator switched regimes at command indices 12, 25 and 37 and paired each Δt with its own row's regime; the Transformer and the benchmark scores reported here were regenerated after correcting this, and scores from the earlier version should not be compared with them.

This benchmark tests that the pipeline separates actors that differ by construction in reaction profile and command habits. It cannot answer RQ1, because the premise that reaction profiles differ between actors is built into the generator.

### 5.4 Methods compared

`[DATA: not yet implemented.]` The planned comparison is: (a) a text-only baseline, TF-IDF of command text with clustering; (b) the PCA backend; (c) the Transformer backend; and ablations of (c) without the reaction-time inputs, without the command-structure inputs, and trained and evaluated on control-arm sessions only. The text-only baseline and the ablations do not exist in the code at present.

### 5.5 Metrics

Agreement with weak labels uses the adjusted Rand index (Hubert and Arabie, 1985), always reported with the number and share of sessions that carry a label. Further metrics are the number of actors, session length and the share of sessions that end after a given regime (a regime that ends many more sessions than the baseline is too aggressive), threshold sensitivity, and sensitivity to session order (the index after random shuffles of arrival order). Confidence intervals use a bootstrap over sessions. `[DATA: tests and intervals to be specified once the sample size is known.]`

Weak labels link sessions that share a download URL or an offered SSH public key, directly or through a chain of such sessions. HASSH, User-Agent and header order are excluded because unrelated attackers share them. Because the presence of a URL in a command is also one of the model's six command-structure inputs, a score against URL-derived labels is not independent of the features; we report URL-derived and key-derived labels separately.

---

## 6. Results (synthetic benchmark only)

### 6.6 Synthetic benchmark

Table 8 gives the adjusted Rand index of the predicted actors against the true actors. All figures were reproduced by re-running the benchmark in this repository.

**Table 8.** Attribution on the synthetic benchmark (adjusted Rand index; predicted actors in brackets).

| Scenario | True actors | PCA backend | Transformer backend |
|---|---|---|---|
| Script A vs script B, equal length | 2 | 1.00 (2) | 1.00 (2) |
| Script A vs script B, unequal length | 2 | 1.00 (2) | 1.00 (2) |
| Six unseen random archetypes (seed 1000) | 6 | 0.96 (9) | 1.00 (6) |
| Six unseen random archetypes, mean and range over seeds 1001 to 1010 | 6 | 0.95 (0.88 to 1.00); 6 to 11 actors | 0.98 (0.81 to 1.00); 6 actors in every draw |

Both backends separate the two canonical scripts. On six archetypes not seen in training the two backends are close: the Transformer recovers six actors in every draw and the PCA backend over-splits in most (7 to 11 actors in seven of ten draws), but the difference in the adjusted Rand index is small (0.98 against 0.95 on average) and the Transformer's weakest draw (0.81) is worse than the PCA backend's (0.88). The Transformer was trained on archetypes from the same generator, and its threshold was calibrated on a different draw from that generator. The result therefore reflects the simulator and not real attackers, and it does not support a claim that the Transformer is clearly better than the PCA baseline.

`[CHECK: the next paragraph quotes runs made with the earlier weights and the earlier pairing. Repeat the live bot runs and the dashboard demonstration with the retrained model and quote the new hash and counts; the automated test that repeated runs of the bot receive the same hash and actor still passes.]`

Scripted live runs against the decoy gave consistent results: two separate runs of the same SSH bot (15 commands each, from the same host) produced identical hashes and were assigned to the same actor. Because the bot is deterministic, this shows that the measurement is repeatable, not that it separates different attackers. The dashboard's agreement tile read 1.00 over the 17 of 37 demonstration sessions that carry weak labels; these labels come from synthetic botnets that share a dropper URL, so the value tests the scoring code and not accuracy.

---

## 7. Limitations (so far)

Several limitations follow from the design and from the checks reported above.

1. **Evidence.** All results so far come from synthetic data and from scripts written by the authors. They do not show accuracy on real attackers, an effect on engagement, or resource use.
2. **Simulator realism.** The simulator now follows the live decoy's regime schedule and reaction pairing (Section 5.2), but its archetypes are drawn from simple distributions (log-uniform medians, log-normal noise, a few habitual commands), and scores on it are not a prediction of performance on live sessions.
3. **Few reactions per regime.** The schedule switches every two commands, so a session has only two reactions each to baseline, slowdown and jitter responses before the filesystem-latency phase (Section 4.4). Per-regime statistics are noisy for short sessions. A longer baseline phase was not tried.
4. **Regime confounded with position.** In treatment sessions the regime is determined by the command index, so only the control arm can separate the effect of a regime from the effect of position.
5. **Embedding trained on synthetic labels.** The Transformer is trained with labels from the simulator (Section 4.6).
6. **Threshold and hash size.** The thresholds (6 and 10 bits) and the 64-bit size were set on synthetic data; the Transformer's threshold has no margin on its calibration draw (largest within-actor distance 10, smallest between-actor distance 11) and the PCA threshold is uncalibrated (Section 4.7). A threshold that is too low fragments one actor into several, as the PCA backend does on unseen archetypes, and one that is too high merges different actors. First-match assignment depends on arrival order.
7. **Batch dependence of the PCA backend.** PCA hashes change with the batch (Section 4.7), so the persistent registry should be used with the Transformer backend only.
8. **Network conditions.** Latency, jitter and load change measured reaction times (Kuzminykh et al., 2020). Attackers behind slow links may be split across actors, and different attackers using the same tool may share a fingerprint. Short sessions carry little signal.
9. **Feature ceiling.** Attribution can be limited by how much attackers share, not by how they are modelled: a recent study of cross-campaign attribution on synthetic data found that actors remained hard to separate because sophisticated adversaries share practices (Weinberg, 2026).
10. **Interactive share.** A study of eleven SSH honeypots found that 99.23% of 177,622 authenticated sessions over fifteen days were non-interactive (Valeros et al., 2026). Our method needs sessions with several commands; `[DATA: the share of real sessions in the deployment that have enough commands]`.
11. **Detectability.** The decoy uses an off-the-shelf SSH library and may be recognised as a honeypot (Vetterl and Clayton, 2018). `[DATA: a check against honeypot-detection tools has not been done.]`
12. **Perturbation may alter behaviour.** The delays may cause attackers to disconnect or change behaviour; this has not been measured on real traffic.
13. **Scope of the decoy.** HTTP is plain text only, so TLS client fingerprints are not collected; the dashboard has no authentication; and the container deployment has not been built or tested.
14. **Literature search.** Our search of the literature was not systematic and did not cover all indexing services.

---

## 8. Conclusion (to be finalised)

`[DATA: to be written after the real-traffic experiments. Content so far: the system measures attacker reaction time net of the decoy's own delay, hashes the reaction profile and links sessions to persistent actors; on a synthetic benchmark the Transformer backend separates unseen archetypes where the PCA backend fragments them; real-traffic accuracy, the effect of perturbation on engagement and the benefit over a text-only baseline are not yet established.]`

---

## Declarations (placeholders)

- **Declaration of generative AI and AI-assisted technologies in the manuscript preparation process.** `[DATA: required, in its own section before the references. Must name the tools and the purpose, and state that the authors reviewed and edited the content. Include the use of AI-assisted tools for coding and drafting if applicable.]`
- **Declaration of competing interests.** `[DATA]`
- **Funding.** `[DATA: standard sentence if none]`
- **Data availability.** `[DATA: deposit of the dataset and an archived software release with DOIs, or a statement of why data cannot be shared (journal Option C). The repository currently has no LICENSE file.]`
- **CRediT author statement.** `[DATA]`
- **Acknowledgements.** `[DATA]`
