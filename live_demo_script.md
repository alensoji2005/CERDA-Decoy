# CERDA Live Demo Script (~10 minutes)

This is the live, run-it-yourself demo. (`demo_script.md` is the narration for the pre-rendered Remotion video.)
Every command below was dry-run against the current code.

---

## 0. Setup (do this 15 minutes before)

```bash
cd D:\projects\CERDA
pip install -r requirements.txt
pytest -q                               # expect: 28 passed
```

Open **4 terminals** in the repo root and size them so the audience can read them (font 18pt+).
Use a clean demo folder so old CSVs don't leak in:

```bash
mkdir demo_run
cd demo_run
set PYTHONPATH=D:\projects\CERDA        # PowerShell: $env:PYTHONPATH="D:\projects\CERDA"
python -m scripts.generate_demo_data    # seeds 35 sessions from 2 synthetic botnets
```

Run every terminal from `demo_run`. Pre-open the browser on `http://localhost:8501`.

**Avoid surprises:**
- Unset `GEMINI_API_KEY` unless you have reliable wifi. The mock outputs are deterministic and look the same.
- Start the decoy **before** you go on stage. It takes about 10 seconds to load PyTorch.

| Terminal | Command | Role |
|---|---|---|
| T1 | `python D:\projects\CERDA\decoy_server.py --tarpit` | Decoy (wait for the "Starting CERDA Decoy Server..." line) |
| T2 | `streamlit run D:\projects\CERDA\dashboard.py` | Dashboard |
| T3 | `ssh -o StrictHostKeyChecking=no -p 2222 root@127.0.0.1` (password `123456`) | You, playing the attacker |
| T4 | spare | Bot, benchmark, blocklist |

---

## Act 1: The problem (1 min, no screen)

> "Honeypots today are passive. They record what an attacker types, but attackers rotate IPs, reuse tools and change commands, so the logs rarely tell you *who* you are looking at. And sophisticated bots detect static honeypots and leave."

> "CERDA flips this. Instead of only watching, we **perturb** the attacker. We deliberately change the decoy's timing and measure how their tooling *reacts*. That reaction rhythm is a fingerprint. We call it a CERF: a Counterfactual Execution-Rhythm Fingerprint."

---

## Act 2: The decoy (3 min, T3)

Type slowly. The audience follows the screen.

```
ls
cat ~/.aws/credentials
whoami
ps aux
cd /tmp
touch payload.sh
ls
```

What to point out:
- **`cat ~/.aws/credentials`**: "Those are honeytoken credentials, fabricated on the fly. If they're ever used against AWS, we know exactly which session leaked them." (With `GEMINI_API_KEY` set, an LLM generates files in context. Without it, deterministic templates are used.)
- **`touch` then `ls`**: "The filesystem is stateful. The attacker's changes persist, so it feels real. But nothing ever executes on the host. That's an acceptance test (A3)."
- **From about the 7th command, the output types out slowly.** "That's the perturbation schedule kicking in: baseline, slowdown, jitter, then filesystem latency. We're changing the conditions and watching how the client adapts."
- **Tarpit:** "This server also runs with `--tarpit`. At the TCP level, the decoy advertises a tiny receive window, so an automated scanner's throughput collapses. It wastes their time and resources."

Type `exit`.

> "And that was a real SSH server: OpenSSH banner, real handshake, every password attempt logged to `auth.csv`."

---

## Act 3: The bot and the fingerprint (3 min, T4 + browser)

```bash
python -m scripts.bot_attacker
```

> "Now a scripted bot. Watch the response times climb as it moves through the perturbation regimes. A human pauses, reads and adapts. A script fires on a fixed rhythm. That difference is exactly what we measure."

Switch to the **dashboard** (it auto-refreshes; the decoy re-runs analytics every few seconds):
- **Network graph:** "Each cluster is a threat actor: sessions grouped by fingerprint, *not* by IP. The two botnets from the seeded data are cleanly separated, and our live sessions appear as their own actors."
- **Regime timeline:** "Here's the perturbation applied over each session."
- **Export JSON:** "One click gives a threat-intel export for a SOC or SIEM."

Talking point on the model:
> "The fingerprint comes from a Spatio-Temporal Transformer. It reads each command's timing, its structure (flags, pipes, URLs, subshells) and *which perturbation was active*. It compresses all of that into a 64-bit locality-sensitive hash. Similar behaviour gives similar hashes, so clustering is just Hamming distance."

---

## Act 4: The evidence (2 min, T4)

```bash
cd D:\projects\CERDA
python -m src.analytics.benchmark
```

Expected output (about 30 seconds; simplified here, the real output is a dict per line):

```
A/B equal length       pca          ari 1.0
A/B equal length       transformer  ari 1.0
A/B unequal length     pca          ari 1.0
A/B unequal length     transformer  ari 1.0
6 unseen archetypes    pca          ari ~0.49   (finds ~20 actors for 6)
6 unseen archetypes    transformer  ari 1.0     (finds exactly 6)
```

> "The key row is the last one. These are six attacker types the model **never saw in training**. The classical PCA baseline shatters them into about 20 fake actors. The trained Transformer recovers exactly six. That's why it's the default."

Then close the loop with active defense:

```bash
cd demo_run
python -m src.analytics.blocklist
type cerda_blocklist.nft                 # macOS/Linux: cat
```

> "Attribution turns into action: per-actor IP blocklists in nftables format. Every IP is validated, and nothing is applied automatically. A human reviews it and pushes it to the firewall."

(Live local sessions come from 127.0.0.1, which is deliberately excluded, so the IPs you see come from the seeded botnet data.)

---

## Act 5: Close (30 seconds)

> "Passive honeypots record. CERDA *interrogates*. It perturbs the attacker, fingerprints the reaction, attributes it to an actor across IP changes, and feeds that back into the firewall. It's packaged as a Docker deployment (`docker compose up`) for edge or DMZ nodes."

---

## Q&A: honest answers

| Question | Answer |
|---|---|
| "Is this tested on real attackers?" | "Not yet. All accuracy numbers are on synthetic data, including held-out archetypes. Real-world collection on an internet-facing node is the next phase." **Don't overclaim this.** |
| "Can attackers detect the timing changes?" | "They can notice latency, but variable latency is normal on the internet. The perturbations stay in the 50–200 ms range, the same as real network lag." |
| "What does the RL piece do?" | "An optional Q-learning scheduler (`--rl`) picks which perturbation to apply next, maximising information gained while penalising dropped sessions. The default is a fixed, reproducible schedule." |
| "Why a hash, not just the embedding?" | "A 64-bit LSH is compact, comparable in constant time and shareable between sites without sharing raw telemetry." |
| "What if the model weights are missing?" | "The engine falls back to the PCA baseline with a warning. That's tested (B7)." |
| "LLM latency?" | "File outputs are cached per path, and there's a deterministic mock fallback if the API is slow or down." |

---

## If something breaks

- **Bot gets "connection refused":** the decoy is still loading. Wait for its startup line.
- **Dashboard is empty:** run `python -m scripts.generate_demo_data` again in `demo_run`, then refresh.
- **Anything else:** skip to Act 4. `python -m src.analytics.benchmark` needs no server and is the strongest evidence anyway.
