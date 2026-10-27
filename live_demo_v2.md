# CERDA big demo (about 15 minutes), driven from the dashboard

Everything runs on one laptop, for free. The attackers are scripts we wrote (`scripts/live_range.py`), so say so on
stage: this shows the mechanism working, not accuracy on real attackers.

## Setup (10 minutes before)
Use a fresh folder: it holds all the demo data, and nothing in it is ever overwritten, only added to.

    mkdir demo_run3 ; cd demo_run3
    $env:PYTHONPATH="D:\projects\CERDA"                    (PowerShell)
    streamlit run D:\projects\CERDA\dashboard.py           (open http://localhost:8501)

Optional second terminal, the pager that prints a red alert whenever an attacker touches bait:

    python -m scripts.alert_listener
    $env:CERDA_ALERT_WEBHOOK="http://127.0.0.1:9099/"       (set this BEFORE starting the decoy)

Then in the dashboard, tab **Live Range**, press **Start the decoy in this folder**. It needs up to a minute to load
the models; the Decoy tile turns Online. (You can also start it yourself: `python D:\projects\CERDA\decoy_server.py --tarpit`.)

Do not run `generate_demo_data`: an empty dashboard that fills up live is the point (the script now refuses to
overwrite existing data anyway).

## Act 1: the empty decoy (1 min)
Show the empty dashboard. Passive honeypots record. CERDA perturbs its own timing and measures how each attacker's tool reacts.

## Act 2: attackers arrive (3 min), tab Live Range
Press **Launch attack wave**. Fourteen kinds of attacker connect at once, each session from its own address:
botnet dropper, patient scanner, backoff-aware bot, human-style operator, crypto-miner installer, persistence
implanter, data thief, credential stuffer, web scanner, SQL-injection prober, WordPress brute-forcer, exploit prober, a Mirai-style Telnet bot (port 2323) and a webshell uploader.
Then open the tab **Malware**: the bot's binary (built with `echo` lines) and the uploaded webshell are in quarantine,
hashed, and every session that dropped the same file shares the hash. The tab **Export Intel** gives a STIX 2.1 / MISP file.
Watch the log, then the tabs Live Sessions and CERF Network Graph: the column "demo_attacker" shows who each session
really was. About 70 to 90 seconds per wave.

## Act 3: they come back on new addresses (1 min)
Press Launch again. Every wave uses new, never-used addresses, new usernames and passwords, and a new dropper server,
and the same attackers get the SAME actor IDs back (the registry persists). Previous runs stay listed; nothing is replaced.

## Act 4: stopping them (5 min), tab Defense
1. Read the four steps: observe, identify, decide, enforce.
2. Block an actor with its **Block** button (for example the dropper and the miner), or press
   **Block all N actors that tripped a canary**. Blocking bans every address the actor has used so far.
3. Go back to Live Range and Launch again (leave "share returning from an old address" at 25%).
4. In Defense watch: sessions **cut mid-attack** (the attacker's connection is dropped after about 15 to 20 commands,
   when its rhythm matches a blocked actor), **connections refused at the door** (old addresses), and the table
   "How much of each attack was prevented". The green line counts cuts on addresses nobody had seen before: an IP
   blocklist would have missed those, the rhythm did not.
5. Unblocked attackers (for example the scanner or the SQL prober) finish normally: the defence does not cut innocent actors.
6. Switch on **Auto-block when an actor trips a canary** and launch once more: actors that read bait are blocked on their own.
7. The nftables rules at the bottom are the list for a real firewall. Nothing on this computer is changed.

## Act 5: a panelist attacks (3 min)
Terminal: `ssh -o StrictHostKeyChecking=no -p 2222 root@127.0.0.1` (password `123456`). Let them explore
(`ls`, `cat ~/.aws/credentials`, `ps aux`). The pager fires on the bait files. After about 15 commands they appear as
their own actor. Block that actor and they are cut (and 127.0.0.1 is banned until you press **Unblock everything**).

## What to say about the limits
- Simulated, scripted attackers only; real traffic is the next step.
- A fingerprint needs about 15 commands, so a very fast attacker finishes part of its job before it is recognised;
  the first sessions of a new attacker are never stopped, only observed.
- The web scanner, exploit prober and WordPress brute-forcer tend to merge into one actor (their rhythms are too alike);
  SSH attackers separate much better.
- A twin of the scanner with identical commands but a fast rhythm (add `twin_fast` to the attacker list) is separated
  by rhythm alone, but small rhythm gaps may not be.
- The defence evicts attackers from the decoy; protecting a real network means loading the exported rules into a real firewall.

## If something goes wrong
- Decoy will not start: run it by hand in the same folder (see Setup). The dashboard notices it within seconds.
- A wave seems stuck: **Stop this attack**, then launch again.
- Lost the story: the Remotion video (`demo_script.md`) is the backup.
