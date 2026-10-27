const fs = require("fs");
const path = require("path");
const D = require("docx");
const { Document, Packer, Paragraph, TextRun, Table, TableRow, TableCell, WidthType, AlignmentType, BorderStyle,
  ImageRun, Footer, PageNumber, LineNumberRestartFormat } = D;
const C = require("./content.js");
const FIG = process.env.FIGS;
const OUT = process.env.OUT;
const FONT = "Times New Roman";

// ---------- inline markup: *italic*  **bold**  ^sup^  ~sub~ ----------
function runs(text, o = {}) {
  const base = { font: FONT, size: o.size || 24, bold: o.bold, italics: o.italics };
  return text.split(/(\*\*[^*]+\*\*|\*[^*]+\*|\^[^^]+\^|~[^~]+~)/).filter((s) => s !== "").map((s) => {
    if (s.startsWith("**")) return new TextRun({ ...base, text: s.slice(2, -2), bold: true });
    if (s.startsWith("*")) return new TextRun({ ...base, text: s.slice(1, -1), italics: true });
    if (s.startsWith("^")) return new TextRun({ ...base, text: s.slice(1, -1), superScript: true });
    if (s.startsWith("~")) return new TextRun({ ...base, text: s.slice(1, -1), subScript: true });
    return new TextRun({ ...base, text: s });
  });
}
const DOUBLE = { line: 480, lineRule: "auto", before: 0, after: 0 };
const SINGLE = { line: 240, lineRule: "auto", before: 0, after: 0 };
const para = (text, o = {}) => new Paragraph({ spacing: o.spacing || DOUBLE, alignment: o.align || AlignmentType.LEFT, keepNext: o.keepNext,
  indent: o.indent, children: runs(text, o) });
const h1 = (t) => new Paragraph({ spacing: { ...DOUBLE, before: 120 }, keepNext: true, children: runs(t, { bold: true }) });
const h2 = (t) => new Paragraph({ spacing: DOUBLE, keepNext: true, children: runs(t, { bold: true, italics: true }) });
const unnumbered = (t) => new Paragraph({ spacing: { ...DOUBLE, before: 120 }, keepNext: true, children: runs(t, { bold: true }) });

// ---------- tables ----------
const none = { style: BorderStyle.NONE, size: 0, color: "FFFFFF" };
const rule = { style: BorderStyle.SINGLE, size: 6, color: "000000" };
function table(widths, header, rows) {
  const total = widths.reduce((a, b) => a + b, 0);
  const cell = (txt, w, isHead, last) => new TableCell({
    width: { size: w, type: WidthType.DXA },
    margins: { top: 40, bottom: 40, left: 80, right: 80 },
    borders: { top: isHead ? rule : none, bottom: isHead ? rule : last ? rule : none, left: none, right: none },
    children: [new Paragraph({ spacing: SINGLE, children: runs(String(txt), { size: 18, bold: isHead }) })],
  });
  return new Table({
    width: { size: total, type: WidthType.DXA }, columnWidths: widths,
    borders: { top: rule, bottom: rule, left: none, right: none, insideHorizontal: none, insideVertical: none },
    rows: [new TableRow({ tableHeader: true, children: header.map((h, i) => cell(h, widths[i], true, false)) }),
      ...rows.map((r, ri) => new TableRow({ cantSplit: true, children: r.map((c, i) => cell(c, widths[i], false, ri === rows.length - 1)) }))],
  });
}
function caption(label, title) {
  return new Paragraph({ spacing: { ...SINGLE, before: 200, after: 80 }, keepNext: true, children: [...runs(`${label}. `, { bold: true, size: 22 }), ...runs(title, { size: 22 })] });
}
const note = (txt) => new Paragraph({ spacing: { ...SINGLE, before: 60, after: 240 }, children: runs(txt, { size: 20 }) });

const f2 = C.f2;
const T = C.T;
const tables = {
  t1: { cap: ["Table 1", "Selected related work compared on timing use and honeypot behaviour change."],
    w: [1500, 1800, 1650, 1450, 1426, 1200],
    head: ["Work", "Honeypot data", "Grouped or assessed", "Timing", "Honeypot changes behaviour", "Operator ground truth"],
    rows: [
      ["Almotairi et al. (2007)", "Network honeypot traffic", "Traffic clusters by inter-arrival times", "Passive", "No", "None"],
      ["Crespi et al. (2021)", "Honeypot-as-a-service network, up to 90 million sessions", "Source addresses and sessions", "Timestamps for a longitudinal view", "No", "None"],
      ["Shamsi et al. (2022)", "Five honeypot types, 5.55 million Cowrie sessions", "Attacking addresses", "Passive (intervals, timestamps)", "No", "None"],
      ["Zhu et al. (2022)", "Telnet, 4,855 request logs", "Bot loader families", "Not used", "No", "Control run of known loaders"],
      ["Wagener (2011)", "High-interaction honeypot", "Attacker skill and reactions", "Not checked", "Yes (blocking, errors, insults)", "Not applicable"],
      ["Schneider et al. (2021)", "Three honeypots, over 200 sessions", "Reaction to blocking and insults", "Duration and command count only", "Yes (blocking, insults)", "Not applicable"],
      ["This work", "SSH and HTTP decoys", "Sessions linked to persistent actors", "Active: reaction time to controlled delays", "Yes (timing)", "Weak labels only"],
    ],
    note: "\"Not used\" means the work does not use the signal; \"not checked\" means the full text could not be read. The row for this work describes the design; its evidence is limited to simulated and scripted traffic." },
  t2: { cap: ["Table 2", "Perturbation regimes applied to treatment sessions."], w: [2300, 2100, 4626],
    head: ["Regime", "Applies from command index", "Added delay"],
    rows: [
      ["R0 baseline", "0", "None"],
      ["R1 slowdown", "2", "100 ms"],
      ["R2 jitter", "4", "Random integer from 50 to 199 ms"],
      ["R3 filesystem latency", "6", "200 ms for commands that touch the emulated filesystem, otherwise 50 ms; the SSH response is also sent in at most 15 chunks with gaps of 20 to 80 ms, capped at 0.3 s in total"],
    ],
    note: "Indices count commands from 0. Control sessions use R0 throughout." },
  t3: { cap: ["Table 3", "Signals recorded by the decoy and their role."], w: [3100, 900, 2300, 2726],
    head: ["Signal", "Protocol", "Recorded", "Role"],
    rows: [
      ["HASSH: hash of the client's key-exchange, cipher, MAC and compression algorithm lists (Salesforce, n.d.)", "SSH", "Once per connection", "Corroboration only"],
      ["Offered public-key fingerprints", "SSH", "Each offer (always refused)", "Corroboration; weak-label source"],
      ["Login-attempt order", "SSH", "Each attempt", "Corroboration"],
      ["HTTP header-name order (hashed)", "HTTP", "Once per session", "Corroboration only"],
      ["User-Agent", "HTTP", "Once per session", "Corroboration only"],
      ["Download addresses in commands", "SSH", "At analysis time", "Corroboration; weak-label source"],
      ["Control or treatment arm", "Both", "When the control share is above 0", "Analysis"],
    ],
    note: "None of these signals is part of the embedding." },
  t4: { cap: ["Table 4", "Model configuration of the two embedding backends."], w: [2200, 6826],
    head: ["Item", "Configuration"],
    rows: [
      ["Transformer input", "One step per command, 11 values: log Δt / 20; six command-structure indicators; one-hot of the regime reacted to (zeros and Δt = 0 for command 0)"],
      ["Transformer encoder", "Linear projection to 32 dimensions, learned positions, 2 encoder layers, 4 heads, feed-forward width 64, masked mean pooling, L2 normalisation"],
      ["Transformer training", "Supervised contrastive loss, temperature 0.1; AdamW, learning rate 0.001, weight decay 0.0001; 1,500 steps; 8 archetypes × 4 sessions per batch; seed 42; final loss 1.13"],
      ["PCA input", "Median and spread of log Δt per regime reacted to; ratios to baseline; adaptation measure; six command-structure means; 10 TF-IDF features of command text"],
      ["PCA reduction", "Standardisation and PCA fitted on the analysed batch; 95% of variance kept; zero-padded to 32 dimensions"],
      ["Hash", "32 × 64 Gaussian matrix, fixed seed; sign of each projection gives one bit (64 bits)"],
      ["Clustering", "First-match, Hamming distance at most 6 (PCA) or 10 (Transformer)"],
    ],
    note: "TF-IDF: term-frequency inverse-document-frequency." },
  t5: { cap: ["Table 5", "Attribution on the simulator: adjusted Rand index (predicted actors)."], w: [3500, 1300, 2113, 2113],
    head: ["Scenario", "True actors", "PCA backend", "Transformer backend"],
    rows: [
      ["Script A and script B, equal length", "2", "1.00 (2)", "1.00 (2)"],
      ["Script A and script B, unequal length", "2", "1.00 (2)", "1.00 (2)"],
      ["Six unseen archetypes, draw 1000", "6", "0.96 (9)", "1.00 (6)"],
      ["Six unseen archetypes, mean of draws 1001 to 1010", "6", `${f2(T("pca", 6).ari_mean)} (${T("pca", 6).actors_mean.toFixed(1)} on average)`, `${f2(T("transformer", 10).ari_mean)} (${T("transformer", 10).actors_mean.toFixed(1)} on average)`],
      ["Same draws, lowest and highest single draw", "6", `${f2(T("pca", 6).ari_min)} and 1.00`, `${f2(T("transformer", 10).ari_min)} and 1.00`],
    ],
    note: "Deployed thresholds: 6 bits (PCA) and 10 bits (Transformer). Scores are for a simulator and are not a measure of accuracy on real attackers." },
  t6: { cap: ["Table 6", "Hash changes between batches: Hamming distance for the same session."], w: [1700, 2150, 900, 900, 800, 1300, 1276],
    head: ["Backend", "First batch", "Mean (bits)", "Median", "Max", "Beyond threshold", "Identical"],
    rows: [
      ["PCA", "Half of each archetype", "9.7", "7", "28", "55%", "3%"],
      ["PCA", "Two of six archetypes", "31.0", "30", "60", "98%", "0%"],
      ["Transformer", "Half of each archetype", "0.0", "0", "0", "0%", "100%"],
      ["Transformer", "Two of six archetypes", "0.0", "0", "0", "0%", "100%"],
    ],
    note: "Each row compares the hashes of the sessions present in both the first batch and the full batch of 120 sessions (draw 1000). Thresholds: 6 bits (PCA) and 10 bits (Transformer)." },
};

const figs = {
  fig1: { file: "fig1_architecture.png", cap: ["Fig. 1", "Architecture of the decoy, telemetry, analytics and analyst tooling."],
    legend: "The attacker connects to the decoy listener, which runs on an isolated host. The perturbation engine delays responses according to the regime schedule. Command events, signals, login attempts and alerts are recorded as telemetry. The analytics layer turns each session into an embedding and a 64-bit hash, assigns it to an actor and stores the actor in a registry that the dashboard reads. Signals are recorded to corroborate groupings and are not part of the embedding." },
  fig2: { file: "fig2_live_session.png", cap: ["Fig. 2", "Reaction times of a scripted client across the four perturbation regimes."],
    legend: "One session of the scripted client against the running decoy. Each point is the time from the end of the decoy's response to the arrival of the next command, excluding the delay the decoy injected. Shading shows the regime of the response each command reacts to. Command 0 has no preceding response and is not plotted. The client pauses 0.1 s between commands, so its reaction time does not change with the regime." },
  fig3: { file: "fig3_threshold.png", cap: ["Fig. 3", "Effect of the Hamming threshold on attribution for both embedding backends."],
    legend: "(a) Mean adjusted Rand index and (b) mean number of predicted actors (logarithmic axis; true number 6) over ten simulated draws of six archetypes (seeds 1001 to 1010), as the Hamming threshold varies. The dotted vertical line marks the deployed PCA threshold (6 bits) and the dash-dotted line the deployed Transformer threshold (10 bits)." },
  fig4: { file: "fig4_length.png", cap: ["Fig. 4", "Effect of session length on attribution for both embedding backends."],
    legend: "(a) Mean adjusted Rand index and (b) mean number of predicted actors over five simulated draws (seeds 1001 to 1005) when every session is cut to its first n commands (\"full\": sessions of 15 to 60 commands), at the deployed thresholds." },
};
function pngSize(f) { const b = fs.readFileSync(f); return [b.readUInt32BE(16), b.readUInt32BE(20)]; }
function figureBlocks(key) {
  const g = figs[key];
  const file = path.join(FIG, g.file);
  const [w, h] = pngSize(file);
  const width = 580;
  return [
    new Paragraph({ spacing: { ...SINGLE, before: 200 }, alignment: AlignmentType.CENTER, keepNext: true,
      children: [new ImageRun({ type: "png", data: fs.readFileSync(file), transformation: { width, height: Math.round((width * h) / w) },
        altText: { title: g.cap[0], description: g.cap[1], name: key } })] }),
    new Paragraph({ spacing: { ...SINGLE, before: 80 }, keepNext: true, children: [...runs(`${g.cap[0]}. `, { bold: true, size: 22 }), ...runs(g.cap[1], { size: 22 })] }),
    new Paragraph({ spacing: { ...SINGLE, before: 40, after: 240 }, children: runs(g.legend, { size: 20 }) }),
  ];
}

// ---------- references ----------
const REFS = [
  ["Almotairi 2007", "Almotairi, S., Clark, A., Dacier, M., Leita, C., Mohay, G., Pham, V.H., Thonnard, O., Zimmermann, J., 2007. Extracting inter-arrival time based behaviour from honeypot traffic using cliques, in: Proceedings of the 5th Australian Digital Forensics Conference, Mount Lawley, Australia."],
  ["Boffa 2022a", "Boffa, M., Milan, G., Vassio, L., Drago, I., Mellia, M., Ben Houidi, Z., 2022a. Towards NLP-based processing of honeypot logs, in: 2022 IEEE European Symposium on Security and Privacy Workshops (EuroS&PW), pp. 314–321. https://doi.org/10.1109/EuroSPW55150.2022.00038."],
  ["Boffa 2022b", "Boffa, M., Vassio, L., Mellia, M., Drago, I., Milan, G., Ben Houidi, Z., Rossi, D., 2022b. On using pretext tasks to learn representations from network logs, in: Proceedings of the 1st International Workshop on Native Network Intelligence, pp. 21–26. https://doi.org/10.1145/3565009.3569522."],
  ["Bridges 2026", "Bridges, R.A., Mitchell, T.R., Muñoz, M., Henriksson, T., 2026. SoK: Honeypots & LLMs, more than the sum of their parts?, in: 2026 IEEE 11th European Symposium on Security and Privacy (EuroS&P), pp. 910–928. https://doi.org/10.1109/EuroSP68448.2026.00063."],
  ["Charikar 2002", "Charikar, M.S., 2002. Similarity estimation techniques from rounding algorithms, in: Proceedings of the 34th Annual ACM Symposium on Theory of Computing, pp. 380–388. https://doi.org/10.1145/509907.509965."],
  ["Crespi 2021", "Crespi, V., Hardaker, W., Abu-El-Haija, S., Galstyan, A., 2021. Identifying botnet IP address clusters using natural language processing techniques on honeypot command logs. arXiv:2104.10232."],
  ["Deshmukh 2019", "Deshmukh, S., Rade, R., Kazi, F., 2019. Attacker behaviour profiling using stochastic ensemble of hidden Markov models. arXiv:1905.11824."],
  ["Dulaunoy 2022", "Dulaunoy, A., Huynen, J.-L., Thirion, A., 2022. Active and passive collection of SSH key material for cyber threat intelligence. arXiv:2204.04922."],
  ["Dumont 2019", "Dumont, P., Meier, R., Gugelmann, D., Lenders, V., 2019. Detection of malicious remote shell sessions, in: 2019 11th International Conference on Cyber Conflict (CyCon), pp. 1–20. https://doi.org/10.23919/CYCON.2019.8757163."],
  ["Dykstra 2025", "Dykstra, J., Shortridge, K., Met, J., Hough, D., 2025. Sludge for good: Slowing and imposing costs on cyber attackers, in: Proceedings of the Hawaii International Conference on System Sciences. https://doi.org/10.24251/HICSS.2025.132."],
  ["Ediga 2026", "Ediga, M., Chattopadhyay, S., 2026. Trace: Unmasking AI attack agents through terminal behavior fingerprinting. arXiv:2605.01186."],
  ["Fan 2018", "Fan, W., Du, Z., Fernández, D., Villagrá, V.A., 2018. Enabling an anatomic view to investigate honeypot systems: A survey. IEEE Syst. J. 12, 3906–3919. https://doi.org/10.1109/JSYST.2017.2762161."],
  ["Guan 2023", "Guan, C., Liu, H., Cao, G., Zhu, S., La Porta, T., 2023. HoneyIoT: Adaptive high-interaction honeypot for IoT devices through reinforcement learning, in: Proceedings of the 16th ACM Conference on Security and Privacy in Wireless and Mobile Networks, pp. 49–59. https://doi.org/10.1145/3558482.3590195."],
  ["Haikal 2025", "Haikal, T., Hammad, E., Ismail, S., 2025. Characterizing large-scale adversarial activities through large-scale honey-nets. arXiv:2512.06557."],
  ["Holz 2005", "Holz, T., Raynal, F., 2005. Detecting honeypots and other suspicious environments, in: Proceedings of the Sixth Annual IEEE SMC Information Assurance Workshop, pp. 29–36. https://doi.org/10.1109/IAW.2005.1495930."],
  ["Huang 2019", "Huang, L., Zhu, Q., 2019. Adaptive honeypot engagement through reinforcement learning of semi-Markov decision processes, in: Decision and Game Theory for Security (GameSec 2019), Lecture Notes in Computer Science, pp. 196–216. https://doi.org/10.1007/978-3-030-32430-8_13."],
  ["Hubert 1985", "Hubert, L., Arabie, P., 1985. Comparing partitions. J. Classif. 2, 193–218. https://doi.org/10.1007/BF01908075."],
  ["Kang 2026", "Kang, D., Jeong, H., Sheffey, J., Datta, P., Houmansadr, A., 2026. Whose agent are you? Multi-layer fingerprinting and attribution of autonomous web agents. arXiv:2606.20910."],
  ["Khosla 2020", "Khosla, P., Teterwak, P., Wang, C., Sarna, A., Tian, Y., Isola, P., Maschinot, A., Liu, C., Krishnan, D., 2020. Supervised contrastive learning, in: Advances in Neural Information Processing Systems 33. arXiv:2004.11362."],
  ["Kuzminykh 2020", "Kuzminykh, I., Ghita, B., Silonosov, A., 2020. Impact of network and host characteristics on the keystroke pattern in remote desktop sessions. arXiv:2012.03577."],
  ["Passino 2025", "Sanna Passino, F., Mantziou, A., Ghani, D., Thiede, P., Bevington, R., Heard, N.A., 2025. Nested Dirichlet models for unsupervised attack pattern detection in honeypot data. Ann. Appl. Stat. 19, 586–613. https://doi.org/10.1214/24-AOAS1974."],
  ["Salesforce n.d.", "Salesforce, n.d. HASSH: SSH client and server fingerprinting. https://github.com/salesforce/hassh (accessed 27 October 2026)."],
  ["Schneider 2021", "Schneider, D., Fraunholz, D., Krohmer, D., 2021. A qualitative empirical analysis of human post-exploitation behavior. arXiv:2101.02102."],
  ["Shamsi 2022", "Shamsi, Z., Zhang, D., Kyoung, D., Liu, A., 2022. Measuring and clustering network attackers using medium-interaction honeypots, in: 2022 IEEE European Symposium on Security and Privacy Workshops (EuroS&PW), pp. 294–306. https://doi.org/10.1109/EuroSPW55150.2022.00036."],
  ["Sladić 2024", "Sladić, M., Valeros, V., Catania, C., Garcia, S., 2024. LLM in the shell: Generative honeypots, in: 2024 IEEE European Symposium on Security and Privacy Workshops (EuroS&PW), pp. 430–435. https://doi.org/10.1109/EuroSPW61312.2024.00054."],
  ["Song 2001", "Song, D.X., Wagner, D., Tian, X., 2001. Timing analysis of keystrokes and timing attacks on SSH, in: Proceedings of the 10th USENIX Security Symposium."],
  ["Srinivasa 2023", "Srinivasa, S., Pedersen, J.M., Vasilomanolakis, E., 2023. Gotta catch 'em all: A multistage framework for honeypot fingerprinting. Digit. Threats Res. Pract. 4, 1–28. https://doi.org/10.1145/3584976."],
  ["Udhani 2019", "Udhani, S., Withers, A., Bashir, M., 2019. Human vs bots: Detecting human attacks in a honeypot environment, in: 2019 7th International Symposium on Digital Forensics and Security (ISDFS), pp. 1–6. https://doi.org/10.1109/ISDFS.2019.8757534."],
  ["Valeros 2023", "Valeros, V., Rigaki, M., Garcia, S., 2023. Attacker profiling through analysis of attack patterns in geographically distributed honeypots. arXiv:2305.01346."],
  ["Valeros 2026", "Valeros, V., Sladić, M., Garcia, S., 2026. Ghost without shell: Measuring non-interactive SSH attacks on honeypots. arXiv:2606.28006."],
  ["Vaswani 2017", "Vaswani, A., Shazeer, N., Parmar, N., Uszkoreit, J., Jones, L., Gomez, A.N., Kaiser, L., Polosukhin, I., 2017. Attention is all you need, in: Advances in Neural Information Processing Systems 30. arXiv:1706.03762."],
  ["Vetterl 2018", "Vetterl, A., Clayton, R., 2018. Bitter harvest: Systematically fingerprinting low- and medium-interaction honeypots at internet scale, in: 12th USENIX Workshop on Offensive Technologies (WOOT 18), Baltimore. https://www.usenix.org/conference/woot18/presentation/vetterl."],
  ["Wagener 2011", "Wagener, G., 2011. Self-adaptive honeypots coercing and assessing attacker behaviour. PhD thesis, Université Henri Poincaré, Nancy 1. https://theses.hal.science/tel-00627981."],
  ["Wang 2018", "Wang, P.-H., Liao, I.-E., Kao, K.-F., Huang, J.-Y., 2018. An intrusion detection method based on log sequence clustering of honeypot for Modbus TCP protocol, in: 2018 IEEE International Conference on Applied System Innovation (ICASI), pp. 255–258. https://doi.org/10.1109/ICASI.2018.8394581."],
  ["Wang 2026", "Wang, Z., You, J., Wang, H., Yuan, T., Lv, S., Wang, Y., Sun, L., 2026. HoneyGPT: Breaking the trilemma in honeypots with large language models. Comput. Netw. 282, 112223. https://doi.org/10.1016/j.comnet.2026.112223."],
  ["Weinberg 2026", "Weinberg, A.I., 2026. ARCANE: Cross-campaign attacker re-identification via passive beacon telemetry: A Bayesian network framework for longitudinal cyber attribution. arXiv:2604.24644."],
  ["Yurcik 2005", "Yurcik, W., Liu, C., 2005. A first step toward detecting SSH identity theft in HPC cluster environments: Discriminating masqueraders based on command behavior, in: CCGrid 2005 IEEE International Symposium on Cluster Computing and the Grid, vol. 1, pp. 111–120. https://doi.org/10.1109/CCGRID.2005.1558542."],
  ["Zhang 2021", "Zhang, L., Thing, V.L.L., 2021. Three decades of deception techniques in active cyber defense: Retrospect and outlook. Comput. Secur. 106, 102288. https://doi.org/10.1016/j.cose.2021.102288."],
  ["Zhu 2022", "Zhu, Y., Chen, Z., Yan, Q., Wang, S., Li, E., Peng, L., Zhao, C., 2022. Mining function homology of bot loaders from honeypot logs. arXiv:2206.00385."],
  ["Zhu 2023", "Zhu, Q., 2023. The doctrine of cyber effect: An ethics framework for defensive cyber deception. arXiv:2302.13362."],
];

// ---------- assemble ----------
const kids = [];
const AUTH = [["Keshav Agarwal", "a"], ["Yuvraj Agrawal", "a"], ["Alen Varghese Soji", "a,*"], ["Sudha S", "a"]];
kids.push(new Paragraph({ spacing: { ...SINGLE, after: 240 }, alignment: AlignmentType.CENTER, children: runs(C.title, { bold: true, size: 32 }) }));
kids.push(new Paragraph({ spacing: { ...SINGLE, after: 120 }, alignment: AlignmentType.CENTER,
  children: AUTH.flatMap(([n, a], i) => [new TextRun({ text: n, font: FONT, size: 24 }), new TextRun({ text: a, font: FONT, size: 24, superScript: true }),
    new TextRun({ text: i < AUTH.length - 1 ? ", " : "", font: FONT, size: 24 })]) }));
kids.push(new Paragraph({ spacing: { ...SINGLE, after: 120 }, alignment: AlignmentType.CENTER,
  children: [new TextRun({ text: "a", font: FONT, size: 22, superScript: true }), new TextRun({ text: " School of Computer Science and Engineering (SCOPE), Vellore Institute of Technology, Vellore 632014, Tamil Nadu, India", font: FONT, size: 22, italics: true })] }));
kids.push(new Paragraph({ spacing: { ...SINGLE, after: 360 }, alignment: AlignmentType.CENTER,
  children: [new TextRun({ text: "* Corresponding author. Alen Varghese Soji. Email: alenvarghese.soji2023@vitstudent.ac.in", font: FONT, size: 22 })] }));
kids.push(unnumbered("Abstract"));
kids.push(para(C.abstract));
kids.push(para(`**Keywords:** ${C.keywords.join("; ")}`));

for (const b of C.body) {
  if (b.h1) kids.push(h1(b.h1));
  else if (b.h2) kids.push(h2(b.h2));
  else if (b.p) kids.push(para(b.p));
  else if (b.table) {
    const t = tables[b.table];
    kids.push(caption(t.cap[0], t.cap[1]), table(t.w, t.head, t.rows), note(t.note));
  } else if (b.fig) kids.push(...figureBlocks(b.fig));
}

kids.push(unnumbered("Declaration of generative AI and AI-assisted technologies in the manuscript preparation process"));
kids.push(para(`During the preparation of this work the authors used Claude (Anthropic) to draft and edit the text, to search for and summarise the literature, and to write and test parts of the software and the analysis scripts described in the paper. After using this tool, the authors reviewed and edited the content as needed and take full responsibility for the content of the published article.`));
kids.push(unnumbered("Declaration of competing interest"));
kids.push(para(`The authors declare that they have no known competing financial interests or personal relationships that could have appeared to influence the work reported in this paper.`));
kids.push(unnumbered("Funding"));
kids.push(para(`This research did not receive any specific grant from funding agencies in the public, commercial, or not-for-profit sectors.`));
kids.push(unnumbered("Data availability"));
kids.push(para(`No real network traffic was collected or analysed. All results are produced by the project's simulator from the seeds stated in Sections 5 and 6 or are logs of scripted runs against the decoy. The software, the simulator, the trained Transformer weights and the scripts that produce every result in Section 6 are in the project repository (project name: CERDA-Decoy; home page: https://github.com/alensoji2005/CERDA-Decoy; operating system: platform independent, developed and tested on Windows; programming language: Python 3.10 or later; other requirements: PyTorch, scikit-learn, pandas, asyncssh, aiohttp and Streamlit, as listed in requirements.txt). The commands that regenerate each result are listed in Appendix A. The software is released under the MIT licence. The version used for every result in this paper is the tagged release v1.0.0 (https://github.com/alensoji2005/CERDA-Decoy/releases/tag/v1.0.0).`));
kids.push(unnumbered("CRediT authorship contribution statement"));
kids.push(para(`Keshav Agarwal: Software, Investigation, Writing – review and editing. Yuvraj Agrawal: Software, Investigation, Writing – review and editing. Alen Varghese Soji: Conceptualization, Methodology, Software, Investigation, Formal analysis, Data curation, Validation, Visualization, Writing – original draft, Writing – review and editing, Project administration. Sudha S: Supervision, Writing – review and editing.`));
kids.push(unnumbered("Acknowledgements"));
kids.push(para(`None.`));

kids.push(unnumbered("Appendix A. Reproducing the results"));
kids.push(para(`All commands are run from the repository root. The results correspond to release v1.0.0.`, {}));
[
  "python -m pytest : runs the automated tests (57 at the time of writing).",
  "python -m scripts.train_transformer : trains the Transformer encoder (defaults: seed 42, 1,500 steps).",
  "python -m src.analytics.benchmark : the scenarios of Table 5 on the main draw (seed 1000).",
  "python -m scripts.sensitivity out.json : the threshold, arrival-order and session-length analyses (Figs. 3 and 4; draws 1001 to 1010).",
  "python -m scripts.hash_stability : the batch-dependence analysis (Table 6).",
  "python -m scripts.generate_demo_data, then python decoy_server.py and python -m scripts.bot_attacker : the scripted live runs (Section 6.6).",
].forEach((t) => kids.push(para(t, { indent: { left: 360 } })));

kids.push(unnumbered("References"));
REFS.slice().sort((a, b) => a[1].localeCompare(b[1], "en")).forEach(([, text]) =>
  kids.push(new Paragraph({ spacing: DOUBLE, indent: { left: 720, hanging: 720 }, children: runs(text) })));

const doc = new Document({
  creator: "", title: C.title,
  styles: { default: { document: { run: { font: FONT, size: 24 } } } },
  sections: [{
    properties: {
      page: { size: { width: 11906, height: 16838 }, margin: { top: 1440, right: 1440, bottom: 1440, left: 1440 } },
      lineNumbers: { countBy: 1, restart: LineNumberRestartFormat.CONTINUOUS },
    },
    footers: { default: new Footer({ children: [new Paragraph({ alignment: AlignmentType.CENTER, children: [new TextRun({ children: [PageNumber.CURRENT], font: FONT, size: 20 })] })] }) },
    children: kids,
  }],
});
Packer.toBuffer(doc).then((buf) => { fs.writeFileSync(OUT, buf); console.log("manuscript written", OUT, buf.length); });

// ---------- highlights file ----------
const hl = new Document({ sections: [{ children: [
  new Paragraph({ spacing: SINGLE, children: runs("Highlights", { bold: true, size: 28 }) }),
  new Paragraph({ spacing: { ...SINGLE, after: 120 }, children: runs(C.title, { italics: true }) }),
  ...C.highlights.map((h) => new Paragraph({ spacing: { ...SINGLE, after: 80 }, bullet: { level: 0 }, children: runs(h) })),
] }] });
Packer.toBuffer(hl).then((buf) => { fs.writeFileSync(OUT.replace(/\.docx$/, "_highlights.docx"), buf); console.log("highlights written"); });

module.exports = { REFS, tables };
