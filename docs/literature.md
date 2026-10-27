# CERDA paper: verified literature (2026-10-27)

Scope: this file holds **citations only**. All statements about CERDA itself will be written from the report (Final_Report_BCSE497J_Revised.docx) and the codebase. The old IEEE draft is not used.

## How each entry was checked
- **Crossref** (api.crossref.org): DOI, authors, venue, year, volume, pages.
- **arXiv** (research-paper index): authors and abstract for preprints.
- **Publisher page** (USENIX, ACM, Eurecom): papers with no DOI.
- **GitHub API**: software repositories.
Nothing below was taken from memory alone. Entries marked **[preprint]** exist only as arXiv versions in my check; before submission, look for a published version and cite that instead.

## A. The report's own references, corrected
Fixes needed in the existing reference list (report numbers in brackets):

| Key | Fix / full details | Verified via |
|---|---|---|
| Shafi2025 [1] | Shafi, M., Lashkari, A.H., Haghighian Roudsari, A., 2025. NTLFlowLyzer: Towards generating an intrusion detection dataset and intruders behavior profiling through network and transport layers traffic analysis and pattern extraction. *Computers & Security* 148, 104160. doi:10.1016/j.cose.2024.104160 | Crossref |
| Dong2023 [2] | Dong, C., Yang, J., Liu, S., Wang, Z., Liu, Y., Lu, Z., 2023. C-BEDIM and S-BEDIM: Lateral movement detection in enterprise network through behavior deviation measurement. *Computers & Security* 130, 103267. doi:10.1016/j.cose.2023.103267 | Crossref (first 4 authors seen; the last two come from the report) |
| Pendyala2025 [3] | Journal is *International Journal of Computers and Applications* 47, 1076-1105. doi:10.1080/1206212x.2025.2584106 | Crossref |
| Sethuraman2023 [4] | *Computer Science Review* 50, 100600. doi:10.1016/j.cosrev.2023.100600 | Crossref |
| Hans2025 [5] | Published in *AHFE International* 199. doi:10.54941/ahfe1007047. The arXiv ID in the report (2510.20930) is correct; cite the published version. Crossref spells the third author "Sofia", arXiv "Sophia": check which is right. | Crossref, arXiv |
| Nisha2023 [6] | **Authors are Nisha T. N. and Dhanya Pramod** (report has "N. T. N."). **Year 2023, not 2024.** *Journal of Computer Information Systems* 64(1), 106-123. doi:10.1080/08874417.2023.2175337 | Crossref |
| Salih2021 [7] | doi:10.1109/iec52205.2021.9476132, pp. 61-66 | Crossref |
| Udhani2019 [8] | doi:10.1109/isdfs.2019.8757534, pp. 1-6 | Crossref |
| Yurcik2005 [9] | **Report has no authors.** Yurcik, W., Liu, C., 2005. *CCGrid 2005*, vol. 1, pp. 111-120. doi:10.1109/ccgrid.2005.1558542 | Crossref |
| Boffa2022a [10] | EuroS&PW 2022, pp. 314-321. doi:10.1109/eurospw55150.2022.00038. Authors: Boffa, Milan, Vassio, Drago, Mellia, Ben Houidi (matches report). | Crossref |
| Almotairi2007 [11] | **Report has no authors.** Almotairi, S., Clark, A., Dacier, M., Leita, C., Mohay, G., Pham, V.H., Thonnard, O., Zimmermann, J., 2007. In: *5th Australian Digital Forensics Conference (ADF 2007)*, Mount Lawley, Australia. No DOI. | Eurecom publication page |
| Dumont2019 [12] | CyCon 2019, pp. 1-20. doi:10.23919/cycon.2019.8757163 | Crossref |
| Passino2025 [13] | Now published: Sanna Passino, F., Mantziou, A., Ghani, D., Thiede, P., Bevington, R., Heard, N.A., 2025. *Annals of Applied Statistics* 19(1), 586-613. doi:10.1214/24-aoas1974. Cite this, not the arXiv version. | Crossref |
| Boffa2022b [14] | **Author order in the report is wrong.** Correct: Boffa, Vassio, Mellia, Drago, Milan, Ben Houidi, Rossi. *1st International Workshop on Native Network Intelligence*, Dec 2022, pp. 21-26. doi:10.1145/3565009.3569522 | Crossref |
| Ondrikov2026 [15] | *Int. J. Critical Infrastructure Protection* 55, 100898. doi:10.1016/j.ijcip.2026.100898 | Crossref |
| Asulba2024 [16] | doi:10.1145/3726122.3726166, pp. 295-304 | Crossref |
| Wang2018 [17] | ICASI 2018, pp. 255-258. doi:10.1109/icasi.2018.8394581 | Crossref |

## B. New references to add

### Honeypot clustering and attribution (closest prior work)
| Key | Citation | Notes | Verified via |
|---|---|---|---|
| Crespi2021 | Crespi, V., Hardaker, W., Abu-El-Haija, S., Galstyan, A. Identifying botnet IP address clusters using natural language processing techniques on honeypot command logs. arXiv:2104.10232, 2021. **[preprint]** | Clusters botnet source IPs from honeypot shell commands | arXiv |
| Shamsi2022 | Shamsi, Z., Zhang, D., Kyoung, D., Liu, A. Measuring and clustering network attackers using medium-interaction honeypots. arXiv:2206.13614, 2022. **[preprint]** | Finds IPs likely controlled by one operator | arXiv |
| Zhu2022 | Zhu, Y., Chen, Z., Yan, Q., Wang, S., Li, E., Peng, L., Zhao, C. Mining function homology of bot loaders from honeypot logs. arXiv:2206.00385, 2022. **[preprint]** | Clusters loader families | arXiv |
| Deshmukh2019 | Deshmukh, S., Rade, R., Kazi, F. Attacker behaviour profiling using stochastic ensemble of hidden Markov models. arXiv:1905.11824, 2019. **[preprint]** | Cowrie data, sequence modelling | arXiv |
| Valeros2023 | Valeros, V., Rigaki, M., Garcia, S. Attacker profiling through analysis of attack patterns in geographically distributed honeypots. arXiv:2305.01346, 2023. **[preprint]** | Behavioural profiles of attackers | arXiv |
| Valeros2026 | Valeros, V., Sladić, M., Garcia, S. Ghost without shell: measuring non-interactive SSH attacks on honeypots. arXiv:2606.28006, 2026. **[preprint]** | **Important for the limitations section:** 99.23% of 177,622 authenticated sessions were non-interactive. Interactive attribution may apply to very few real sessions. | arXiv |
| Ediga2026 | Ediga, M., Chattopadhyay, S. Trace: Unmasking AI attack agents through terminal behavior fingerprinting. arXiv:2605.01186, 2026. **[preprint]** | Attribution from terminal command sequences, for AI agents | arXiv |

### Engagement and adaptive honeypots
| Key | Citation | Verified via |
|---|---|---|
| Huang2019 | Huang, L., Zhu, Q. Adaptive honeypot engagement through reinforcement learning of semi-Markov decision processes. arXiv:1906.12182, 2019. **[preprint]** | arXiv |
| Guan2023 | Guan, C., Liu, H., Cao, G., Zhu, S., La Porta, T. HoneyIoT: Adaptive high-interaction honeypot for IoT devices through reinforcement learning. arXiv:2305.06430, 2023. **[preprint]** | arXiv |

### LLM honeypots (relevant because the decoy has an optional LLM mode)
| Key | Citation | Verified via |
|---|---|---|
| Sladic2023 | Sladić, M., Valeros, V., Catania, C., Garcia, S. LLM in the shell: Generative honeypots. arXiv:2309.00155, 2023. **[preprint]** | arXiv |
| Wang2024 | Wang, Z., You, J., Wang, H., Yuan, T., Lv, S., Wang, Y., Sun, L. HoneyGPT: Breaking the trilemma in terminal honeypots with large language model. arXiv:2406.01882, 2024. **[preprint]** | arXiv |
| Bridges2025 | Bridges, R.A., Mitchell, T.R., Muñoz, M., Henriksson, T. SoK: Honeypots & LLMs, more than the sum of their parts? arXiv:2510.25939, 2025. **[preprint]** | arXiv |

### Honeypot detectability (needed for the detectability threat)
| Key | Citation | Verified via |
|---|---|---|
| Holz2005 | Holz, T., Raynal, F., 2005. Detecting honeypots and other suspicious environments. In: *Proc. 6th Annual IEEE SMC Information Assurance Workshop*, pp. 29-36. doi:10.1109/iaw.2005.1495930 | Crossref |
| Vetterl2018 | Vetterl, A., Clayton, R., 2018. Bitter harvest: Systematically fingerprinting low- and medium-interaction honeypots at internet scale. In: *12th USENIX Workshop on Offensive Technologies (WOOT 18)*, Baltimore. https://www.usenix.org/conference/woot18/presentation/vetterl | USENIX page |
| Srinivasa2021 | Srinivasa, S., Pedersen, J.M., Vasilomanolakis, E. Gotta catch 'em all: a multistage framework for honeypot fingerprinting. arXiv:2109.10652, 2021. **[preprint]** | arXiv |
| Williams2024 | Williams, J., Edwards, M., Gardiner, J. Time-to-lie: Identifying industrial control system honeypots using the Internet Control Message Protocol. arXiv:2410.17731, 2024. **[preprint]** | arXiv |

### Surveys
| Key | Citation | Verified via |
|---|---|---|
| Zhang2021 | Zhang, L., Thing, V.L.L., 2021. Three decades of deception techniques in active cyber defense: Retrospect and outlook. *Computers & Security* 106, 102288. doi:10.1016/j.cose.2021.102288. **Same journal as the target, so cite it.** | Crossref |
| Fan2018 | Fan, W., Du, Z., Fernández, D., Villagrá, V.A., 2018. Enabling an anatomic view to investigate honeypot systems: A survey. *IEEE Systems Journal* 12, 3906-3919. doi:10.1109/jsyst.2017.2762161 | Crossref |

### Timing, SSH signals and botnets
| Key | Citation | Verified via |
|---|---|---|
| Song2001 | Song, D.X., Wagner, D., Tian, X., 2001. Timing analysis of keystrokes and timing attacks on SSH. In: *Proc. 10th USENIX Security Symposium*. ACM DL: 10.5555/1251327.1251352 | USENIX, ACM DL |
| Antonakakis2017 | Antonakakis, M., April, T., Bailey, M., Bernhard, M., et al., 2017. Understanding the Mirai botnet. In: *26th USENIX Security Symposium*. https://www.usenix.org/conference/usenixsecurity17/technical-sessions/presentation/antonakakis | USENIX page (full author list to copy from the page) |
| Dulaunoy2022 | Dulaunoy, A., Huynen, J.-L., Thirion, A. Active and passive collection of SSH key material for cyber threat intelligence. arXiv:2204.04922, 2022. **[preprint]** | arXiv |
| HASSH | Salesforce. HASSH: SSH client and server fingerprinting. https://github.com/salesforce/hassh (accessed 2026-10-27) | GitHub API, HTTP 200 |
| Cowrie | Cowrie SSH/Telnet honeypot. https://github.com/cowrie/cowrie (accessed 2026-10-27) | GitHub API, HTTP 200 |

### Methods the codebase uses
| Key | Where in the code | Citation | Verified via |
|---|---|---|---|
| Vaswani2017 | `SpatioTemporalTransformer` (nn.TransformerEncoder) | Vaswani, A., Shazeer, N., Parmar, N., Uszkoreit, J., Jones, L., Gomez, A.N., Kaiser, L., Polosukhin, I., 2017. Attention is all you need. *Advances in Neural Information Processing Systems* 30. arXiv:1706.03762 | arXiv |
| Khosla2020 | `scripts/train_transformer.py`, `supcon_loss` | Khosla, P., Teterwak, P., Wang, C., Sarna, A., Tian, Y., Isola, P., Maschinot, A., Liu, C., Krishnan, D., 2020. Supervised contrastive learning. arXiv:2004.11362 (published in NeurIPS 33; confirm before citing) | arXiv |
| Charikar2002 | 64-bit sign-LSH CERF hash | Charikar, M.S., 2002. Similarity estimation techniques from rounding algorithms. In: *Proc. 34th ACM STOC*, pp. 380-388. doi:10.1145/509907.509965 | Crossref |
| Hubert1985 | Adjusted Rand index | Hubert, L., Arabie, P., 1985. Comparing partitions. *Journal of Classification* 2, 193-218. doi:10.1007/bf01908075 | Crossref |
| Vinh2009 | Optional: why ARI vs. other measures | Vinh, N.X., Epps, J., Bailey, J., 2009. Information theoretic measures for clusterings comparison. In: *Proc. 26th ICML*, pp. 1073-1080. doi:10.1145/1553374.1553511 | Crossref |
| Oliver2013 | Optional: LSH used for security data | Oliver, J., Cheng, C., Chen, Y., 2013. TLSH: A locality sensitive hash. In: *4th Cybercrime and Trustworthy Computing Workshop*, pp. 7-13. doi:10.1109/ctc.2013.9 | Crossref |

## C. Things this search found that the paper must handle honestly

1. **Training labels.** `scripts/train_transformer.py` trains the Transformer with a *supervised* contrastive loss on randomly generated archetypes (labels = archetype id). The report says clustering needs "no labelled data". That is true at clustering time, but the embedding is trained with synthetic labels. The paper must say so.
2. **The 1.00 ARI test is in-distribution.** Training and the six "unseen archetypes" both come from the same `random_family` generator. The report already says this; the paper has to keep that wording.
3. **Valeros2026** (99.23% non-interactive sessions) is a direct challenge: a reviewer may ask what fraction of real sessions CERDA's timing method can cover. Plan to report the interactive share of the real data.
4. **Closest prior work** is Crespi2021, Shamsi2022 and Zhu2022 (clustering sessions or IPs to find a common operator). The related-work section should compare against them explicitly, not only the five general IDS papers in the report.
5. **Detectability.** Vetterl2018 shows low- and medium-interaction honeypots can be fingerprinted from a single packet. The paper should state this as a threat to CERDA and cite the planned check against detection tools.

## D. Gaps: a second search pass is still needed
- **Active timing perturbation for attribution.** My searches (attacker-reaction-time probes, response-delay fingerprinting) returned no paper doing what CERDA does. That is **not** proof none exists: the pass was short, and the report itself warns against universal novelty claims. Run a dedicated pass (keystroke dynamics, active network fingerprinting, tarpit effects on bots) before wording any novelty claim.
- **Human vs. bot via timing:** only Udhani2019 and Song2001 so far.
- **TLS/JA3/JA4:** not searched, and the report defers TLS anyway.
- **Ethics and legality of honeypots:** not searched.
- **Candidates seen but not yet inspected:** Cross-Agent Campaign Attribution (arXiv:2607.18826), Characterizing Large-Scale Adversarial Activities Through Large-Scale Honey-Nets (arXiv:2512.06557), VelLMes (arXiv:2510.06975), a 4-month SSH honeypot dataset (Data in Brief, doi:10.1016/j.dib.2026.112860), Mapping Cyber Bot Behaviors (Sensors, doi:10.3390/s26010011).
- **Preprints:** 15 of the new entries are marked **[preprint]** (arXiv-only in my check). Look up published versions before submission. Khosla2020 and Vaswani2017 also need their proceedings details confirmed. (Second pass below found published versions for several.)

---

# Second pass (2026-10-27)

Same verification rules as above. The searches covered active probing and response delay, tarpits, keystroke timing, active fingerprinting, honeypot ethics, linking sessions across IPs, TLS fingerprinting, and a web search for any direct precedent.

## E. Novelty check: what I found and did not find

**Closest precedent (must be cited and discussed):**
- **Wagener, G., 2011. *Self-adaptive honeypots coercing and assessing attacker behaviour*. PhD thesis, Université Henri Poincaré, Nancy 1 / INRIA Lorraine / University of Luxembourg.** HAL: tel-00627981 (https://theses.hal.science/tel-00627981). Verified via the HAL API (the PDF itself is behind a bot challenge, so I read the abstract only). It builds honeypots that interfere with attackers (blocking commands, returning errors, insults) and uses the attackers' *reactions* to assess their skills, including as a reverse Turing test between humans and machines. Related paper: Wagener, G., State, R., Dulaunoy, A., Engel, T., 2010. Heliza: talking dirty to the attackers. *Journal in Computer Virology*. doi:10.1007/s11416-010-0150-4 (Crossref).
- **Schneider, D., Fraunholz, D., Krohmer, D. A qualitative empirical analysis of human post-exploitation behavior. arXiv:2101.02102, 2021 [preprint].** Same idea (blocking or insulting), 200+ sessions, finds attackers react differently.

**What this means.** "Perturb the honeypot and watch the attacker's reaction" is *not* new. What I have not found is anyone using **timing perturbation specifically**, measuring **reaction time net of the injected delay**, and turning it into a **hash used to link sessions to persistent actors**. My searches found no such paper, but the thesis full text was unreadable to me and search coverage is limited, so wording must be cautious: say "to our knowledge", describe the contribution as *combining* these elements, and cite Wagener explicitly as the precedent for reaction-based assessment. Do not claim the idea of adaptive perturbation as new.

## F. New references from the second pass

| Key | Citation | Use in paper | Verified via |
|---|---|---|---|
| Wagener2011 | See above (thesis) | Closest precedent for reaction-based assessment | HAL API |
| Wagener2010 | Wagener, G., State, R., Dulaunoy, A., Engel, T., 2010. Heliza: talking dirty to the attackers. *J. Comput. Virol.* doi:10.1007/s11416-010-0150-4 | Same | Crossref (volume/pages not retrieved) |
| Schneider2021 | arXiv:2101.02102 **[preprint]**. A Crossref search found no published version. | Attackers react to blocked/insulting responses | arXiv |
| Kuzminykh2020 | Kuzminykh, I., Ghita, B., Silonosov, A. Impact of network and host characteristics on the keystroke pattern in remote desktop sessions. arXiv:2012.03577, 2020 **[preprint]** | **Supports the network-latency limitation:** congestion latency changes timing features substantially. A later related paper exists (Computer Modeling and Intelligent Systems 2021, doi:10.32782/cmis/2864-21, different title: *On keystroke pattern variability in virtual desktop infrastructure*); confirm which to cite. | arXiv, Crossref |
| Dykstra2025 | Dykstra, J., Shortridge, K., Met, J., Hough, D., 2025. Sludge for good: Slowing and imposing costs on cyber attackers. *Proc. HICSS*. doi:10.24251/hicss.2025.132 | Delay as a defensive cost | Crossref (title and first authors match arXiv) |
| Reti2021 | Reti, D., Klaaßen, D., Duque Anton, S., Schotten, H.D., 2021. Secure (S)Hell: Introducing an SSH deception proxy framework. *CyberSA 2021*. doi:10.1109/cybersa52016.2021.9478201 | SSH deception | Crossref |
| Zhu2023ethics | Zhu, Q. The doctrine of cyber effect: An ethics framework for defensive cyber deception. arXiv:2302.13362, 2023 **[preprint]** | Ethics section | arXiv |
| Weinberg2026 | Weinberg, A.I. ARCANE: Cross-campaign attacker re-identification via passive beacon telemetry. arXiv:2604.24644, 2026 **[preprint]** | **Useful caution:** on synthetic data, separation between sophisticated actors is limited by shared practices (a ceiling from feature indistinguishability). Relevant to the limitations. | arXiv |
| Haikal2025 | Haikal, T., Hammad, E., Ismail, S. Characterizing large-scale adversarial activities through large-scale honey-nets. arXiv:2512.06557, 2025 **[preprint]** | Pseudonymisation (salted SHA-256) as a data-handling reference | arXiv |
| Kang2026 | Kang, D., Jeong, H., Sheffey, J., Datta, P., Houmansadr, A. Whose agent are you? Multi-layer fingerprinting and attribution of autonomous web agents. arXiv:2606.20910, 2026 **[preprint]** | Multi-layer fingerprinting (TLS, HTTP, behaviour) of automated clients | arXiv |

**Listed by the search but NOT verified (do not cite until checked):**
- A review of honeypot fingerprinting, detection and evasion, *Future Internet* 18(4):190, https://www.mdpi.com/1999-5903/18/4/190. Only the search snippet was read; authors unknown to me. It mentions timing and latency as fingerprinting vectors, so it is likely useful for the detectability discussion.
- TLS fingerprinting papers (arXiv:2602.09606 bot detection via TLS fingerprints; arXiv:2109.03878 unsupervised clustering of malicious TLS flows). Titles only. The report defers TLS, so these are only needed for the future-work sentence.
- Spoki reactive telescope (arXiv:2110.05160), Cross-Agent Campaign Attribution (arXiv:2607.18826), VelLMes (arXiv:2510.06975): titles only.

## G. Published versions found for preprints cited earlier

Matched on title and first authors via Crossref; cite these instead of arXiv where possible. Confirm the full author list when building the final reference list.

| Key | Published version |
|---|---|
| Shamsi2022 | *IEEE European Symposium on Security and Privacy Workshops (EuroS&PW) 2022*, pp. 294-306. doi:10.1109/eurospw55150.2022.00036 |
| Huang2019 | *GameSec 2019*, LNCS, pp. 196-216. doi:10.1007/978-3-030-32430-8_13 |
| Guan2023 | *Proc. 16th ACM Conference on Security and Privacy in Wireless and Mobile Networks (WiSec)*, 2023, pp. 49-59. doi:10.1145/3558482.3590195 |
| Sladic2023 | *EuroS&PW 2024*, pp. 430-435. doi:10.1109/eurospw61312.2024.00054 |
| Wang2024 | Crossref returns *HoneyGPT: Breaking the trilemma in honeypots with large language models*, *Computer Networks* 282, 112223 (2026), doi:10.1016/j.comnet.2026.112223. Title differs slightly from the arXiv version; confirm it is the same work. |
| Srinivasa2021 | *Digital Threats: Research and Practice* 4, 1-28 (2023). doi:10.1145/3584976 |
| Williams2024 | *IEEE ICDCSW 2025*, pp. 806-812. doi:10.1109/icdcsw63273.2025.00141 |
| Bridges2025 | *IEEE EuroS&P 2026*, pp. 910-928. doi:10.1109/eurosp68448.2026.00063 |

**Still arXiv-only after the check:** Crespi2021, Zhu2022 (Crossref's best hit, *Devils in the clouds*, is a different paper), Deshmukh2019, Valeros2023 (Crossref found only a dataset paper), Valeros2026, Ediga2026, Dulaunoy2022. Khosla2020 and Vaswani2017 are NeurIPS papers; my Crossref search did not return them, so confirm the proceedings details manually.

## H. Remaining gaps
- **Wagener's thesis full text:** unread. Before claiming novelty, get the PDF by hand (the HAL site blocks scripts) and check whether it measures reaction *time* and whether sessions are clustered or attributed.
- **Linking sessions to the same operator:** Crespi, Shamsi and Zhu remain the closest. **Full texts read 2026-10-27** (through an extraction tool, so check numbers against the PDFs): none uses active perturbation; Shamsi and Crespi use timing passively (timestamps, probe intervals); Zhu does not use timing; none has ground truth for operator identity. Schneider et al. (2021) full text also read: it measures duration and command counts, not reaction timing. Used in `docs/paper_draft.md` Section 2.
- **Honeypot ethics and law:** only Zhu (2023) found. Nothing yet on legal aspects of logging attacker IPs and credentials (GDPR). Needs a targeted search together with the data-sharing decision.
- **Scope of this search:** two passes of keyword searches over an arXiv/PubMed-style index, Crossref and general web search. It is not a systematic review, and Scopus, IEEE Xplore and ACM DL were not searched directly. Say so in the paper rather than claiming exhaustive coverage.
