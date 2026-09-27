# CERDA Video Presentation & Demo Script

Since we have fully programmaticized the presentation into a polished, high-definition Remotion video, you no longer need to worry about running live Python servers or relying on the internet for API calls during your panel! 

Your sole focus should be on delivering a powerful, Steve Jobs-style presentation alongside the video.

---

## 🎬 Pre-Presentation Setup

1. **Locate the Video**: Ensure you have the final `demo.mp4` file downloaded to your presentation laptop. (It is located locally at `d:\projects\CERDA\remotion-demo\out\demo.mp4`).
2. **Audio Setup**: The video contains highly realistic sound effects (keyboard typing, terminal pings). Ensure your laptop is plugged into the room's AV system or the speakers are turned up.
3. **Full Screen**: Open the video in your media player, set it to full-screen, and pause it at `0:00`.

---

## 🎤 The Presentation Script (Syncing with the Video)

The video is exactly 67 seconds long and is divided into 4 Acts. While the text in the video is self-explanatory, your live narration will add the necessary human impact for the judges.

### Act 1: The Problem (0:00 - 0:10)
*Hit PLAY on the video.*

**What you say:** 
> *"Traditional honeypots are fundamentally flawed. They are static and passive. Modern automated malware instantly detects them, fingerprints them, and disconnects before we can gather any meaningful intelligence. They fail to waste the attacker's resources, and they provide zero behavioral attribution for advanced human operators."*

### Act 2: The Novelty (0:10 - 0:17)
*The video transitions to the 3 AI Pillars.*

**What you say:**
> *"CERDA completely flips this paradigm. We built a system powered by three pillars of AI: Contextual Adaptation using Gemini LLMs to hallucinate files on the fly, Behavioral Attribution using a PyTorch Spatio-Temporal Transformer, and Active Defense using Reinforcement Learning."*

### Act 3: The Technical Demo (0:17 - 0:57)
*The video transitions to the Split-Screen Terminal & Dashboard.*

**What you say:** 
> *"Let's look at it in action. On the left is an attacker who has breached our decoy shell. As they look for sensitive data, our Gemini LLM dynamically generates a highly convincing AWS Canary Token on the fly.*
>
> *(Wait for the Tarpit to engage around 0:30)*
> 
> *But we don't just watch. Our Reinforcement Learning agent determines the threat level is critical and drops them into a TCP Tarpit. Notice the terminal slowing down to 1 byte per second. We are actively holding their connection hostage, wasting their compute.*
> 
> *(Wait for the yellow bot node to flash on the Dashboard around 0:45)*
> 
> *Simultaneously, our PyTorch Transformer is analyzing the nanosecond variances between their keystrokes. It instantly recognized that a bot script connected, and mathematically isolated it into a new Threat Actor cluster in real-time."*

### Act 4: Real-World Utilization (0:57 - 1:07)
*The video transitions to the Network Diagram.*

**What you say:**
> *"So how is this used in the real world? By deploying CERDA nodes at the edge of a network DMZ, enterprise organizations can absorb automated botnet scanning, actively waste Threat Actor resources, and build deep behavioral fingerprints of APT groups... long before they ever reach the production data center."*

---

## 🏆 Tips for Winning
1. **Pacing is Everything:** Practice your speech along with the video multiple times. The video waits for no one, so you want your words to perfectly match the animated callouts as they pop up on screen.
2. **Emphasize the Architecture:** Make sure the judges understand that **standard honeypots don't use PyTorch to track timing rhythms**, and they don't use **LLMs to dynamically hallucinate files**. 
3. **Q&A Readiness:** Be prepared to answer questions about the LLM latency (you can mention the caching mechanism we built) and the RL reward functions (we penalize for losing the connection, reward for stalling).
