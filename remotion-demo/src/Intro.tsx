import React from 'react';
import { useCurrentFrame, useVideoConfig, spring, interpolate } from 'remotion';

export const Intro: React.FC = () => {
  const frame = useCurrentFrame();
  const { fps } = useVideoConfig();

  const titleScale = spring({ frame, fps, config: { damping: 12 } });
  const titleOpacity = interpolate(frame, [0, 20], [0, 1], { extrapolateRight: 'clamp' });

  const subOpacity1 = interpolate(frame, [40, 60], [0, 1], { extrapolateRight: 'clamp' });
  const subOpacity2 = interpolate(frame, [100, 120], [0, 1], { extrapolateRight: 'clamp' });
  const subOpacity3 = interpolate(frame, [160, 180], [0, 1], { extrapolateRight: 'clamp' });

  return (
    <div style={{ flex: 1, backgroundColor: '#000', color: '#00FF66', display: 'flex', flexDirection: 'column', justifyContent: 'center', alignItems: 'center', fontFamily: '"Space Grotesk", sans-serif', padding: '60px' }}>
      <h1 style={{ fontSize: '80px', transform: `scale(${titleScale})`, opacity: titleOpacity, margin: 0, textAlign: 'center' }}>
        The Novelty of CERDA
      </h1>
      <h2 style={{ fontSize: '30px', opacity: titleOpacity, marginBottom: '60px', textAlign: 'center', color: '#fff' }}>
        (Counterfactual Execution-Rhythm Decoy Architecture)
      </h2>

      <div style={{ fontSize: '35px', maxWidth: '1400px', lineHeight: 1.6 }}>
        <p style={{ opacity: subOpacity1, marginBottom: '30px' }}>
          <strong style={{color: '#00aaff'}}>[Contextual Adaptation]</strong> Dynamically synthesizes believable, environment-specific honeytokens on the fly using Gemini LLMs.
        </p>
        <p style={{ opacity: subOpacity2, marginBottom: '30px' }}>
          <strong style={{color: '#ffea00'}}>[Behavioral Attribution]</strong> Uses a PyTorch Spatio-Temporal Transformer to mathematically cluster the rhythm of an attacker's keystrokes, reliably distinguishing humans from bots.
        </p>
        <p style={{ opacity: subOpacity3 }}>
          <strong style={{color: '#ff3b3b'}}>[Active Defense]</strong> Deploys a Reinforcement Learning agent that dynamically injects TCP Tarpits, actively wasting the attacker's compute and time.
        </p>
      </div>
    </div>
  );
};
