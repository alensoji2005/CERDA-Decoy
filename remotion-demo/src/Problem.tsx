import React from 'react';
import { useCurrentFrame, useVideoConfig, spring, interpolate } from 'remotion';

export const Problem: React.FC = () => {
  const frame = useCurrentFrame();
  const { fps } = useVideoConfig();

  const titleScale = spring({ frame, fps, config: { damping: 12 } });
  const titleOpacity = interpolate(frame, [0, 20], [0, 1], { extrapolateRight: 'clamp' });
  
  const line1Opacity = interpolate(frame, [40, 60], [0, 1], { extrapolateRight: 'clamp' });
  const line2Opacity = interpolate(frame, [100, 120], [0, 1], { extrapolateRight: 'clamp' });
  const line3Opacity = interpolate(frame, [160, 180], [0, 1], { extrapolateRight: 'clamp' });

  return (
    <div style={{ flex: 1, backgroundColor: '#000', color: '#fff', display: 'flex', flexDirection: 'column', justifyContent: 'center', alignItems: 'center', fontFamily: '"Space Grotesk", sans-serif', padding: '60px' }}>
      <h1 style={{ fontSize: '80px', transform: `scale(${titleScale})`, opacity: titleOpacity, marginBottom: '60px', color: '#ff3b3b', textAlign: 'center' }}>
        The Problem with Traditional Honeypots
      </h1>
      
      <div style={{ fontSize: '40px', maxWidth: '1400px', lineHeight: 1.8 }}>
        <div style={{ opacity: line1Opacity, marginBottom: '40px', display: 'flex', alignItems: 'center' }}>
          <span style={{ fontSize: '50px', marginRight: '20px' }}>⚠️</span> 
          <span><strong>Static & Predictable:</strong> Easily fingerprinted by automated bots and immediately ignored.</span>
        </div>
        <div style={{ opacity: line2Opacity, marginBottom: '40px', display: 'flex', alignItems: 'center' }}>
          <span style={{ fontSize: '50px', marginRight: '20px' }}>⚠️</span> 
          <span><strong>Passive Observation:</strong> They fail to waste the attacker's time, compute, or resources.</span>
        </div>
        <div style={{ opacity: line3Opacity, display: 'flex', alignItems: 'center' }}>
          <span style={{ fontSize: '50px', marginRight: '20px' }}>⚠️</span> 
          <span><strong>Zero Attribution:</strong> Standard logs cannot differentiate between scripts and human APT operators.</span>
        </div>
      </div>
    </div>
  );
};
