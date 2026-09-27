import React from 'react';
import { useCurrentFrame, useVideoConfig, spring, interpolate } from 'remotion';

export const RealWorld: React.FC = () => {
  const frame = useCurrentFrame();
  const { fps } = useVideoConfig();

  const titleOpacity = interpolate(frame, [0, 20], [0, 1], { extrapolateRight: 'clamp' });
  
  const edgeScale = spring({ frame: frame - 40, fps, config: { damping: 12 } });
  const prodScale = spring({ frame: frame - 80, fps, config: { damping: 12 } });
  const arrowOpacity = interpolate(frame, [120, 140], [0, 1], { extrapolateRight: 'clamp' });
  
  const text1Opacity = interpolate(frame, [160, 180], [0, 1], { extrapolateRight: 'clamp' });
  const text2Opacity = interpolate(frame, [200, 220], [0, 1], { extrapolateRight: 'clamp' });

  return (
    <div style={{ flex: 1, backgroundColor: '#f4f4f0', color: '#000', display: 'flex', flexDirection: 'column', alignItems: 'center', fontFamily: '"Space Grotesk", sans-serif', padding: '60px' }}>
      <h1 style={{ fontSize: '70px', opacity: titleOpacity, marginBottom: '60px', fontWeight: 900 }}>
        Real-World Edge Deployment
      </h1>
      
      {/* Network Diagram */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', width: '100%', marginBottom: '80px', gap: '40px' }}>
        
        {/* Attacker */}
        <div style={{ textAlign: 'center' }}>
          <div style={{ fontSize: '100px', marginBottom: '10px' }}>🤖</div>
          <div style={{ fontSize: '24px', fontWeight: 'bold' }}>Botnets / Scanners</div>
        </div>
        
        {/* Arrow to Edge */}
        <div style={{ fontSize: '50px', opacity: arrowOpacity, color: '#ff3b3b' }}>
          &#8594;
        </div>
        
        {/* Edge / CERDA */}
        <div style={{ 
          transform: `scale(${edgeScale})`,
          border: '6px solid #000', 
          backgroundColor: '#ffea00', 
          padding: '40px', 
          boxShadow: '12px 12px 0px 0px #000',
          textAlign: 'center',
          width: '400px'
        }}>
          <h2 style={{ fontSize: '40px', margin: 0, fontWeight: 900 }}>CERDA Node</h2>
          <p style={{ fontSize: '24px', fontWeight: 'bold', margin: '10px 0 0' }}>Edge DMZ</p>
          <div style={{ marginTop: '20px', fontSize: '20px', backgroundColor: '#fff', padding: '10px', border: '2px solid #000' }}>
            🛑 Absorbing Scans<br/>
            🛑 Tarpitting Attackers<br/>
            🧠 Fingerprinting Behavior
          </div>
        </div>

        {/* Arrow to Prod (Blocked) */}
        <div style={{ fontSize: '50px', opacity: arrowOpacity, color: '#000', position: 'relative' }}>
          &#8594;
          <div style={{ position: 'absolute', top: '50%', left: '50%', transform: 'translate(-50%, -50%)', fontSize: '60px', color: '#ff3b3b' }}>X</div>
        </div>
        
        {/* Production */}
        <div style={{ 
          transform: `scale(${prodScale})`,
          border: '6px solid #000', 
          backgroundColor: '#fff', 
          padding: '40px', 
          boxShadow: '12px 12px 0px 0px #000',
          textAlign: 'center',
          width: '300px'
        }}>
          <h2 style={{ fontSize: '40px', margin: 0, fontWeight: 900 }}>Production</h2>
          <p style={{ fontSize: '24px', fontWeight: 'bold', margin: '10px 0 0', color: '#10B981' }}>Safe & Shielded</p>
        </div>

      </div>

      <div style={{ fontSize: '32px', maxWidth: '1200px', lineHeight: 1.6, textAlign: 'center' }}>
        <p style={{ opacity: text1Opacity, marginBottom: '20px', fontWeight: 'bold' }}>
          Deploy CERDA nodes at the edge to absorb automated attacks.
        </p>
        <p style={{ opacity: text2Opacity, color: '#ff3b3b', fontWeight: 'bold' }}>
          Waste Threat Actor resources and build behavioral fingerprints BEFORE they reach production.
        </p>
      </div>
    </div>
  );
};
