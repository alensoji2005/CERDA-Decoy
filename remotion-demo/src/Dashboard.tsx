import React from 'react';
import { useCurrentFrame, interpolate, spring, useVideoConfig } from 'remotion';

const Callout: React.FC<{ text: string, showAt: number, hideAt: number, top: string, left: string, color: string }> = ({ text, showAt, hideAt, top, left, color }) => {
  const frame = useCurrentFrame();
  const { fps } = useVideoConfig();

  const scale = spring({
    frame: frame - showAt,
    fps,
    config: { damping: 12 },
  });

  const opacity = interpolate(frame, [hideAt - 15, hideAt], [1, 0], { extrapolateRight: 'clamp' });

  if (frame < showAt) return null;

  return (
    <div style={{
      position: 'absolute',
      top, left,
      backgroundColor: '#111',
      color: color,
      padding: '15px 25px',
      borderRadius: '8px',
      border: `2px solid ${color}`,
      boxShadow: `0 0 20px ${color}`,
      transform: `scale(${scale})`,
      opacity,
      fontFamily: '"Space Grotesk", sans-serif',
      fontWeight: 'bold',
      fontSize: '20px',
      zIndex: 50
    }}>
      {text}
    </div>
  );
};

export const Dashboard: React.FC = () => {
  const frame = useCurrentFrame();
  const { fps } = useVideoConfig();

  const isBotDetected = frame > 800; // Trigger bot detection at frame 800
  const showRegimeTimeline = frame > 1000; // Switch to timeline view at frame 1000

  // Animate the flash when bot is detected
  const flashOpacity = spring({
    frame: frame - 800,
    fps,
    config: { damping: 200 },
  });

  const cardStyle: React.CSSProperties = {
    padding: '2rem',
    border: '4px solid #000',
    boxShadow: '8px 8px 0px 0px #000',
    backgroundColor: '#fff',
    marginBottom: '2rem',
    display: 'flex',
    flexDirection: 'column',
  };

  const metricLabel: React.CSSProperties = { fontSize: '1rem', fontWeight: 800, marginBottom: '10px' };
  const metricValue: React.CSSProperties = { fontSize: '2.5rem', fontWeight: 900, borderBottom: '4px solid #000', paddingBottom: '5px', wordWrap: 'break-word', display: 'block' };

  return (
    <div style={{ flex: 1, backgroundColor: '#f4f4f0', color: '#000', fontFamily: '"Space Grotesk", sans-serif', padding: '40px', display: 'flex', flexDirection: 'column', position: 'relative' }}>
      <h1 style={{ fontSize: '40px', fontWeight: 900, marginBottom: '20px' }}>
        CERDA: Counterfactual Execution-Rhythm Decoy Architecture
      </h1>
      
      <div style={{ display: 'flex', gap: '40px', marginBottom: '40px' }}>
        <div style={{ flex: 1, ...cardStyle }}>
          <span style={metricLabel}>Active Decoy Listeners</span>
          <span style={metricValue}>Ports 2222, 8080</span>
        </div>
        <div style={{ flex: 1, ...cardStyle, backgroundColor: isBotDetected ? `rgba(255, 234, 0, ${flashOpacity})` : '#fff' }}>
          <span style={metricLabel}>Total Captured Sessions</span>
          <span style={metricValue}>{isBotDetected ? '44' : '43'}</span>
        </div>
        <div style={{ flex: 1, ...cardStyle, backgroundColor: isBotDetected ? `rgba(255, 59, 59, ${flashOpacity})` : '#fff' }}>
          <span style={metricLabel}>Attributed Threat Actors</span>
          <span style={metricValue}>{isBotDetected ? '3' : '2'}</span>
        </div>
      </div>

      <div style={{ ...cardStyle, flex: 1, position: 'relative' }}>
        <h2 style={{ fontSize: '24px', fontWeight: 800, borderBottom: '4px solid #000', paddingBottom: '10px', marginBottom: '20px', display: 'flex', justifyContent: 'space-between' }}>
          <span>{showRegimeTimeline ? 'Regime Timeline (Latency vs Perturbation)' : 'Captured Sessions Registry'}</span>
          <span style={{ fontSize: '16px', color: '#888' }}>
             <span style={{ color: !showRegimeTimeline ? '#000' : '#888' }}>Tab 1</span> | <span style={{ color: showRegimeTimeline ? '#000' : '#888' }}>Tab 2</span>
          </span>
        </h2>
        
        {!showRegimeTimeline ? (
          <div style={{ backgroundColor: '#111', color: '#fff', flex: 1, padding: '20px', fontFamily: 'monospace', fontSize: '14px', border: '4px solid #000' }}>
            <div style={{ display: 'flex', borderBottom: '2px solid #333', paddingBottom: '10px', marginBottom: '10px', color: '#888' }}>
              <span style={{ flex: 1 }}>threat_actor_id</span>
              <span style={{ flex: 1 }}>session_id</span>
              <span style={{ flex: 2 }}>cerf_hash</span>
            </div>
            <div style={{ display: 'flex', marginBottom: '10px' }}>
              <span style={{ flex: 1, color: '#ff3b3b' }}>TA-001</span>
              <span style={{ flex: 1 }}>session_A_000</span>
              <span style={{ flex: 2 }}>d0e46bd4379a6730...</span>
            </div>
            <div style={{ display: 'flex', marginBottom: '10px' }}>
              <span style={{ flex: 1, color: '#ff3b3b' }}>TA-001</span>
              <span style={{ flex: 1 }}>session_A_001</span>
              <span style={{ flex: 2 }}>d0e46bd4379a6730...</span>
            </div>
            <div style={{ display: 'flex', marginBottom: '10px' }}>
              <span style={{ flex: 1, color: '#00aaff' }}>TA-002</span>
              <span style={{ flex: 1 }}>session_B_007</span>
              <span style={{ flex: 2 }}>50e46bc4378a6330...</span>
            </div>
            
            {isBotDetected && (
              <div style={{ display: 'flex', marginBottom: '10px', backgroundColor: '#ffea00', color: '#000', padding: '5px', fontWeight: 'bold' }}>
                <span style={{ flex: 1 }}>TA-003 [BOT]</span>
                <span style={{ flex: 1 }}>session_C_999</span>
                <span style={{ flex: 2 }}>0000000000000000...</span>
              </div>
            )}
          </div>
        ) : (
          <div style={{ flex: 1, padding: '20px', border: '4px solid #000', position: 'relative', display: 'flex', alignItems: 'flex-end', gap: '5px' }}>
            {/* Fake Chart: Latency Spiking */}
            {Array.from({ length: 40 }).map((_, i) => {
               // First 20 are baseline (low latency), next 20 are Tarpit (skyrocketing latency)
               let height = i < 20 ? 10 + Math.random() * 5 : 10 + (i - 20) * 4.5 + Math.random() * 10;
               let color = i < 20 ? '#10B981' : '#8B5CF6'; // Green for baseline, Purple for FS_LATENCY
               
               // Animate the bars growing in
               const barScale = spring({
                   frame: frame - 1000 - i * 2,
                   fps,
                   config: { damping: 12 }
               });
               
               return (
                   <div key={i} style={{ flex: 1, backgroundColor: color, height: `${height}%`, transform: `scaleY(${barScale})`, transformOrigin: 'bottom' }} />
               )
            })}
            
            {/* Chart Overlays */}
            <div style={{ position: 'absolute', top: '10px', left: '20px', fontWeight: 'bold', color: '#10B981' }}>Regime 0: Baseline (10ms)</div>
            <div style={{ position: 'absolute', top: '10px', right: '20px', fontWeight: 'bold', color: '#8B5CF6' }}>Regime 3: TCP Tarpit (1000ms)</div>
          </div>
        )}
      </div>

      <Callout text="🧠 PyTorch Spatio-Temporal Transformer: Analyzing keystroke variance" showAt={820} hideAt={980} top="35%" left="-20px" color="#ffea00" />
    </div>
  );
};
