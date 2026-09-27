import React from 'react';
import { useCurrentFrame, Audio, interpolate, spring, useVideoConfig } from 'remotion';

// Simulated terminal sequence
const SEQUENCE = [
  { frameStart: 0, text: "CERDA Decoy Shell (SSH)\n$ " },
  // 1. cat /tmp/config.json
  { frameStart: 30, text: "c", typing: true },
  { frameStart: 35, text: "a", typing: true },
  { frameStart: 40, text: "t", typing: true },
  { frameStart: 45, text: " ", typing: true },
  { frameStart: 50, text: "/", typing: true },
  { frameStart: 55, text: "t", typing: true },
  { frameStart: 60, text: "m", typing: true },
  { frameStart: 65, text: "p", typing: true },
  { frameStart: 70, text: "/", typing: true },
  { frameStart: 75, text: "c", typing: true },
  { frameStart: 80, text: "o", typing: true },
  { frameStart: 85, text: "n", typing: true },
  { frameStart: 90, text: "f", typing: true },
  { frameStart: 95, text: "i", typing: true },
  { frameStart: 100, text: "g", typing: true },
  { frameStart: 105, text: ".", typing: true },
  { frameStart: 110, text: "j", typing: true },
  { frameStart: 115, text: "s", typing: true },
  { frameStart: 120, text: "o", typing: true },
  { frameStart: 125, text: "n", typing: true },
  { frameStart: 140, text: "\n", typing: true },
  { frameStart: 141, text: "production:\n  adapter: postgresql\n  database: prod_db\n  username: admin\n  password: supersecretpassword123\n  host: 127.0.0.1\n$ " },
  
  // 2. cat ~/.aws/credentials
  { frameStart: 250, text: "c", typing: true },
  { frameStart: 255, text: "a", typing: true },
  { frameStart: 260, text: "t", typing: true },
  { frameStart: 265, text: " ", typing: true },
  { frameStart: 270, text: "~", typing: true },
  { frameStart: 275, text: "/", typing: true },
  { frameStart: 280, text: ".", typing: true },
  { frameStart: 285, text: "a", typing: true },
  { frameStart: 290, text: "w", typing: true },
  { frameStart: 295, text: "s", typing: true },
  { frameStart: 300, text: "/", typing: true },
  { frameStart: 305, text: "c", typing: true },
  { frameStart: 310, text: "r", typing: true },
  { frameStart: 315, text: "e", typing: true },
  { frameStart: 320, text: "d", typing: true },
  { frameStart: 325, text: "e", typing: true },
  { frameStart: 330, text: "n", typing: true },
  { frameStart: 335, text: "t", typing: true },
  { frameStart: 340, text: "i", typing: true },
  { frameStart: 345, text: "a", typing: true },
  { frameStart: 350, text: "l", typing: true },
  { frameStart: 355, text: "s", typing: true },
  { frameStart: 370, text: "\n", typing: true },
  { frameStart: 371, text: "[default]\naws_access_key_id = AKIAIOSFODNN7EXAMPLE\naws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n$ " },
  
  // 3. Tarpit: whoami
  { frameStart: 550, text: "w", typing: true },
  { frameStart: 555, text: "h", typing: true },
  { frameStart: 560, text: "o", typing: true },
  { frameStart: 565, text: "a", typing: true },
  { frameStart: 570, text: "m", typing: true },
  { frameStart: 575, text: "i", typing: true },
  { frameStart: 590, text: "\n", typing: true },
  
  // Tarpit delay (slow rendering of "root")
  { frameStart: 620, text: "r" },
  { frameStart: 670, text: "o" },
  { frameStart: 720, text: "o" },
  { frameStart: 770, text: "t" },
  { frameStart: 820, text: "\n" },
  { frameStart: 870, text: "$" },
  { frameStart: 920, text: " " },
];

const Callout: React.FC<{ text: string, showAt: number, hideAt: number, top: string, right: string, color: string }> = ({ text, showAt, hideAt, top, right, color }) => {
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
      top, right,
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

export const Terminal: React.FC = () => {
  const frame = useCurrentFrame();

  let visibleText = "";
  let isTyping = false;
  for (const item of SEQUENCE) {
    if (frame >= item.frameStart) {
      visibleText += item.text;
      if (item.typing && frame === item.frameStart) {
          isTyping = true;
      }
    }
  }

  return (
    <div style={{ flex: 1, backgroundColor: '#000', padding: '40px', display: 'flex', flexDirection: 'column', position: 'relative' }}>
      
      {/* MacOS Window Frame */}
      <div style={{ 
        flex: 1, 
        backgroundColor: '#1a1a1a', 
        borderRadius: '12px', 
        border: '1px solid #333',
        boxShadow: '0 20px 50px rgba(0,0,0,0.8)',
        display: 'flex',
        flexDirection: 'column',
        overflow: 'hidden'
      }}>
        
        {/* Titlebar */}
        <div style={{ height: '32px', backgroundColor: '#2d2d2d', display: 'flex', alignItems: 'center', padding: '0 15px', borderBottom: '1px solid #111' }}>
          <div style={{ width: '12px', height: '12px', borderRadius: '50%', backgroundColor: '#ff5f56', marginRight: '8px' }}></div>
          <div style={{ width: '12px', height: '12px', borderRadius: '50%', backgroundColor: '#ffbd2e', marginRight: '8px' }}></div>
          <div style={{ width: '12px', height: '12px', borderRadius: '50%', backgroundColor: '#27c93f' }}></div>
          <div style={{ flex: 1, textAlign: 'center', color: '#888', fontFamily: 'sans-serif', fontSize: '13px', fontWeight: 'bold' }}>ssh root@honeypot.internal</div>
        </div>

        {/* Terminal Content */}
        <div style={{ 
          flex: 1, 
          padding: '20px', 
          color: '#00FF66', 
          fontFamily: '"Courier New", Courier, monospace', 
          fontSize: '24px', 
          whiteSpace: 'pre-wrap',
          textShadow: '0 0 5px rgba(0, 255, 102, 0.6)'
        }}>
          {visibleText}
          {frame % 30 < 15 ? <span style={{ backgroundColor: '#00FF66', boxShadow: '0 0 5px #00FF66' }}>_</span> : null}
        </div>
      </div>

      <Callout text="✨ Gemini LLM: Contextual AWS Honeypot Generated ✨" showAt={390} hideAt={530} top="45%" right="-20px" color="#00aaff" />
      <Callout text="🛑 RL Agent: Threat Level Critical. Engaging TCP Tarpit (1 byte/sec)" showAt={640} hideAt={900} top="65%" right="-20px" color="#ff3b3b" />
      
      {isTyping ? (
          <Audio src="https://actions.google.com/sounds/v1/foley/keyboard_typing.ogg" startFrom={0} endAt={5} volume={0.3} />
      ) : null}
    </div>
  );
};
