import React from 'react';
import { Terminal } from './Terminal';
import { Dashboard } from './Dashboard';

export const SplitScreen: React.FC = () => {
  return (
    <div style={{ display: 'flex', flexDirection: 'row', width: '100%', height: '100%', backgroundColor: '#000' }}>
      <div style={{ flex: 1, display: 'flex' }}>
        <Terminal />
      </div>
      <div style={{ flex: 1, display: 'flex', borderLeft: '4px solid #333' }}>
        <Dashboard />
      </div>
    </div>
  );
};
