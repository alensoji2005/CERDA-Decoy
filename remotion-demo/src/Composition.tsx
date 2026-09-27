import { Composition, Sequence } from 'remotion';
import { Problem } from './Problem';
import { Intro } from './Intro';
import { SplitScreen } from './SplitScreen';
import { RealWorld } from './RealWorld';

export const MyComposition = () => {
  return (
    <>
      <Composition
        id="CERDADemo"
        component={DemoVideo}
        durationInFrames={2010}
        fps={30}
        width={1920}
        height={1080}
      />
    </>
  );
};

export const DemoVideo: React.FC = () => {
  return (
    <div style={{ flex: 1, backgroundColor: '#000' }}>
      <Sequence from={0} durationInFrames={300}>
        <Problem />
      </Sequence>
      <Sequence from={300} durationInFrames={210}>
        <Intro />
      </Sequence>
      <Sequence from={510} durationInFrames={1200}>
        <SplitScreen />
      </Sequence>
      <Sequence from={1710} durationInFrames={300}>
        <RealWorld />
      </Sequence>
    </div>
  );
};
