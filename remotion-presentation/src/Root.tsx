import React from 'react';
import { Composition } from 'remotion';
import { WebSecurityPresentation } from './WebSecurityPresentation';

export const RemotionRoot: React.FC = () => {
  return (
    <>
      <Composition
        id="WebSecurityPresentation"
        component={WebSecurityPresentation}
        durationInFrames={2250} // 75 seconds at 30fps (15 slides)
        fps={30}
        width={1920}
        height={1080}
      />
    </>
  );
};
