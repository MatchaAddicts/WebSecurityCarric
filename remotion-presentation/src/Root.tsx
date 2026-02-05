import React from 'react';
import { Composition } from 'remotion';
import { WebSecurityPresentation } from './WebSecurityPresentation';

export const RemotionRoot: React.FC = () => {
  return (
    <>
      <Composition
        id="WebSecurityPresentation"
        component={WebSecurityPresentation}
        durationInFrames={1500} // Approximately 50 seconds at 30fps
        fps={30}
        width={1920}
        height={1080}
      />
    </>
  );
};
