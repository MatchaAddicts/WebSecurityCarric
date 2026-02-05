import React from 'react';
import { AbsoluteFill, interpolate, useCurrentFrame } from 'remotion';
import { SlideFooter } from './SlideFooter';
import { theme, slideStyles } from '../styles/theme';

interface SlideLayoutProps {
  children: React.ReactNode;
  footerTitle: string;
  pageNumber: number;
  animate?: boolean;
}

export const SlideLayout: React.FC<SlideLayoutProps> = ({
  children,
  footerTitle,
  pageNumber,
  animate = true,
}) => {
  const frame = useCurrentFrame();

  const opacity = animate
    ? interpolate(frame, [0, 15], [0, 1], { extrapolateRight: 'clamp' })
    : 1;

  const translateY = animate
    ? interpolate(frame, [0, 15], [20, 0], { extrapolateRight: 'clamp' })
    : 0;

  return (
    <AbsoluteFill style={slideStyles.container}>
      <div
        style={{
          flex: 1,
          display: 'flex',
          flexDirection: 'column',
          opacity,
          transform: `translateY(${translateY}px)`,
        }}
      >
        {children}
      </div>
      <SlideFooter title={footerTitle} pageNumber={pageNumber} />
    </AbsoluteFill>
  );
};
