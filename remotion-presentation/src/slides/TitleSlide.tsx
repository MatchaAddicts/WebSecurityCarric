import React from 'react';
import { AbsoluteFill, interpolate, useCurrentFrame, spring, useVideoConfig } from 'remotion';
import { SlideFooter } from '../components/SlideFooter';
import { theme } from '../styles/theme';

interface TitleSlideProps {
  title: string;
  subtitle: string;
  footerTitle: string;
}

export const TitleSlide: React.FC<TitleSlideProps> = ({
  title,
  subtitle,
  footerTitle,
}) => {
  const frame = useCurrentFrame();
  const { fps } = useVideoConfig();

  const titleOpacity = interpolate(frame, [0, 20], [0, 1], {
    extrapolateRight: 'clamp',
  });

  const titleScale = spring({
    frame,
    fps,
    config: { damping: 200, stiffness: 100 },
  });

  const subtitleOpacity = interpolate(frame, [15, 35], [0, 1], {
    extrapolateRight: 'clamp',
  });

  const subtitleTranslateY = interpolate(frame, [15, 35], [30, 0], {
    extrapolateRight: 'clamp',
  });

  return (
    <AbsoluteFill
      style={{
        backgroundColor: theme.colors.background,
        fontFamily: theme.fonts.primary,
        display: 'flex',
        flexDirection: 'column',
        justifyContent: 'center',
        alignItems: 'center',
        padding: theme.spacing.xl,
      }}
    >
      <h1
        style={{
          fontSize: 100,
          fontWeight: 'bold',
          color: theme.colors.text,
          textAlign: 'center',
          margin: 0,
          marginBottom: theme.spacing.md,
          opacity: titleOpacity,
          transform: `scale(${titleScale})`,
        }}
      >
        {title}
      </h1>
      <p
        style={{
          fontSize: theme.fontSize.subtitle,
          color: theme.colors.textLight,
          textAlign: 'center',
          margin: 0,
          opacity: subtitleOpacity,
          transform: `translateY(${subtitleTranslateY}px)`,
        }}
      >
        {subtitle}
      </p>
      <SlideFooter title={footerTitle} pageNumber={1} />
    </AbsoluteFill>
  );
};
