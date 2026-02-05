import React from 'react';
import { AbsoluteFill, interpolate, useCurrentFrame, spring, useVideoConfig } from 'remotion';
import { SlideFooter } from '../components/SlideFooter';
import { theme } from '../styles/theme';

interface ThankYouSlideProps {
  footerTitle: string;
  pageNumber: number;
  githubLink?: string;
}

export const ThankYouSlide: React.FC<ThankYouSlideProps> = ({
  footerTitle,
  pageNumber,
  githubLink,
}) => {
  const frame = useCurrentFrame();
  const { fps } = useVideoConfig();

  const titleScale = spring({
    frame,
    fps,
    config: { damping: 200, stiffness: 80 },
  });

  const subtitleOpacity = interpolate(frame, [20, 40], [0, 1], {
    extrapolateRight: 'clamp',
  });

  const linkOpacity = interpolate(frame, [40, 60], [0, 1], {
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
          fontSize: 120,
          fontWeight: 'bold',
          color: theme.colors.primary,
          textAlign: 'center',
          margin: 0,
          marginBottom: theme.spacing.md,
          transform: `scale(${titleScale})`,
        }}
      >
        Thank You!
      </h1>
      <p
        style={{
          fontSize: theme.fontSize.subtitle,
          color: theme.colors.textLight,
          textAlign: 'center',
          margin: 0,
          marginBottom: theme.spacing.lg,
          opacity: subtitleOpacity,
        }}
      >
        Questions?
      </p>
      {githubLink && (
        <p
          style={{
            fontSize: theme.fontSize.body - 4,
            color: theme.colors.textMuted,
            textAlign: 'center',
            margin: 0,
            opacity: linkOpacity,
          }}
        >
          View the code: {githubLink}
        </p>
      )}
      <SlideFooter title={footerTitle} pageNumber={pageNumber} />
    </AbsoluteFill>
  );
};
