import React from 'react';
import { interpolate, useCurrentFrame, spring, useVideoConfig } from 'remotion';
import { SlideLayout } from '../components/SlideLayout';
import { theme } from '../styles/theme';

interface DemoSlideProps {
  title: string;
  presenterName?: string;
  description: string;
  demoSteps: string[];
  footerTitle: string;
  pageNumber: number;
}

export const DemoSlide: React.FC<DemoSlideProps> = ({
  title,
  presenterName,
  description,
  demoSteps,
  footerTitle,
  pageNumber,
}) => {
  const frame = useCurrentFrame();
  const { fps } = useVideoConfig();

  const badgeScale = spring({
    frame: frame - 10,
    fps,
    config: { damping: 200, stiffness: 150 },
  });

  return (
    <SlideLayout footerTitle={footerTitle} pageNumber={pageNumber} animate={false}>
      <h1
        style={{
          fontSize: theme.fontSize.heading - 20,
          fontWeight: 'bold',
          color: theme.colors.text,
          margin: 0,
          marginBottom: presenterName ? theme.spacing.xs : theme.spacing.md,
        }}
      >
        {title}
      </h1>
      {presenterName && (
        <p
          style={{
            fontSize: theme.fontSize.small,
            color: theme.colors.textMuted,
            margin: 0,
            marginBottom: theme.spacing.md,
          }}
        >
          Presented by: {presenterName}
        </p>
      )}

      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: theme.spacing.sm,
          marginBottom: theme.spacing.md,
        }}
      >
        <div
          style={{
            backgroundColor: theme.colors.success,
            color: 'white',
            padding: `${theme.spacing.xs}px ${theme.spacing.md}px`,
            borderRadius: 20,
            fontSize: theme.fontSize.small,
            fontWeight: 'bold',
            transform: `scale(${Math.max(0, badgeScale)})`,
          }}
        >
          LIVE DEMO
        </div>
      </div>

      <p
        style={{
          fontSize: theme.fontSize.body,
          color: theme.colors.text,
          marginBottom: theme.spacing.md,
          lineHeight: 1.4,
          opacity: interpolate(frame, [15, 30], [0, 1], {
            extrapolateRight: 'clamp',
          }),
        }}
      >
        {description}
      </p>

      <div
        style={{
          backgroundColor: '#1e1e1e',
          borderRadius: 8,
          padding: theme.spacing.md,
          opacity: interpolate(frame, [25, 40], [0, 1], {
            extrapolateRight: 'clamp',
          }),
        }}
      >
        <p
          style={{
            fontSize: theme.fontSize.small - 4,
            color: '#888',
            margin: 0,
            marginBottom: theme.spacing.sm,
          }}
        >
          Demo Steps:
        </p>
        {demoSteps.map((step, index) => {
          const stepOpacity = interpolate(
            frame,
            [35 + index * 8, 45 + index * 8],
            [0, 1],
            { extrapolateRight: 'clamp' }
          );

          return (
            <div
              key={index}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: theme.spacing.sm,
                marginBottom: theme.spacing.xs,
                opacity: stepOpacity,
              }}
            >
              <span
                style={{
                  color: '#4ec9b0',
                  fontSize: theme.fontSize.small,
                  fontFamily: 'monospace',
                }}
              >
                {index + 1}.
              </span>
              <span
                style={{
                  color: '#d4d4d4',
                  fontSize: theme.fontSize.small,
                  fontFamily: 'monospace',
                }}
              >
                {step}
              </span>
            </div>
          );
        })}
      </div>
    </SlideLayout>
  );
};
