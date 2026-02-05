import React from 'react';
import { interpolate, useCurrentFrame, spring, useVideoConfig } from 'remotion';
import { SlideLayout } from '../components/SlideLayout';
import { theme } from '../styles/theme';

interface Finding {
  metric: string;
  value: string;
  description?: string;
}

interface FindingsSlideProps {
  presenterName?: string;
  findings: Finding[];
  demoNote?: string;
  footerTitle: string;
  pageNumber: number;
}

export const FindingsSlide: React.FC<FindingsSlideProps> = ({
  presenterName,
  findings,
  demoNote,
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
          marginBottom: presenterName ? theme.spacing.xs : theme.spacing.sm,
        }}
      >
        (vi) Findings/Results/Demo
      </h1>
      {presenterName && (
        <p
          style={{
            fontSize: theme.fontSize.small,
            color: theme.colors.textMuted,
            margin: 0,
            marginBottom: theme.spacing.sm,
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
            fontSize: theme.fontSize.small - 4,
            fontWeight: 'bold',
            transform: `scale(${Math.max(0, badgeScale)})`,
          }}
        >
          DEMO INCLUDED
        </div>
      </div>

      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(3, 1fr)',
          gap: theme.spacing.md,
          marginBottom: theme.spacing.md,
        }}
      >
        {findings.map((finding, index) => {
          const itemOpacity = interpolate(
            frame,
            [15 + index * 8, 28 + index * 8],
            [0, 1],
            { extrapolateRight: 'clamp' }
          );
          const itemScale = interpolate(
            frame,
            [15 + index * 8, 28 + index * 8],
            [0.9, 1],
            { extrapolateRight: 'clamp' }
          );

          return (
            <div
              key={index}
              style={{
                backgroundColor: '#f8f9fa',
                border: `2px solid ${theme.colors.primary}`,
                borderRadius: 8,
                padding: theme.spacing.sm,
                textAlign: 'center',
                opacity: itemOpacity,
                transform: `scale(${itemScale})`,
              }}
            >
              <div
                style={{
                  fontSize: theme.fontSize.title - 20,
                  fontWeight: 'bold',
                  color: theme.colors.primary,
                  marginBottom: theme.spacing.xs / 2,
                }}
              >
                {finding.value}
              </div>
              <div
                style={{
                  fontSize: theme.fontSize.small - 2,
                  fontWeight: 'bold',
                  color: theme.colors.text,
                  marginBottom: finding.description ? theme.spacing.xs / 2 : 0,
                }}
              >
                {finding.metric}
              </div>
              {finding.description && (
                <div
                  style={{
                    fontSize: theme.fontSize.small - 4,
                    color: theme.colors.textMuted,
                  }}
                >
                  {finding.description}
                </div>
              )}
            </div>
          );
        })}
      </div>

      {demoNote && (
        <div
          style={{
            backgroundColor: '#1e1e1e',
            borderRadius: 8,
            padding: theme.spacing.sm,
            opacity: interpolate(frame, [50, 65], [0, 1], { extrapolateRight: 'clamp' }),
          }}
        >
          <p
            style={{
              fontSize: theme.fontSize.small - 2,
              color: '#d4d4d4',
              margin: 0,
              fontFamily: 'monospace',
            }}
          >
            {demoNote}
          </p>
        </div>
      )}
    </SlideLayout>
  );
};
