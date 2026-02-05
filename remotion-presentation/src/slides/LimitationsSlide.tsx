import React from 'react';
import { interpolate, useCurrentFrame } from 'remotion';
import { SlideLayout } from '../components/SlideLayout';
import { theme } from '../styles/theme';

interface LimitationsSlideProps {
  presenterName?: string;
  limitations: string[];
  futureWork: string[];
  footerTitle: string;
  pageNumber: number;
}

export const LimitationsSlide: React.FC<LimitationsSlideProps> = ({
  presenterName,
  limitations,
  futureWork,
  footerTitle,
  pageNumber,
}) => {
  const frame = useCurrentFrame();

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
        (viii) Limitations and Future Works
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

      <div style={{ display: 'flex', gap: theme.spacing.lg }}>
        <div style={{ flex: 1 }}>
          <h3
            style={{
              fontSize: theme.fontSize.body - 4,
              fontWeight: 'bold',
              color: '#c0392b',
              margin: 0,
              marginBottom: theme.spacing.sm,
              opacity: interpolate(frame, [10, 20], [0, 1], { extrapolateRight: 'clamp' }),
            }}
          >
            Current Limitations
          </h3>
          <ul style={{ listStyle: 'disc', paddingLeft: theme.spacing.md, margin: 0 }}>
            {limitations.map((item, index) => {
              const itemOpacity = interpolate(
                frame,
                [15 + index * 8, 27 + index * 8],
                [0, 1],
                { extrapolateRight: 'clamp' }
              );
              return (
                <li
                  key={index}
                  style={{
                    fontSize: theme.fontSize.small,
                    color: theme.colors.text,
                    marginBottom: theme.spacing.xs,
                    opacity: itemOpacity,
                    lineHeight: 1.4,
                  }}
                >
                  {item}
                </li>
              );
            })}
          </ul>
        </div>

        <div style={{ flex: 1 }}>
          <h3
            style={{
              fontSize: theme.fontSize.body - 4,
              fontWeight: 'bold',
              color: theme.colors.success,
              margin: 0,
              marginBottom: theme.spacing.sm,
              opacity: interpolate(frame, [30, 40], [0, 1], { extrapolateRight: 'clamp' }),
            }}
          >
            Future Research Directions
          </h3>
          <ul style={{ listStyle: 'disc', paddingLeft: theme.spacing.md, margin: 0 }}>
            {futureWork.map((item, index) => {
              const itemOpacity = interpolate(
                frame,
                [35 + index * 8, 47 + index * 8],
                [0, 1],
                { extrapolateRight: 'clamp' }
              );
              return (
                <li
                  key={index}
                  style={{
                    fontSize: theme.fontSize.small,
                    color: theme.colors.text,
                    marginBottom: theme.spacing.xs,
                    opacity: itemOpacity,
                    lineHeight: 1.4,
                  }}
                >
                  {item}
                </li>
              );
            })}
          </ul>
        </div>
      </div>
    </SlideLayout>
  );
};
