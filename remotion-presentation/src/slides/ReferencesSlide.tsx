import React from 'react';
import { interpolate, useCurrentFrame } from 'remotion';
import { SlideLayout } from '../components/SlideLayout';
import { theme } from '../styles/theme';

interface Reference {
  id: number;
  citation: string;
}

interface ReferencesSlideProps {
  presenterName?: string;
  references: Reference[];
  footerTitle: string;
  pageNumber: number;
}

export const ReferencesSlide: React.FC<ReferencesSlideProps> = ({
  presenterName,
  references,
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
        (xi) References
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

      <div style={{ display: 'flex', flexDirection: 'column', gap: theme.spacing.xs }}>
        {references.map((ref, index) => {
          const itemOpacity = interpolate(
            frame,
            [10 + index * 5, 20 + index * 5],
            [0, 1],
            { extrapolateRight: 'clamp' }
          );

          return (
            <div
              key={ref.id}
              style={{
                display: 'flex',
                gap: theme.spacing.sm,
                opacity: itemOpacity,
                fontSize: theme.fontSize.small - 4,
                lineHeight: 1.4,
              }}
            >
              <span
                style={{
                  color: theme.colors.primary,
                  fontWeight: 'bold',
                  minWidth: 30,
                }}
              >
                [{ref.id}]
              </span>
              <span style={{ color: theme.colors.text }}>{ref.citation}</span>
            </div>
          );
        })}
      </div>

      <p
        style={{
          fontSize: theme.fontSize.small - 4,
          color: theme.colors.textMuted,
          fontStyle: 'italic',
          marginTop: theme.spacing.md,
          opacity: interpolate(frame, [60, 75], [0, 1], { extrapolateRight: 'clamp' }),
        }}
      >
        * IEEE citation style
      </p>
    </SlideLayout>
  );
};
