import React from 'react';
import { interpolate, useCurrentFrame } from 'remotion';
import { SlideLayout } from '../components/SlideLayout';
import { theme } from '../styles/theme';

interface AnalysisPoint {
  title: string;
  points: string[];
}

interface AnalysisSlideProps {
  presenterName?: string;
  analyses: AnalysisPoint[];
  footerTitle: string;
  pageNumber: number;
}

export const AnalysisSlide: React.FC<AnalysisSlideProps> = ({
  presenterName,
  analyses,
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
        (vii) Analysis/Discussion
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
        {analyses.map((analysis, colIndex) => {
          const colOpacity = interpolate(
            frame,
            [10 + colIndex * 20, 25 + colIndex * 20],
            [0, 1],
            { extrapolateRight: 'clamp' }
          );

          return (
            <div key={colIndex} style={{ flex: 1, opacity: colOpacity }}>
              <h3
                style={{
                  fontSize: theme.fontSize.body - 4,
                  fontWeight: 'bold',
                  color: theme.colors.primary,
                  margin: 0,
                  marginBottom: theme.spacing.sm,
                  borderBottom: `2px solid ${theme.colors.primary}`,
                  paddingBottom: theme.spacing.xs,
                }}
              >
                {analysis.title}
              </h3>
              <ul style={{ listStyle: 'disc', paddingLeft: theme.spacing.md, margin: 0 }}>
                {analysis.points.map((point, pointIndex) => {
                  const pointOpacity = interpolate(
                    frame,
                    [20 + colIndex * 20 + pointIndex * 6, 32 + colIndex * 20 + pointIndex * 6],
                    [0, 1],
                    { extrapolateRight: 'clamp' }
                  );
                  return (
                    <li
                      key={pointIndex}
                      style={{
                        fontSize: theme.fontSize.small,
                        color: theme.colors.text,
                        marginBottom: theme.spacing.xs,
                        opacity: pointOpacity,
                        lineHeight: 1.4,
                      }}
                    >
                      {point}
                    </li>
                  );
                })}
              </ul>
            </div>
          );
        })}
      </div>
    </SlideLayout>
  );
};
