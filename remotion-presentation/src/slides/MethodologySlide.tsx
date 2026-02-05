import React from 'react';
import { interpolate, useCurrentFrame } from 'remotion';
import { SlideLayout } from '../components/SlideLayout';
import { theme } from '../styles/theme';

interface MethodologyStep {
  phase: string;
  description: string;
}

interface MethodologySlideProps {
  presenterName?: string;
  steps: MethodologyStep[];
  footerTitle: string;
  pageNumber: number;
}

export const MethodologySlide: React.FC<MethodologySlideProps> = ({
  presenterName,
  steps,
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
        (v) Methodology/Approach
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

      <div style={{ display: 'flex', flexDirection: 'column', gap: theme.spacing.sm }}>
        {steps.map((step, index) => {
          const itemOpacity = interpolate(
            frame,
            [10 + index * 10, 25 + index * 10],
            [0, 1],
            { extrapolateRight: 'clamp' }
          );
          const itemTranslateX = interpolate(
            frame,
            [10 + index * 10, 25 + index * 10],
            [-20, 0],
            { extrapolateRight: 'clamp' }
          );

          return (
            <div
              key={index}
              style={{
                display: 'flex',
                alignItems: 'flex-start',
                gap: theme.spacing.md,
                opacity: itemOpacity,
                transform: `translateX(${itemTranslateX}px)`,
              }}
            >
              <div
                style={{
                  backgroundColor: theme.colors.primary,
                  color: 'white',
                  width: 36,
                  height: 36,
                  borderRadius: '50%',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  fontSize: theme.fontSize.small,
                  fontWeight: 'bold',
                  flexShrink: 0,
                }}
              >
                {index + 1}
              </div>
              <div style={{ flex: 1 }}>
                <h3
                  style={{
                    fontSize: theme.fontSize.body - 4,
                    fontWeight: 'bold',
                    color: theme.colors.primary,
                    margin: 0,
                    marginBottom: theme.spacing.xs / 2,
                  }}
                >
                  {step.phase}
                </h3>
                <p
                  style={{
                    fontSize: theme.fontSize.small,
                    color: theme.colors.textLight,
                    margin: 0,
                    lineHeight: 1.3,
                  }}
                >
                  {step.description}
                </p>
              </div>
            </div>
          );
        })}
      </div>
    </SlideLayout>
  );
};
