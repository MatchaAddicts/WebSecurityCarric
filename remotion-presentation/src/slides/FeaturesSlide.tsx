import React from 'react';
import { interpolate, useCurrentFrame } from 'remotion';
import { SlideLayout } from '../components/SlideLayout';
import { theme } from '../styles/theme';

interface Feature {
  title: string;
  description: string;
}

interface FeaturesSlideProps {
  title: string;
  presenterName?: string;
  features: Feature[];
  footerTitle: string;
  pageNumber: number;
}

export const FeaturesSlide: React.FC<FeaturesSlideProps> = ({
  title,
  presenterName,
  features,
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
          display: 'grid',
          gridTemplateColumns: 'repeat(2, 1fr)',
          gap: theme.spacing.md,
          marginTop: theme.spacing.sm,
        }}
      >
        {features.map((feature, index) => {
          const itemOpacity = interpolate(
            frame,
            [10 + index * 6, 20 + index * 6],
            [0, 1],
            { extrapolateRight: 'clamp' }
          );
          const itemScale = interpolate(
            frame,
            [10 + index * 6, 20 + index * 6],
            [0.95, 1],
            { extrapolateRight: 'clamp' }
          );

          return (
            <div
              key={index}
              style={{
                backgroundColor: '#f8f9fa',
                borderLeft: `4px solid ${theme.colors.primary}`,
                padding: theme.spacing.sm,
                opacity: itemOpacity,
                transform: `scale(${itemScale})`,
              }}
            >
              <h3
                style={{
                  fontSize: theme.fontSize.body - 4,
                  fontWeight: 'bold',
                  color: theme.colors.primary,
                  margin: 0,
                  marginBottom: theme.spacing.xs,
                }}
              >
                {feature.title}
              </h3>
              <p
                style={{
                  fontSize: theme.fontSize.small,
                  color: theme.colors.textLight,
                  margin: 0,
                  lineHeight: 1.3,
                }}
              >
                {feature.description}
              </p>
            </div>
          );
        })}
      </div>
    </SlideLayout>
  );
};
