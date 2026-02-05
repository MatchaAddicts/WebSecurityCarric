import React from 'react';
import { interpolate, useCurrentFrame } from 'remotion';
import { SlideLayout } from '../components/SlideLayout';
import { theme } from '../styles/theme';

interface AIUsage {
  tool: string;
  usage: string;
}

interface GenerativeAISlideProps {
  aiUsages: AIUsage[];
  footerTitle: string;
  pageNumber: number;
}

export const GenerativeAISlide: React.FC<GenerativeAISlideProps> = ({
  aiUsages,
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
          marginBottom: theme.spacing.lg,
        }}
      >
        Use of Generative AI
      </h1>

      <div>
        {aiUsages.map((item, index) => {
          const itemOpacity = interpolate(
            frame,
            [10 + index * 12, 25 + index * 12],
            [0, 1],
            { extrapolateRight: 'clamp' }
          );
          const itemTranslateX = interpolate(
            frame,
            [10 + index * 12, 25 + index * 12],
            [-30, 0],
            { extrapolateRight: 'clamp' }
          );

          return (
            <div
              key={index}
              style={{
                marginBottom: theme.spacing.md,
                opacity: itemOpacity,
                transform: `translateX(${itemTranslateX}px)`,
              }}
            >
              <div
                style={{
                  display: 'flex',
                  alignItems: 'flex-start',
                  gap: theme.spacing.md,
                }}
              >
                <div
                  style={{
                    backgroundColor: theme.colors.primary,
                    color: 'white',
                    padding: `${theme.spacing.xs}px ${theme.spacing.sm}px`,
                    borderRadius: 4,
                    fontSize: theme.fontSize.small,
                    fontWeight: 'bold',
                    minWidth: 180,
                    textAlign: 'center',
                  }}
                >
                  {item.tool}
                </div>
                <p
                  style={{
                    fontSize: theme.fontSize.body - 4,
                    color: theme.colors.text,
                    margin: 0,
                    flex: 1,
                    lineHeight: 1.4,
                  }}
                >
                  {item.usage}
                </p>
              </div>
            </div>
          );
        })}
      </div>
    </SlideLayout>
  );
};
