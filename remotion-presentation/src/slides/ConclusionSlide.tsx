import React from 'react';
import { interpolate, useCurrentFrame, spring, useVideoConfig } from 'remotion';
import { SlideLayout } from '../components/SlideLayout';
import { theme } from '../styles/theme';

interface ConclusionSlideProps {
  title: string;
  presenterName?: string;
  keyPoints: string[];
  futureWork?: string[];
  footerTitle: string;
  pageNumber: number;
}

export const ConclusionSlide: React.FC<ConclusionSlideProps> = ({
  title,
  presenterName,
  keyPoints,
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

      <div style={{ display: 'flex', gap: theme.spacing.lg }}>
        <div style={{ flex: 1 }}>
          <h3
            style={{
              fontSize: theme.fontSize.body,
              fontWeight: 'bold',
              color: theme.colors.primary,
              margin: 0,
              marginBottom: theme.spacing.sm,
              opacity: interpolate(frame, [10, 20], [0, 1], {
                extrapolateRight: 'clamp',
              }),
            }}
          >
            Key Takeaways
          </h3>
          <ul
            style={{
              listStyle: 'disc',
              paddingLeft: theme.spacing.md,
              margin: 0,
            }}
          >
            {keyPoints.map((point, index) => {
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
                    fontSize: theme.fontSize.body - 4,
                    color: theme.colors.text,
                    marginBottom: theme.spacing.xs,
                    opacity: itemOpacity,
                    lineHeight: 1.4,
                  }}
                >
                  {point}
                </li>
              );
            })}
          </ul>
        </div>

        {futureWork && futureWork.length > 0 && (
          <div style={{ flex: 1 }}>
            <h3
              style={{
                fontSize: theme.fontSize.body,
                fontWeight: 'bold',
                color: theme.colors.primary,
                margin: 0,
                marginBottom: theme.spacing.sm,
                opacity: interpolate(frame, [30, 40], [0, 1], {
                  extrapolateRight: 'clamp',
                }),
              }}
            >
              Future Work
            </h3>
            <ul
              style={{
                listStyle: 'disc',
                paddingLeft: theme.spacing.md,
                margin: 0,
              }}
            >
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
                      fontSize: theme.fontSize.body - 4,
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
        )}
      </div>
    </SlideLayout>
  );
};
