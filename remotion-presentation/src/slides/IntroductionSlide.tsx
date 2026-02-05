import React from 'react';
import { interpolate, useCurrentFrame } from 'remotion';
import { SlideLayout } from '../components/SlideLayout';
import { theme } from '../styles/theme';

interface IntroductionSlideProps {
  presenterName: string;
  content: string[];
  footerTitle: string;
  pageNumber: number;
}

export const IntroductionSlide: React.FC<IntroductionSlideProps> = ({
  presenterName,
  content,
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
          marginBottom: theme.spacing.sm,
        }}
      >
        (ii) Introduction/Background/Problem Statement
      </h1>
      <p
        style={{
          fontSize: theme.fontSize.small,
          color: theme.colors.textMuted,
          margin: 0,
          marginBottom: theme.spacing.lg,
        }}
      >
        Presented by: {presenterName}
      </p>

      <ul
        style={{
          listStyle: 'disc',
          paddingLeft: theme.spacing.lg,
          margin: 0,
        }}
      >
        {content.map((item, index) => {
          const itemOpacity = interpolate(
            frame,
            [15 + index * 10, 30 + index * 10],
            [0, 1],
            { extrapolateRight: 'clamp' }
          );

          return (
            <li
              key={index}
              style={{
                fontSize: theme.fontSize.body,
                color: theme.colors.text,
                marginBottom: theme.spacing.md,
                opacity: itemOpacity,
                lineHeight: 1.5,
              }}
            >
              {item}
            </li>
          );
        })}
      </ul>
    </SlideLayout>
  );
};
