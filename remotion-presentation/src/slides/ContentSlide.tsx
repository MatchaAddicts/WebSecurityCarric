import React from 'react';
import { interpolate, useCurrentFrame } from 'remotion';
import { SlideLayout } from '../components/SlideLayout';
import { theme } from '../styles/theme';

interface ContentSlideProps {
  title: string;
  presenterName?: string;
  content: string[];
  footerTitle: string;
  pageNumber: number;
}

export const ContentSlide: React.FC<ContentSlideProps> = ({
  title,
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
          marginBottom: presenterName ? theme.spacing.xs : theme.spacing.lg,
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
            marginBottom: theme.spacing.lg,
          }}
        >
          Presented by: {presenterName}
        </p>
      )}

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
            [10 + index * 8, 22 + index * 8],
            [0, 1],
            { extrapolateRight: 'clamp' }
          );

          return (
            <li
              key={index}
              style={{
                fontSize: theme.fontSize.body,
                color: theme.colors.text,
                marginBottom: theme.spacing.sm,
                opacity: itemOpacity,
                lineHeight: 1.4,
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
