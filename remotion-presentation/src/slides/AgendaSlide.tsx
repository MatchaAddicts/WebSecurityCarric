import React from 'react';
import { interpolate, useCurrentFrame } from 'remotion';
import { SlideLayout } from '../components/SlideLayout';
import { theme } from '../styles/theme';

interface AgendaSlideProps {
  items: string[];
  footerTitle: string;
  pageNumber: number;
}

export const AgendaSlide: React.FC<AgendaSlideProps> = ({
  items,
  footerTitle,
  pageNumber,
}) => {
  const frame = useCurrentFrame();

  return (
    <SlideLayout footerTitle={footerTitle} pageNumber={pageNumber} animate={false}>
      <h1
        style={{
          fontSize: theme.fontSize.heading,
          fontWeight: 'bold',
          color: theme.colors.text,
          margin: 0,
          marginBottom: theme.spacing.lg,
        }}
      >
        Agenda
      </h1>
      <ul
        style={{
          listStyle: 'disc',
          paddingLeft: theme.spacing.lg,
          margin: 0,
        }}
      >
        {items.map((item, index) => {
          const itemOpacity = interpolate(
            frame,
            [10 + index * 8, 20 + index * 8],
            [0, 1],
            { extrapolateRight: 'clamp' }
          );
          const itemTranslateX = interpolate(
            frame,
            [10 + index * 8, 20 + index * 8],
            [-20, 0],
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
                transform: `translateX(${itemTranslateX}px)`,
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
