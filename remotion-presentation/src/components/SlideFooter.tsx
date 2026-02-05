import React from 'react';
import { theme } from '../styles/theme';

interface SlideFooterProps {
  title: string;
  pageNumber: number;
}

export const SlideFooter: React.FC<SlideFooterProps> = ({ title, pageNumber }) => {
  return (
    <div
      style={{
        position: 'absolute',
        bottom: theme.spacing.md,
        left: 0,
        right: 0,
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center',
        padding: `0 ${theme.spacing.lg}px`,
        color: theme.colors.textMuted,
        fontSize: theme.fontSize.small,
      }}
    >
      <div style={{ flex: 1 }} />
      <div style={{ textAlign: 'center', flex: 2 }}>{title}</div>
      <div style={{ flex: 1, textAlign: 'right' }}>{pageNumber}</div>
    </div>
  );
};
