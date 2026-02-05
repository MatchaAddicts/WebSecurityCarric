import React from 'react';
import { interpolate, useCurrentFrame } from 'remotion';
import { SlideLayout } from '../components/SlideLayout';
import { theme } from '../styles/theme';

interface OthersSection {
  title: string;
  content: string[];
}

interface OthersSlideProps {
  presenterName?: string;
  sections: OthersSection[];
  footerTitle: string;
  pageNumber: number;
}

export const OthersSlide: React.FC<OthersSlideProps> = ({
  presenterName,
  sections,
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
        (xii) Others
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

      <div style={{ display: 'flex', flexDirection: 'column', gap: theme.spacing.md }}>
        {sections.map((section, sectionIndex) => {
          const sectionOpacity = interpolate(
            frame,
            [10 + sectionIndex * 15, 25 + sectionIndex * 15],
            [0, 1],
            { extrapolateRight: 'clamp' }
          );

          return (
            <div key={sectionIndex} style={{ opacity: sectionOpacity }}>
              <h3
                style={{
                  fontSize: theme.fontSize.body - 4,
                  fontWeight: 'bold',
                  color: theme.colors.primary,
                  margin: 0,
                  marginBottom: theme.spacing.xs,
                }}
              >
                {section.title}
              </h3>
              <ul style={{ listStyle: 'disc', paddingLeft: theme.spacing.md, margin: 0 }}>
                {section.content.map((item, itemIndex) => (
                  <li
                    key={itemIndex}
                    style={{
                      fontSize: theme.fontSize.small,
                      color: theme.colors.text,
                      marginBottom: theme.spacing.xs / 2,
                      lineHeight: 1.4,
                    }}
                  >
                    {item}
                  </li>
                ))}
              </ul>
            </div>
          );
        })}
      </div>
    </SlideLayout>
  );
};
