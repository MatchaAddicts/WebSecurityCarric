import React from 'react';
import { interpolate, useCurrentFrame } from 'remotion';
import { SlideLayout } from '../components/SlideLayout';
import { theme } from '../styles/theme';

interface TeamMember {
  name: string;
  email: string;
  sections: string;
}

interface TeamLinksSlideProps {
  teamMembers: TeamMember[];
  githubLink: string;
  youtubeLink?: string;
  footerTitle: string;
  pageNumber: number;
}

export const TeamLinksSlide: React.FC<TeamLinksSlideProps> = ({
  teamMembers,
  githubLink,
  youtubeLink,
  footerTitle,
  pageNumber,
}) => {
  const frame = useCurrentFrame();

  const tableOpacity = interpolate(frame, [10, 25], [0, 1], {
    extrapolateRight: 'clamp',
  });

  const linksOpacity = interpolate(frame, [30, 45], [0, 1], {
    extrapolateRight: 'clamp',
  });

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
        (i) Project Team & Links
      </h1>

      <div style={{ opacity: tableOpacity }}>
        <table
          style={{
            width: '100%',
            borderCollapse: 'collapse',
            marginBottom: theme.spacing.lg,
          }}
        >
          <thead>
            <tr>
              <th
                style={{
                  backgroundColor: theme.colors.tableHeader,
                  color: 'white',
                  padding: theme.spacing.sm,
                  textAlign: 'left',
                  fontSize: theme.fontSize.body - 4,
                  fontWeight: 'bold',
                }}
              >
                Name/Email
              </th>
              <th
                style={{
                  backgroundColor: theme.colors.tableHeader,
                  color: 'white',
                  padding: theme.spacing.sm,
                  textAlign: 'left',
                  fontSize: theme.fontSize.body - 4,
                  fontWeight: 'bold',
                }}
              >
                Section Responsible
              </th>
              <th
                style={{
                  backgroundColor: theme.colors.tableHeader,
                  color: 'white',
                  padding: theme.spacing.sm,
                  textAlign: 'center',
                  fontSize: theme.fontSize.body - 4,
                  fontWeight: 'bold',
                  width: 140,
                }}
              >
                Group Mark (10%)
              </th>
              <th
                style={{
                  backgroundColor: theme.colors.tableHeader,
                  color: 'white',
                  padding: theme.spacing.sm,
                  textAlign: 'center',
                  fontSize: theme.fontSize.body - 4,
                  fontWeight: 'bold',
                  width: 140,
                }}
              >
                Individual Mark (20%)
              </th>
            </tr>
          </thead>
          <tbody>
            {teamMembers.map((member, index) => (
              <tr key={index}>
                <td
                  style={{
                    backgroundColor:
                      index % 2 === 0
                        ? theme.colors.tableRowEven
                        : theme.colors.tableRowOdd,
                    padding: theme.spacing.sm,
                    fontSize: theme.fontSize.small,
                  }}
                >
                  <div style={{ fontStyle: 'italic' }}>{member.name}</div>
                  <div>{member.email}</div>
                </td>
                <td
                  style={{
                    backgroundColor:
                      index % 2 === 0
                        ? theme.colors.tableRowEven
                        : theme.colors.tableRowOdd,
                    padding: theme.spacing.sm,
                    fontSize: theme.fontSize.small,
                    fontStyle: 'italic',
                  }}
                >
                  {member.sections}
                </td>
                <td
                  style={{
                    backgroundColor: '#d0d8dc',
                    padding: theme.spacing.sm,
                  }}
                />
                <td
                  style={{
                    backgroundColor: '#e8ecee',
                    padding: theme.spacing.sm,
                  }}
                />
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <div
        style={{
          opacity: linksOpacity,
          fontSize: theme.fontSize.body - 4,
        }}
      >
        <p style={{ margin: `${theme.spacing.xs}px 0` }}>
          <strong>GitHub:</strong> {githubLink}
        </p>
        {youtubeLink && (
          <p style={{ margin: `${theme.spacing.xs}px 0` }}>
            <strong>YouTube:</strong> {youtubeLink}
          </p>
        )}
        <p
          style={{
            margin: `${theme.spacing.sm}px 0 0 0`,
            fontWeight: 'bold',
          }}
        >
          This section is mandatory.
        </p>
      </div>
    </SlideLayout>
  );
};
