import React from 'react';
import { Sequence } from 'remotion';
import {
  TitleSlide,
  AgendaSlide,
  TeamLinksSlide,
  IntroductionSlide,
  ContentSlide,
  FeaturesSlide,
  GenerativeAISlide,
  DemoSlide,
  ConclusionSlide,
  ThankYouSlide,
} from './slides';

// Configuration - adjust these values to customize the presentation
const FOOTER_TITLE = 'Webber-Attack: AI-Powered Web Security Scanner';
const GITHUB_LINK = 'https://github.com/MatchaAddicts/WebSecurityCarric';
const YOUTUBE_LINK = ''; // Add your YouTube link when available

// Slide durations in frames (at 30fps, 90 frames = 3 seconds)
const SLIDE_DURATION = 150; // 5 seconds per slide

// Team members - UPDATE WITH YOUR ACTUAL TEAM INFO
const teamMembers = [
  {
    name: 'Student 1',
    email: 'student1@sit.singaporetech.edu.sg',
    sections: 'Introduction, Problem Statement',
  },
  {
    name: 'Student 2',
    email: 'student2@sit.singaporetech.edu.sg',
    sections: 'Technical Architecture, Features',
  },
  {
    name: 'Student 3',
    email: 'student3@sit.singaporetech.edu.sg',
    sections: 'Demo, Use of Generative AI',
  },
  {
    name: 'Student 4',
    email: 'student4@sit.singaporetech.edu.sg',
    sections: 'Conclusion, Future Work',
  },
];

// Agenda items
const agendaItems = [
  'Project Team & Links',
  'Introduction / Problem Statement',
  'Technical Architecture',
  'Key Features',
  'Live Demo',
  'Use of Generative AI',
  'Conclusion & Future Work',
];

export const WebSecurityPresentation: React.FC = () => {
  let currentFrame = 0;
  let pageNumber = 1;

  const getNextSequence = (duration: number = SLIDE_DURATION) => {
    const from = currentFrame;
    currentFrame += duration;
    return { from, durationInFrames: duration, page: pageNumber++ };
  };

  return (
    <>
      {/* 1. Title Slide */}
      {(() => {
        const seq = getNextSequence();
        return (
          <Sequence from={seq.from} durationInFrames={seq.durationInFrames}>
            <TitleSlide
              title="Webber-Attack"
              subtitle="AI-Powered Web Security Vulnerability Scanner"
              footerTitle={FOOTER_TITLE}
            />
          </Sequence>
        );
      })()}

      {/* 2. Agenda Slide */}
      {(() => {
        const seq = getNextSequence();
        return (
          <Sequence from={seq.from} durationInFrames={seq.durationInFrames}>
            <AgendaSlide
              items={agendaItems}
              footerTitle={FOOTER_TITLE}
              pageNumber={seq.page}
            />
          </Sequence>
        );
      })()}

      {/* 3. Project Team & Links */}
      {(() => {
        const seq = getNextSequence();
        return (
          <Sequence from={seq.from} durationInFrames={seq.durationInFrames}>
            <TeamLinksSlide
              teamMembers={teamMembers}
              githubLink={GITHUB_LINK}
              youtubeLink={YOUTUBE_LINK}
              footerTitle={FOOTER_TITLE}
              pageNumber={seq.page}
            />
          </Sequence>
        );
      })()}

      {/* 4. Introduction / Problem Statement */}
      {(() => {
        const seq = getNextSequence();
        return (
          <Sequence from={seq.from} durationInFrames={seq.durationInFrames}>
            <IntroductionSlide
              presenterName="Student 1"
              content={[
                'Web application security is critical in today\'s digital landscape with increasing cyber threats',
                'Manual security testing is time-consuming, error-prone, and requires specialized expertise',
                'Existing automated tools often produce high false positive rates and miss complex vulnerabilities',
                'Our solution: An AI-powered autonomous web security scanner that addresses these challenges',
              ]}
              footerTitle={FOOTER_TITLE}
              pageNumber={seq.page}
            />
          </Sequence>
        );
      })()}

      {/* 5. Technical Architecture */}
      {(() => {
        const seq = getNextSequence();
        return (
          <Sequence from={seq.from} durationInFrames={seq.durationInFrames}>
            <ContentSlide
              title="(iii) Technical Architecture"
              presenterName="Student 2"
              content={[
                'AI Agent Orchestration System using OpenRouter LLM integration',
                'Model Context Protocol (MCP) for standardized HTTP operations',
                'Systematic scanning engine with configurable intensity modes',
                'Multi-validator framework with dedicated OWASP category validators',
                'MySQL database backend for persistent findings storage',
              ]}
              footerTitle={FOOTER_TITLE}
              pageNumber={seq.page}
            />
          </Sequence>
        );
      })()}

      {/* 6. Key Features */}
      {(() => {
        const seq = getNextSequence();
        return (
          <Sequence from={seq.from} durationInFrames={seq.durationInFrames}>
            <FeaturesSlide
              title="(iv) Key Features"
              presenterName="Student 2"
              features={[
                {
                  title: 'OWASP 2025 Coverage',
                  description: 'Complete coverage of OWASP Top 10 2025 vulnerabilities (A01-A10)',
                },
                {
                  title: 'AI-Powered Intelligence',
                  description: 'LLM-driven payload generation and attack pattern optimization',
                },
                {
                  title: 'False Positive Validation',
                  description: 'Multi-stage validation to minimize false positives',
                },
                {
                  title: 'Flexible Scan Modes',
                  description: 'Quick, Normal, and Thorough scan intensity options',
                },
                {
                  title: 'Rich CLI & TUI',
                  description: 'Beautiful terminal interface with real-time progress',
                },
                {
                  title: 'Comprehensive Reporting',
                  description: 'Detailed reports with remediation recommendations',
                },
              ]}
              footerTitle={FOOTER_TITLE}
              pageNumber={seq.page}
            />
          </Sequence>
        );
      })()}

      {/* 7. Demo Slide */}
      {(() => {
        const seq = getNextSequence(180); // Longer for demo
        return (
          <Sequence from={seq.from} durationInFrames={seq.durationInFrames}>
            <DemoSlide
              title="(v) Live Demo"
              presenterName="Student 3"
              description="Demonstrating Webber-Attack scanning a test web application for OWASP vulnerabilities"
              demoSteps={[
                'webber-attack --url https://target-app.com',
                'Select scan mode: quick / normal / thorough',
                'Watch AI-powered reconnaissance phase',
                'Observe systematic vulnerability testing',
                'Review validated findings and generated report',
              ]}
              footerTitle={FOOTER_TITLE}
              pageNumber={seq.page}
            />
          </Sequence>
        );
      })()}

      {/* 8. Use of Generative AI */}
      {(() => {
        const seq = getNextSequence();
        return (
          <Sequence from={seq.from} durationInFrames={seq.durationInFrames}>
            <GenerativeAISlide
              aiUsages={[
                {
                  tool: 'OpenRouter LLM',
                  usage: 'Intelligent payload generation and attack strategy optimization',
                },
                {
                  tool: 'Claude AI',
                  usage: 'Code development assistance and architecture design',
                },
                {
                  tool: 'AI Orchestration',
                  usage: 'Dynamic decision making during scan execution',
                },
                {
                  tool: 'Pattern Analysis',
                  usage: 'AI-powered vulnerability pattern recognition',
                },
              ]}
              footerTitle={FOOTER_TITLE}
              pageNumber={seq.page}
            />
          </Sequence>
        );
      })()}

      {/* 9. Conclusion */}
      {(() => {
        const seq = getNextSequence();
        return (
          <Sequence from={seq.from} durationInFrames={seq.durationInFrames}>
            <ConclusionSlide
              title="(vi) Conclusion & Future Work"
              presenterName="Student 4"
              keyPoints={[
                'Successfully developed an AI-powered web security scanner',
                'Comprehensive OWASP 2025 Top 10 vulnerability coverage',
                'Reduced false positives through multi-stage validation',
                'User-friendly CLI and TUI interfaces',
              ]}
              futureWork={[
                'Add support for API security testing',
                'Implement distributed scanning capabilities',
                'Enhance reporting with visual dashboards',
                'Integration with CI/CD pipelines',
              ]}
              footerTitle={FOOTER_TITLE}
              pageNumber={seq.page}
            />
          </Sequence>
        );
      })()}

      {/* 10. Thank You */}
      {(() => {
        const seq = getNextSequence(120);
        return (
          <Sequence from={seq.from} durationInFrames={seq.durationInFrames}>
            <ThankYouSlide
              footerTitle={FOOTER_TITLE}
              pageNumber={seq.page}
              githubLink={GITHUB_LINK}
            />
          </Sequence>
        );
      })()}
    </>
  );
};
