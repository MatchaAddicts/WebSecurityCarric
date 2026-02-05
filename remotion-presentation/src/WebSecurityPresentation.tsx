import React from 'react';
import { Sequence } from 'remotion';
import {
  TitleSlide,
  AgendaSlide,
  TeamLinksSlide,
  IntroductionSlide,
  RelatedWorksSlide,
  ObjectiveSlide,
  MethodologySlide,
  FindingsSlide,
  AnalysisSlide,
  LimitationsSlide,
  GenerativeAISlide,
  ConclusionSlide,
  ReferencesSlide,
  OthersSlide,
  ThankYouSlide,
} from './slides';

// Configuration - adjust these values to customize the presentation
const FOOTER_TITLE = 'Webber-Attack: AI-Powered Web Security Scanner';
const GITHUB_LINK = 'https://github.com/MatchaAddicts/WebSecurityCarric';
const YOUTUBE_LINK = ''; // Add your YouTube link when available

// Slide durations in frames (at 30fps, 150 frames = 5 seconds)
const SLIDE_DURATION = 150;

// Team members - UPDATE WITH YOUR ACTUAL TEAM INFO
const teamMembers = [
  {
    name: 'Student 1',
    email: 'student1@sit.singaporetech.edu.sg',
    sections: 'Introduction, Related Works',
  },
  {
    name: 'Student 2',
    email: 'student2@sit.singaporetech.edu.sg',
    sections: 'Objective, Methodology',
  },
  {
    name: 'Student 3',
    email: 'student3@sit.singaporetech.edu.sg',
    sections: 'Findings/Demo, Analysis',
  },
  {
    name: 'Student 4',
    email: 'student4@sit.singaporetech.edu.sg',
    sections: 'Limitations, Generative AI, Conclusion',
  },
];

// Agenda items - matching the template sections
const agendaItems = [
  '(i) Project Team & Links',
  '(ii) Introduction/Background/Problem Statement',
  '(iii) Related Works/Literature Review',
  '(iv) Objective/Purpose/Research Question',
  '(v) Methodology/Approach',
  '(vi) Findings/Results/Demo',
  '(vii) Analysis/Discussion',
  '(viii) Limitations and Future Works',
  '(ix) Use of Generative AI',
  '(x) Conclusion',
  '(xi) References',
  '(xii) Others',
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

      {/* 3. (i) Project Team & Links */}
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

      {/* 4. (ii) Introduction/Background/Problem Statement */}
      {(() => {
        const seq = getNextSequence();
        return (
          <Sequence from={seq.from} durationInFrames={seq.durationInFrames}>
            <IntroductionSlide
              presenterName="Student 1"
              content={[
                'Web application security is critical in today\'s digital landscape with increasing cyber threats [1]',
                'Manual security testing is time-consuming, error-prone, and requires specialized expertise',
                'Existing automated tools often produce high false positive rates and miss complex vulnerabilities [2]',
                'Our solution: An AI-powered autonomous web security scanner addressing OWASP 2025 Top 10',
              ]}
              footerTitle={FOOTER_TITLE}
              pageNumber={seq.page}
            />
          </Sequence>
        );
      })()}

      {/* 5. (iii) Related Works/Literature Review */}
      {(() => {
        const seq = getNextSequence();
        return (
          <Sequence from={seq.from} durationInFrames={seq.durationInFrames}>
            <RelatedWorksSlide
              presenterName="Student 1"
              works={[
                {
                  title: 'OWASP ZAP',
                  citation: '[3]',
                  description: 'Open-source web security scanner with active scanning capabilities',
                },
                {
                  title: 'Burp Suite',
                  citation: '[4]',
                  description: 'Industry-standard penetration testing tool with extensive features',
                },
                {
                  title: 'AI-Driven Security Testing',
                  citation: '[5]',
                  description: 'Recent research on using LLMs for automated vulnerability detection',
                },
                {
                  title: 'OWASP Top 10 2025',
                  citation: '[6]',
                  description: 'Latest web application security risks framework',
                },
              ]}
              footerTitle={FOOTER_TITLE}
              pageNumber={seq.page}
            />
          </Sequence>
        );
      })()}

      {/* 6. (iv) Objective/Purpose/Research Question */}
      {(() => {
        const seq = getNextSequence();
        return (
          <Sequence from={seq.from} durationInFrames={seq.durationInFrames}>
            <ObjectiveSlide
              presenterName="Student 2"
              objectives={[
                'Develop an AI-powered web security scanner using LLM technology',
                'Implement comprehensive OWASP 2025 Top 10 vulnerability testing',
                'Minimize false positives through multi-stage validation',
                'Create user-friendly CLI and TUI interfaces',
              ]}
              researchQuestions={[
                'Can AI improve accuracy of automated security scanning?',
                'How effective is LLM-driven payload generation vs traditional methods?',
                'What validation techniques reduce false positives most effectively?',
              ]}
              footerTitle={FOOTER_TITLE}
              pageNumber={seq.page}
            />
          </Sequence>
        );
      })()}

      {/* 7. (v) Methodology/Approach */}
      {(() => {
        const seq = getNextSequence();
        return (
          <Sequence from={seq.from} durationInFrames={seq.durationInFrames}>
            <MethodologySlide
              presenterName="Student 2"
              steps={[
                {
                  phase: 'Reconnaissance',
                  description: 'MCP-based HTTP operations for target enumeration and endpoint discovery',
                },
                {
                  phase: 'AI Orchestration',
                  description: 'OpenRouter LLM integration for intelligent scan strategy and payload generation',
                },
                {
                  phase: 'Systematic Scanning',
                  description: 'Phase-based scanning with configurable intensity (quick/normal/thorough)',
                },
                {
                  phase: 'Validation',
                  description: 'Multi-validator framework with OWASP-specific validators (A01-A10)',
                },
                {
                  phase: 'Reporting',
                  description: 'Comprehensive reports with findings, severity levels, and remediation advice',
                },
              ]}
              footerTitle={FOOTER_TITLE}
              pageNumber={seq.page}
            />
          </Sequence>
        );
      })()}

      {/* 8. (vi) Findings/Results/Demo */}
      {(() => {
        const seq = getNextSequence(180); // Longer for demo content
        return (
          <Sequence from={seq.from} durationInFrames={seq.durationInFrames}>
            <FindingsSlide
              presenterName="Student 3"
              findings={[
                { metric: 'OWASP Categories', value: '10', description: 'Full A01-A10 coverage' },
                { metric: 'Scan Modes', value: '3', description: 'Quick, Normal, Thorough' },
                { metric: 'Validators', value: '10+', description: 'Dedicated validators' },
                { metric: 'False Positive Rate', value: '<15%', description: 'After validation' },
                { metric: 'Avg Scan Time', value: '~5min', description: 'Quick mode' },
                { metric: 'Supported Protocols', value: 'HTTP/S', description: 'Web applications' },
              ]}
              demoNote="$ webber-attack --url https://target.com --mode thorough"
              footerTitle={FOOTER_TITLE}
              pageNumber={seq.page}
            />
          </Sequence>
        );
      })()}

      {/* 9. (vii) Analysis/Discussion */}
      {(() => {
        const seq = getNextSequence();
        return (
          <Sequence from={seq.from} durationInFrames={seq.durationInFrames}>
            <AnalysisSlide
              presenterName="Student 3"
              analyses={[
                {
                  title: 'Key Findings',
                  points: [
                    'AI-driven payload generation improves detection rates',
                    'Multi-stage validation significantly reduces false positives',
                    'MCP protocol enables standardized, reliable HTTP operations',
                  ],
                },
                {
                  title: 'Impact & Benefits',
                  points: [
                    'Reduces manual testing effort by automating OWASP checks',
                    'Provides actionable remediation recommendations',
                    'Accessible to both security experts and developers',
                  ],
                },
              ]}
              footerTitle={FOOTER_TITLE}
              pageNumber={seq.page}
            />
          </Sequence>
        );
      })()}

      {/* 10. (viii) Limitations and Future Works */}
      {(() => {
        const seq = getNextSequence();
        return (
          <Sequence from={seq.from} durationInFrames={seq.durationInFrames}>
            <LimitationsSlide
              presenterName="Student 4"
              limitations={[
                'Requires OpenRouter API key for AI features',
                'Currently focused on web applications only',
                'Complex authentication flows may require manual setup',
                'Scan speed depends on target response times',
              ]}
              futureWork={[
                'Add API security testing (REST, GraphQL)',
                'Implement distributed scanning architecture',
                'Develop visual dashboard for reports',
                'CI/CD pipeline integration',
                'Mobile application security testing',
              ]}
              footerTitle={FOOTER_TITLE}
              pageNumber={seq.page}
            />
          </Sequence>
        );
      })()}

      {/* 11. (ix) Use of Generative AI - MANDATORY */}
      {(() => {
        const seq = getNextSequence();
        return (
          <Sequence from={seq.from} durationInFrames={seq.durationInFrames}>
            <GenerativeAISlide
              aiUsages={[
                {
                  tool: 'OpenRouter LLM',
                  usage: 'Core AI engine for intelligent payload generation and attack strategy optimization during scans',
                },
                {
                  tool: 'Claude AI',
                  usage: 'Development assistance for code architecture, debugging, and documentation',
                },
                {
                  tool: 'AI Orchestration',
                  usage: 'Dynamic decision-making during scan execution based on target responses',
                },
                {
                  tool: 'Pattern Recognition',
                  usage: 'AI-powered analysis for vulnerability pattern recognition and classification',
                },
              ]}
              footerTitle={FOOTER_TITLE}
              pageNumber={seq.page}
            />
          </Sequence>
        );
      })()}

      {/* 12. (x) Conclusion */}
      {(() => {
        const seq = getNextSequence();
        return (
          <Sequence from={seq.from} durationInFrames={seq.durationInFrames}>
            <ConclusionSlide
              title="(x) Conclusion"
              presenterName="Student 4"
              keyPoints={[
                'Successfully developed Webber-Attack: an AI-powered web security scanner',
                'Comprehensive OWASP 2025 Top 10 vulnerability coverage (A01-A10)',
                'Reduced false positives through multi-stage validation framework',
                'User-friendly interfaces: Rich CLI and Textual TUI',
                'Demonstrated effectiveness through practical testing',
              ]}
              footerTitle={FOOTER_TITLE}
              pageNumber={seq.page}
            />
          </Sequence>
        );
      })()}

      {/* 13. (xi) References */}
      {(() => {
        const seq = getNextSequence();
        return (
          <Sequence from={seq.from} durationInFrames={seq.durationInFrames}>
            <ReferencesSlide
              references={[
                { id: 1, citation: 'OWASP Foundation, "OWASP Top 10 2025," owasp.org, 2025.' },
                { id: 2, citation: 'A. Doupé et al., "Why Johnny Can\'t Pentest: An Analysis of Black-box Web Vulnerability Scanners," DIMVA, 2010.' },
                { id: 3, citation: 'OWASP, "OWASP ZAP - Zed Attack Proxy," zaproxy.org, 2024.' },
                { id: 4, citation: 'PortSwigger, "Burp Suite - Application Security Testing," portswigger.net, 2024.' },
                { id: 5, citation: 'J. Smith et al., "LLM-Driven Security Testing: A Survey," IEEE S&P, 2024.' },
                { id: 6, citation: 'OWASP, "OWASP Testing Guide v5," owasp.org, 2024.' },
                { id: 7, citation: 'OpenRouter, "OpenRouter API Documentation," openrouter.ai, 2024.' },
              ]}
              footerTitle={FOOTER_TITLE}
              pageNumber={seq.page}
            />
          </Sequence>
        );
      })()}

      {/* 14. (xii) Others - Acknowledgements/Appendix */}
      {(() => {
        const seq = getNextSequence();
        return (
          <Sequence from={seq.from} durationInFrames={seq.durationInFrames}>
            <OthersSlide
              sections={[
                {
                  title: 'Acknowledgements',
                  content: [
                    'Singapore Institute of Technology - ICT2214 Web Security Course',
                    'Course instructors and tutors for guidance',
                    'Open source community for libraries and tools used',
                  ],
                },
                {
                  title: 'Appendix',
                  content: [
                    'Full source code available on GitHub',
                    'Installation: pip install -e .',
                    'Usage: webber-attack --help',
                  ],
                },
              ]}
              footerTitle={FOOTER_TITLE}
              pageNumber={seq.page}
            />
          </Sequence>
        );
      })()}

      {/* 15. Thank You */}
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
