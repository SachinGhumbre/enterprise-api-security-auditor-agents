import '@testing-library/jest-dom';

import React from 'react';
import { render, screen } from '@testing-library/react';

import { CardView, CitationList, OriginBadge } from './chat';

describe('chat components', () => {
  test('origin badge distinguishes verified from AI-generated', () => {
    const { rerender } = render(<OriginBadge verified model="muse-spark-1.3" />);
    expect(screen.getByText('Verified findings')).toBeInTheDocument();
    rerender(<OriginBadge verified={false} model="muse-spark-1.3" />);
    expect(screen.getByText('AI-generated')).toBeInTheDocument();
  });

  test('citations render as evidence refs', () => {
    render(
      <CitationList
        citations={[
          { kind: 'policy', ref: 'source:01_authentication_policy.txt' },
          { kind: 'finding', ref: 'R-SvcB-authentication' },
        ]}
      />
    );
    expect(screen.getByText(/source:01_authentication_policy.txt/)).toBeInTheDocument();
    expect(screen.getByText(/R-SvcB-authentication/)).toBeInTheDocument();
  });

  test('completed task card offers navigation without polling', () => {
    global.fetch = jest.fn();
    const onNavigate = jest.fn();
    render(
      <CardView
        card={{ kind: 'task', task_id: 'task-1', assessment_id: 'asm-1', status: 'complete' }}
        onNavigate={onNavigate}
      />
    );
    expect(screen.getByText('Completed')).toBeInTheDocument();
    expect(global.fetch).not.toHaveBeenCalled();
    jest.restoreAllMocks();
  });

  test('unknown card kinds render nothing', () => {
    const { container } = render(<CardView card={{ kind: 'mystery' }} onNavigate={() => {}} />);
    expect(container).toBeEmptyDOMElement();
  });
});
