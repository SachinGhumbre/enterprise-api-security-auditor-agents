import '@testing-library/jest-dom';

import React from 'react';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';

import Assistant from './Assistant';

const PROMPTS = { prompts: ['Audit all APIs and identify critical security issues', 'Why is this API marked non-compliant?'] };

function jsonResponse(body) {
  return { ok: true, status: 200, text: async () => JSON.stringify(body) };
}

describe('Assistant', () => {
  beforeEach(() => {
    sessionStorage.clear();
    global.fetch = jest.fn();
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  test('empty state shows suggested prompts', async () => {
    global.fetch
      .mockResolvedValueOnce(jsonResponse(PROMPTS))
      .mockResolvedValueOnce(jsonResponse({ conversations: [] }));
    render(<Assistant notify={() => {}} onNavigate={() => {}} />);
    await waitFor(() =>
      expect(
        screen.getByText('Audit all APIs and identify critical security issues')
      ).toBeInTheDocument()
    );
    expect(screen.getByText(/Ask about your API security posture/)).toBeInTheDocument();
  });

  test('compact mode hides the page header and collapses history', async () => {
    global.fetch
      .mockResolvedValueOnce(jsonResponse(PROMPTS))
      .mockResolvedValueOnce(
        jsonResponse({ conversations: [{ conversation_id: 'conv-1', title: 'Review' }] })
      )
      .mockResolvedValueOnce(
        jsonResponse({ conversation_id: 'conv-1', messages: [], tasks: [] })
      );
    render(<Assistant notify={() => {}} onNavigate={() => {}} compact />);
    await waitFor(() =>
      expect(screen.getByText('Conversations (1)')).toBeInTheDocument()
    );
    expect(screen.queryByText('Ask about your API security posture')).toBeInTheDocument();
    // History stays hidden until toggled.
    expect(screen.queryByText('Review')).not.toBeInTheDocument();
    fireEvent.click(screen.getByText('Conversations (1)'));
    expect(screen.getByText('Review')).toBeInTheDocument();
  });

  test('selecting a conversation renders verified and AI-generated messages', async () => {
    const thread = {
      conversation_id: 'conv-1',
      title: 'Review',
      assessment_id: 'asm-1',
      messages: [
        { message_id: 'm1', role: 'user', content: 'Show critical findings', created_at: '2026-01-01T00:00:00Z' },
        {
          message_id: 'm2',
          role: 'assistant',
          content: 'One critical entry.',
          intent: 'retrieve_findings',
          verified: true,
          model: 'muse-spark-1.3',
          citations: [{ kind: 'finding', ref: 'R-SvcB-authentication' }],
          tool_calls: [{ tool: 'assistant_read_findings', ok: true }],
          cards: [
            {
              kind: 'finding',
              assessment_id: 'asm-1',
              finding: {
                entry_id: 'R-SvcB-authentication',
                title: 'Authentication gap',
                service: 'SvcB',
                level: 'Critical',
                score: 9.1,
                severity: 'Critical',
                confidence: 'high',
                verified: true,
                state: 'open',
                evidence: [],
              },
            },
          ],
          created_at: '2026-01-01T00:00:01Z',
        },
      ],
      tasks: [],
    };
    global.fetch
      .mockResolvedValueOnce(jsonResponse(PROMPTS))
      .mockResolvedValueOnce(
        jsonResponse({ conversations: [{ conversation_id: 'conv-1', title: 'Review' }] })
      )
      .mockResolvedValueOnce(jsonResponse(thread));
    render(<Assistant notify={() => {}} onNavigate={() => {}} />);
    await waitFor(() => expect(screen.getByText('One critical entry.')).toBeInTheDocument());
    expect(screen.getByText('Verified findings')).toBeInTheDocument();
    expect(screen.getByText('R-SvcB-authentication')).toBeInTheDocument();
    expect(screen.getByText('Authentication gap')).toBeInTheDocument();
  });

  test('sending a prompt streams the reply then reloads the thread', async () => {
    // jsdom omits TextEncoder/TextDecoder; the streamed client needs both.
    const util = require('util');
    if (!global.TextEncoder) global.TextEncoder = util.TextEncoder;
    if (!global.TextDecoder) global.TextDecoder = util.TextDecoder;
    const encoder = new global.TextEncoder();
    const frames = [
      'data: {"type":"header","intent":"knowledge","citations":[],"cards":[],"task":null}\n\n',
      'data: {"delta":"streamed "}\n\n',
      'data: {"delta":"reply"}\n\n',
      'data: {"type":"done","message":{"message_id":"m9","role":"assistant","content":"streamed reply"},"model":"muse-spark-1.3"}\n\n',
    ];
    const chunks = frames.map((f) => encoder.encode(f));
    let index = 0;
    const reader = {
      read: async () => {
        if (index >= chunks.length) return { value: undefined, done: true };
        const value = chunks[index];
        index += 1;
        return { value, done: false };
      },
    };
    global.fetch
      .mockResolvedValueOnce(jsonResponse(PROMPTS))
      .mockResolvedValueOnce(jsonResponse({ conversations: [] }))
      .mockResolvedValueOnce(
        jsonResponse({ conversation_id: 'conv-9', title: 'New conversation' })
      )
      .mockResolvedValueOnce({ ok: true, status: 200, body: { getReader: () => reader } })
      .mockResolvedValueOnce(
        jsonResponse({
          conversation_id: 'conv-9',
          messages: [
            { message_id: 'u1', role: 'user', content: 'Why is this API marked non-compliant?' },
            { message_id: 'm9', role: 'assistant', content: 'streamed reply', verified: false },
          ],
        })
      )
      .mockResolvedValueOnce(jsonResponse({ conversations: [] }));
    const notify = jest.fn();
    render(<Assistant notify={notify} onNavigate={() => {}} />);
    await waitFor(() =>
      expect(
        screen.getByText('Why is this API marked non-compliant?')
      ).toBeInTheDocument()
    );
    fireEvent.click(screen.getByText('Why is this API marked non-compliant?'));
    await waitFor(() => expect(screen.getByText('streamed reply')).toBeInTheDocument());
    const streamCall = global.fetch.mock.calls.find(([url]) =>
      String(url).endsWith('/messages/stream')
    );
    expect(streamCall).toBeTruthy();
    expect(JSON.parse(streamCall[1].body).message).toBe(
      'Why is this API marked non-compliant?'
    );
  });

  test('proposal card links to the remediation centre', async () => {
    const thread = {
      conversation_id: 'conv-2',
      messages: [
        {
          message_id: 'm2',
          role: 'assistant',
          content: 'One proposal.',
          verified: true,
          cards: [
            {
              kind: 'proposal',
              source: 'preview',
              assessment_id: 'asm-2',
              proposal: {
                change_id: 'CH-svcb-enable_plugin-jwt',
                status: 'proposed',
                op: 'enable_plugin',
                plugin: 'jwt',
                target: { service: 'SvcB' },
                rationale: 'Enable jwt on SvcB.',
                preconditions: ['window agreed'],
                residual_risk: { before: 9.0, after: 4.0, level_before: 'Critical', level_after: 'Medium' },
              },
              simulation: { ok: true, effect: 'jwt enabled' },
            },
          ],
        },
      ],
      tasks: [],
    };
    global.fetch
      .mockResolvedValueOnce(jsonResponse(PROMPTS))
      .mockResolvedValueOnce(
        jsonResponse({ conversations: [{ conversation_id: 'conv-2', title: 'Fix' }] })
      )
      .mockResolvedValueOnce(jsonResponse(thread));
    const onNavigate = jest.fn();
    render(<Assistant notify={() => {}} onNavigate={onNavigate} />);
    await waitFor(() => expect(screen.getByText('One proposal.')).toBeInTheDocument());
    expect(screen.getByText('preview · not proposed yet')).toBeInTheDocument();
    fireEvent.click(screen.getByText('CH-svcb-enable_plugin-jwt'));
    fireEvent.click(screen.getByText('Open in Remediation Centre'));
    expect(onNavigate).toHaveBeenCalledWith('centre');
    expect(sessionStorage.getItem('easa.last_assessment')).toBe('asm-2');
  });
});
