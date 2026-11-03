import '@testing-library/jest-dom';

import React from 'react';
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';

import App from './App';
import { setApiKey } from './api/client';

process.env.REACT_APP_OPERATOR_PASSWORD = 'Operator@123';
process.env.REACT_APP_OPERATOR_KEY = 'op-test';

function jsonResponse(body) {
  return { ok: true, status: 200, text: async () => JSON.stringify(body) };
}

function mockFetch() {
  return jest.fn(async (url) => {
    const target = String(url);
    if (target.includes('/llm/calls')) return { ok: true, status: 200 };
    if (target.endsWith('/assistant/prompts')) return jsonResponse({ prompts: [] });
    if (target.includes('/assistant/conversations')) {
      return jsonResponse({ conversations: [] });
    }
    throw new TypeError('service down');
  });
}

async function signIn() {
  fireEvent.change(screen.getByLabelText('Username'), { target: { value: 'operator' } });
  fireEvent.change(screen.getByLabelText('Password'), { target: { value: 'Operator@123' } });
  fireEvent.click(screen.getByRole('button', { name: 'Sign in' }));
  await waitFor(() =>
    expect(screen.getByRole('button', { name: 'Open assistant' })).toBeInTheDocument()
  );
}

describe('App assistant widget', () => {
  beforeEach(() => {
    sessionStorage.clear();
    setApiKey('');
    global.fetch = mockFetch();
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  test('assistant lives in a bottom-right floating button, not the sidebar', async () => {
    render(<App />);
    await signIn();

    const toggle = screen.getByRole('button', { name: 'Open assistant' });
    expect(toggle).toHaveClass('fixed', 'bottom-6', 'right-4');
    expect(
      screen.queryByRole('dialog', { name: 'AI Security Assistant' })
    ).not.toBeInTheDocument();

    const nav = screen.getByRole('navigation');
    expect(within(nav).queryByText(/assistant/i)).not.toBeInTheDocument();
  });

  test('floating button opens and closes the compact assistant dialog', async () => {
    render(<App />);
    await signIn();

    fireEvent.click(screen.getByRole('button', { name: 'Open assistant' }));
    const dialog = await waitFor(() =>
      screen.getByRole('dialog', { name: 'AI Security Assistant' })
    );
    expect(dialog).toHaveClass('fixed', 'bottom-24', 'right-4');
    await waitFor(() =>
      expect(screen.getByText(/Ask about your API security posture/)).toBeInTheDocument()
    );

    const closeButtons = screen.getAllByRole('button', { name: 'Close assistant' });
    fireEvent.click(closeButtons[0]);
    await waitFor(() =>
      expect(
        screen.queryByRole('dialog', { name: 'AI Security Assistant' })
      ).not.toBeInTheDocument()
    );
    expect(screen.getByRole('button', { name: 'Open assistant' })).toBeInTheDocument();
  });
});
