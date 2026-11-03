import '@testing-library/jest-dom';

import React from 'react';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';

import { setApiKey } from '../api/client';
import Login from './Login';

process.env.REACT_APP_ADMIN_PASSWORD = 'Admin@123';
process.env.REACT_APP_ADMIN_KEY = 'adm-test';
process.env.REACT_APP_OPERATOR_PASSWORD = 'Operator@123';
process.env.REACT_APP_OPERATOR_KEY = '';
process.env.REACT_APP_VIEWER_PASSWORD = 'Viewer@123';
process.env.REACT_APP_VIEWER_KEY = 'view-test';

describe('Login', () => {
  beforeEach(() => {
    sessionStorage.clear();
    setApiKey('');
    global.fetch = jest.fn();
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  test('demo credentials are shown on the page', () => {
    render(<Login onLogin={() => {}} />);
    expect(screen.getByText('Demo credentials')).toBeInTheDocument();
    expect(screen.getByText('Admin@123')).toBeInTheDocument();
  });

  test('correct password signs in with the mapped role key', async () => {
    global.fetch.mockResolvedValueOnce({ ok: true, status: 200 });
    const onLogin = jest.fn();
    render(<Login onLogin={onLogin} />);
    fireEvent.change(screen.getByLabelText('Username'), { target: { value: 'admin' } });
    fireEvent.change(screen.getByLabelText('Password'), { target: { value: 'Admin@123' } });
    fireEvent.click(screen.getByRole('button', { name: 'Sign in' }));
    await waitFor(() => expect(onLogin).toHaveBeenCalledWith('admin'));
    expect(global.fetch.mock.calls[0][1].headers).toEqual({ 'X-API-Key': 'adm-test' });
  });

  test('wrong password blocks without any request', () => {
    const onLogin = jest.fn();
    render(<Login onLogin={onLogin} />);
    fireEvent.change(screen.getByLabelText('Password'), { target: { value: 'nope' } });
    fireEvent.click(screen.getByRole('button', { name: 'Sign in' }));
    expect(screen.getByRole('alert')).toHaveTextContent('Incorrect password');
    expect(global.fetch).not.toHaveBeenCalled();
    expect(onLogin).not.toHaveBeenCalled();
  });

  test('password with surrounding whitespace in .env still signs in', async () => {
    const saved = process.env.REACT_APP_ADMIN_PASSWORD;
    process.env.REACT_APP_ADMIN_PASSWORD = '  Admin@123  ';
    try {
      global.fetch.mockResolvedValueOnce({ ok: true, status: 200 });
      const onLogin = jest.fn();
      render(<Login onLogin={onLogin} />);
      fireEvent.change(screen.getByLabelText('Username'), { target: { value: 'admin' } });
      fireEvent.change(screen.getByLabelText('Password'), { target: { value: 'Admin@123' } });
      fireEvent.click(screen.getByRole('button', { name: 'Sign in' }));
      await waitFor(() => expect(onLogin).toHaveBeenCalledWith('admin'));
    } finally {
      process.env.REACT_APP_ADMIN_PASSWORD = saved;
    }
  });

  test('missing passwords show a restart hint on the page', () => {
    const saved = {
      admin: process.env.REACT_APP_ADMIN_PASSWORD,
      operator: process.env.REACT_APP_OPERATOR_PASSWORD,
      viewer: process.env.REACT_APP_VIEWER_PASSWORD,
    };
    delete process.env.REACT_APP_ADMIN_PASSWORD;
    delete process.env.REACT_APP_OPERATOR_PASSWORD;
    delete process.env.REACT_APP_VIEWER_PASSWORD;
    try {
      render(<Login onLogin={() => {}} />);
      expect(screen.getByText(/demo passwords not loaded/i)).toBeInTheDocument();
      expect(screen.getByText(/restart.*npm start/i)).toBeInTheDocument();
    } finally {
      process.env.REACT_APP_ADMIN_PASSWORD = saved.admin;
      process.env.REACT_APP_OPERATOR_PASSWORD = saved.operator;
      process.env.REACT_APP_VIEWER_PASSWORD = saved.viewer;
    }
  });

  test('401 with no role key explains the misconfiguration', async () => {
    global.fetch.mockResolvedValueOnce({ ok: false, status: 401 });
    render(<Login onLogin={() => {}} />);
    // Operator has a password but an empty key in this test env.
    fireEvent.change(screen.getByLabelText('Password'), { target: { value: 'Operator@123' } });
    fireEvent.click(screen.getByRole('button', { name: 'Sign in' }));
    await waitFor(() =>
      expect(screen.getByRole('alert')).toHaveTextContent('No operator key configured')
    );
  });
});
