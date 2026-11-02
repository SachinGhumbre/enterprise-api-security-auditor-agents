import '@testing-library/jest-dom';

import React, { useState } from 'react';
import { fireEvent, render, screen } from '@testing-library/react';

import { MultiSelect } from './ui';

const OPTIONS = ['GDPR', 'HIPAA', 'PCI-DSS'];

function Harness({ options = OPTIONS, initial = [] }) {
  const [selected, setSelected] = useState(initial);
  return (
    <MultiSelect
      options={options}
      selected={selected}
      onChange={setSelected}
      placeholder="Select standards…"
      ariaLabel="Standards in scope"
    />
  );
}

describe('MultiSelect', () => {
  test('shows placeholder, opens, and toggles one option', () => {
    render(<Harness />);
    const button = screen.getByRole('button', { name: 'Standards in scope' });
    expect(button).toHaveTextContent('Select standards…');
    fireEvent.click(button);
    const gdpr = screen.getByRole('checkbox', { name: 'GDPR' });
    fireEvent.click(gdpr);
    expect(button).toHaveTextContent('GDPR');
    // Toggle off again.
    fireEvent.click(gdpr);
    expect(button).toHaveTextContent('Select standards…');
  });

  test('counts multiple selections and clears all', () => {
    render(<Harness />);
    const button = screen.getByRole('button', { name: 'Standards in scope' });
    fireEvent.click(button);
    fireEvent.click(screen.getByText('Select all'));
    expect(button).toHaveTextContent('3 selected');
    fireEvent.click(screen.getByText('Clear all'));
    expect(button).toHaveTextContent('Select standards…');
  });

  test('shows empty hint when there are no options', () => {
    render(<Harness options={[]} />);
    fireEvent.click(screen.getByRole('button', { name: 'Standards in scope' }));
    expect(screen.getByText('No options available.')).toBeInTheDocument();
  });

  test('closes on Escape', () => {
    render(<Harness />);
    fireEvent.click(screen.getByRole('button', { name: 'Standards in scope' }));
    expect(screen.getByText('Select all')).toBeInTheDocument();
    fireEvent.keyDown(document, { key: 'Escape' });
    expect(screen.queryByText('Select all')).not.toBeInTheDocument();
  });
});
