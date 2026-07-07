import '@testing-library/jest-dom';
import { render, screen, fireEvent } from '@testing-library/react';

describe('Banner component', () => {
    beforeEach(() => {
        // Clear sessionStorage before each test to simulate fresh session
        sessionStorage.clear();
    });

    test('renders warning text and dismiss button on first load', () => {
        render(<Banner />);
        const banner = screen.getByTestId('banner');
        expect(banner).toBeInTheDocument();
        expect(screen.getByText(/reduced threat model/i)).toBeInTheDocument();
        const dismissBtn = screen.getByRole('button', { name: /dismiss/i });
        expect(dismissBtn).toBeInTheDocument();
    });

    test('clicking dismiss hides the banner and sets sessionStorage flag', () => {
        render(<Banner />);
        const dismissBtn = screen.getByRole('button', { name: /dismiss/i });
        fireEvent.click(dismissBtn);
        expect(screen.queryByTestId('banner')).not.toBeInTheDocument();
        expect(sessionStorage.getItem('reducedThreatModelDismissed')).toBe('true');
    });

    test('banner reappears on a fresh session after dismissal', () => {
        // First render and dismiss
        const { unmount } = render(<Banner />);
        fireEvent.click(screen.getByRole('button', { name: /dismiss/i }));
        expect(screen.queryByTestId('banner')).not.toBeInTheDocument();
        // Simulate a new session by clearing storage and re-mounting
        sessionStorage.clear();
        unmount();
        render(<Banner />);
        expect(screen.getByTestId('banner')).toBeInTheDocument();
    });
});
