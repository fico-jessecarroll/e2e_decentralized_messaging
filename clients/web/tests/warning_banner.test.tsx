// @vitest-environment jsdom
import '@testing-library/jest-dom';
import { render, screen } from '@testing-library/react';
import WarningBanner from '../src/WarningBanner';

describe('WarningBanner', () => {
    beforeEach(() => {
        localStorage.clear();
    });

    test('does not render when no session_active flag', () => {
        render(<WarningBanner />);
        expect(screen.queryByTestId('reload-warning')).toBeNull();
    });

    test('renders warning when session_active flag is true', () => {
        localStorage.setItem('session_active', 'true');
        render(<WarningBanner />);
        const banner = screen.getByTestId('reload-warning');
        expect(banner).toBeInTheDocument();
        expect(banner).toHaveTextContent(/Reloading this page will lose your active session/);
    });
});