import React from 'react';

/**
 * Displays a persistent warning that an active session will be lost on page reload.
 * The flag is set by useRelayConnection when a receiver session is established.
 */
export default function WarningBanner() {
    const hasSession = typeof window !== 'undefined' && localStorage.getItem('session_active') === 'true';
    if (!hasSession) return null;
    return (
        <div data-testid="reload-warning" style={{backgroundColor: '#ffdddd', padding: '8px'}}>
            Warning: Reloading this page will lose your active session. Please save any unsent messages before reloading.
        </div>
    );
}
