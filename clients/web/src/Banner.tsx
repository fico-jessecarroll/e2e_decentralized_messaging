import React, { useState } from 'react';
import { threatModelWarning } from './index';

const STORAGE_KEY = 'reducedThreatModelDismissed';

export default function Banner() {
    const [dismissed, setDismissed] = useState(() => {
        try {
            return sessionStorage.getItem(STORAGE_KEY) === 'true';
        } catch (_) {
            return false;
        }
    });

    if (dismissed) return null;

    const handleDismiss = () => {
        try {
            sessionStorage.setItem(STORAGE_KEY, 'true');
        } catch (_) {}
        setDismissed(true);
    };

    return (
        <div style={{ backgroundColor: '#ffdddd', padding: '1rem' }} data-testid="banner">
            <p>{threatModelWarning()}</p>
            <button onClick={handleDismiss}>Dismiss</button>
        </div>
    );
}
