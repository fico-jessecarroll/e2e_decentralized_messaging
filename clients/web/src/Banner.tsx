import React, { useState } from 'react';
import { threatModelWarning } from './index';

export default function Banner() {
    const [dismissed, setDismissed] = useState(() => {
        return !!sessionStorage.getItem('bannerDismissed');
    });

    if (dismissed) return null;

    const handleClose = () => {
        sessionStorage.setItem('bannerDismissed', 'true');
        setDismissed(true);
    };

    return (
        <div style={{ background: '#ffdddd', padding: '1rem', position: 'relative' }}>
            <p>{threatModelWarning()}</p>
            <button onClick={handleClose} aria-label="dismiss banner" style={{ position: 'absolute', top: '0.5rem', right: '0.5rem' }}>✕</button>
        </div>
    );
}
