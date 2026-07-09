import React, { useState } from 'react';
import { threatModelWarning } from './api';
import './Banner.css';

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
        <div className="advisory" data-testid="banner">
            <span className="advisory-mark" aria-hidden="true">ADVISORY</span>
            <p className="advisory-text">{threatModelWarning()}</p>
            <button className="advisory-dismiss" onClick={handleDismiss}>Dismiss</button>
        </div>
    );
}
