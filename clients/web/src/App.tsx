import React from 'react';
import Banner from './Banner';
import { Conversation } from './Conversation';

export default function App() {
    return (
        <>
            <Banner />
            <Conversation /><SafetyNumberVerification localIdentityKey={new Uint8Array(32)} remoteIdentityKey={new Uint8Array(32)} conversationId="demo" />
        </>
    );
}
