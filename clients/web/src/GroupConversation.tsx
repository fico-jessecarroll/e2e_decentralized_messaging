import React from 'react';

export interface GroupMessage {
    id: string;
    body: string;
    timestamp: number;
    sentByMe: boolean;
}

export const GroupConversation: React.FC = () => {
    return <div>Group Conversation UI placeholder</div>;
};
