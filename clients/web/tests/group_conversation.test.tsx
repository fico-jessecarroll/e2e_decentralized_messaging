/** @vitest-environment jsdom */
import '@testing-library/jest-dom';
import { describe, test, expect } from 'vitest';
import { render, screen, fireEvent, waitFor, within } from '@testing-library/react';
import { GroupConversation } from '../src/GroupConversation';

describe('GroupConversation', () => {
    test('creates a group, adds members, and sends a message all current members decrypt', async () => {
        render(<GroupConversation />);

        const createBtn = await screen.findByTestId('create-group-button');
        fireEvent.click(createBtn);

        await waitFor(() => expect(screen.getByTestId('member-list')).toBeInTheDocument());

        fireEvent.click(screen.getByTestId('add-Alice'));
        fireEvent.click(screen.getByTestId('add-Bob'));

        // Added members show a Remove button in place of Add.
        expect(screen.getByTestId('remove-Alice')).toBeInTheDocument();
        expect(screen.getByTestId('remove-Bob')).toBeInTheDocument();

        fireEvent.change(screen.getByTestId('group-message-input'), { target: { value: 'hello group' } });
        fireEvent.click(screen.getByTestId('group-send-button'));

        await waitFor(() => expect(screen.getByText('hello group')).toBeInTheDocument());

        // Both added members decrypted the real ciphertext; Eve (never added) did not.
        expect(screen.getByText(/Alice: decrypted/)).toBeInTheDocument();
        expect(screen.getByText(/Bob: decrypted/)).toBeInTheDocument();
        expect(screen.getByText(/Eve: failed/)).toBeInTheDocument();
    });

    test('a removed member cannot decrypt a message sent after their removal', async () => {
        render(<GroupConversation />);

        fireEvent.click(await screen.findByTestId('create-group-button'));
        await waitFor(() => expect(screen.getByTestId('member-list')).toBeInTheDocument());

        fireEvent.click(screen.getByTestId('add-Alice'));
        fireEvent.click(screen.getByTestId('add-Eve'));

        // Eve is a member and can decrypt a message sent while she's still in the group.
        fireEvent.change(screen.getByTestId('group-message-input'), { target: { value: 'eve is still here' } });
        fireEvent.click(screen.getByTestId('group-send-button'));
        await waitFor(() => expect(screen.getByText('eve is still here')).toBeInTheDocument());
        const firstMessage = screen.getByText('eve is still here').closest('div')!;
        expect(within(firstMessage).getByText(/Eve: decrypted/)).toBeInTheDocument();

        // Remove Eve, then send a new message - her removal rotates the sender
        // key (see core/protocol's member_removal_rotation.rs), so this is a
        // real forward-secrecy check, not a simulated one.
        fireEvent.click(screen.getByTestId('remove-Eve'));
        expect(screen.getByTestId('add-Eve')).toBeInTheDocument(); // Add button reappears

        fireEvent.change(screen.getByTestId('group-message-input'), { target: { value: 'eve is gone now' } });
        fireEvent.click(screen.getByTestId('group-send-button'));

        await waitFor(() => expect(screen.getByText('eve is gone now')).toBeInTheDocument());
        const secondMessage = screen.getByText('eve is gone now').closest('div')!;

        // Eve's decrypt attempt against the post-removal message genuinely fails.
        expect(within(secondMessage).getByText(/Eve: failed/)).toBeInTheDocument();
        // Alice, still a member, still decrypts it fine.
        expect(within(secondMessage).getByText(/Alice: decrypted/)).toBeInTheDocument();
    });
});
