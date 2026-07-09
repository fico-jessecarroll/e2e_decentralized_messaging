/** @vitest-environment jsdom */
import { describe, it, expect, beforeAll, afterEach } from 'vitest';
import { cleanup } from '@testing-library/react';
import * as wasm from '../../../core/bindings/wasm/pkg/index.js';
import { ensureWasmInit } from '../src/wasm_init';

afterEach(() => {
    cleanup();
});

beforeAll(async () => {
    await ensureWasmInit();
});

async function genPublicBytes(): Promise<Uint8Array> {
    return wasm.generate_identity().public_bytes();
}

describe('DeviceLinking component', () => {
    it('renders the initial mode-selection screen', async () => {
        const { render, screen, waitFor } = await import('@testing-library/react');
        const { DeviceLinking } = await import('../src/DeviceLinking.tsx');
        const key = await genPublicBytes();
        render(<DeviceLinking localIdentityKey={key} />);

        await waitFor(() => {
            expect(screen.getByText('Show QR code (this device)')).toBeTruthy();
            expect(screen.getByText('Enter linking code (from other device)')).toBeTruthy();
        });
    });

    it('displays a QR code when "Show QR code" is clicked', async () => {
        const { render, screen, waitFor, fireEvent } = await import('@testing-library/react');
        const { DeviceLinking } = await import('../src/DeviceLinking.tsx');
        const key = await genPublicBytes();
        render(<DeviceLinking localIdentityKey={key} />);

        await waitFor(() => screen.getByText('Show QR code (this device)'));
        fireEvent.click(screen.getByText('Show QR code (this device)'));

        await waitFor(() => {
            expect(screen.getByRole('img', { name: 'Device linking QR code' })).toBeTruthy();
        });
    });

    it('shows the safety-number confirmation step after entering a valid linking code', async () => {
        const { render, screen, waitFor, fireEvent } = await import('@testing-library/react');
        const { DeviceLinking } = await import('../src/DeviceLinking.tsx');
        const { encodeLinkingPayload } = await import('../src/device_linking');

        const primaryKey = await genPublicBytes();
        const newDeviceKey = await genPublicBytes();
        const payload = encodeLinkingPayload(newDeviceKey);

        render(<DeviceLinking localIdentityKey={primaryKey} />);

        await waitFor(() => screen.getByText('Enter linking code (from other device)'));
        fireEvent.click(screen.getByText('Enter linking code (from other device)'));

        const input = screen.getByLabelText('Linking code input');
        fireEvent.change(input, { target: { value: payload } });
        fireEvent.click(screen.getByText('Continue'));

        await waitFor(() => {
            expect(screen.getByTestId('displayed-safety-number')).toBeTruthy();
        });
    });

    it('aborts on mismatched safety number (fail closed)', async () => {
        const { render, screen, waitFor, fireEvent } = await import('@testing-library/react');
        const { DeviceLinking } = await import('../src/DeviceLinking.tsx');
        const { encodeLinkingPayload } = await import('../src/device_linking');

        const primaryKey = await genPublicBytes();
        const newDeviceKey = await genPublicBytes();
        const payload = encodeLinkingPayload(newDeviceKey);

        render(<DeviceLinking localIdentityKey={primaryKey} />);

        // Enter linking code
        await waitFor(() => screen.getByText('Enter linking code (from other device)'));
        fireEvent.click(screen.getByText('Enter linking code (from other device)'));
        fireEvent.change(screen.getByLabelText('Linking code input'), { target: { value: payload } });
        fireEvent.click(screen.getByText('Continue'));

        // Wait for confirmation step
        await waitFor(() => screen.getByTestId('displayed-safety-number'));

        // Enter a WRONG safety number
        fireEvent.change(screen.getByLabelText('Safety number confirmation input'), {
            target: { value: 'wrong-number' },
        });
        fireEvent.click(screen.getByText('Confirm and Link'));

        // Must abort, not link
        await waitFor(() => {
            expect(screen.getByRole('alert')).toBeTruthy();
            expect(screen.getByText(/Linking aborted/)).toBeTruthy();
        });
    });

    it('completes the link when the safety number matches', async () => {
        const { render, screen, waitFor, fireEvent } = await import('@testing-library/react');
        const { DeviceLinking } = await import('../src/DeviceLinking.tsx');
        const { encodeLinkingPayload } = await import('../src/device_linking');

        const primaryKey = await genPublicBytes();
        const newDeviceKey = await genPublicBytes();
        const payload = encodeLinkingPayload(newDeviceKey);
        const expectedSn = wasm.derive_safety_number(primaryKey, newDeviceKey);

        render(<DeviceLinking localIdentityKey={primaryKey} />);

        // Enter linking code
        await waitFor(() => screen.getByText('Enter linking code (from other device)'));
        fireEvent.click(screen.getByText('Enter linking code (from other device)'));
        fireEvent.change(screen.getByLabelText('Linking code input'), { target: { value: payload } });
        fireEvent.click(screen.getByText('Continue'));

        // Wait for confirmation step
        await waitFor(() => screen.getByTestId('displayed-safety-number'));

        // Enter the CORRECT safety number
        fireEvent.change(screen.getByLabelText('Safety number confirmation input'), {
            target: { value: expectedSn },
        });
        fireEvent.click(screen.getByText('Confirm and Link'));

        // Must link successfully
        await waitFor(() => {
            expect(screen.getByText('Device linked successfully!')).toBeTruthy();
        });
    });

    it('aborts on malformed linking code (fail closed)', async () => {
        const { render, screen, waitFor, fireEvent } = await import('@testing-library/react');
        const { DeviceLinking } = await import('../src/DeviceLinking.tsx');

        const primaryKey = await genPublicBytes();

        render(<DeviceLinking localIdentityKey={primaryKey} />);

        await waitFor(() => screen.getByText('Enter linking code (from other device)'));
        fireEvent.click(screen.getByText('Enter linking code (from other device)'));
        fireEvent.change(screen.getByLabelText('Linking code input'), {
            target: { value: 'not-valid-hex-zzz' },
        });
        fireEvent.click(screen.getByText('Continue'));

        await waitFor(() => {
            expect(screen.getByRole('alert')).toBeTruthy();
            expect(screen.getByText(/Linking aborted/)).toBeTruthy();
        });
    });
});