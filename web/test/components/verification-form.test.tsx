// @vitest-environment happy-dom
import { act } from "react";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { VerificationForm } from "@/components/verification-form";
import { render, fill, pasteCode } from "../dom";

const confirm = vi.hoisted(() => vi.fn());
vi.mock("@/lib/api", () => ({ api: { confirmVerificationCode: confirm } }));
beforeEach(() => {
  vi.useFakeTimers();
  confirm.mockReset();
});
afterEach(() => {
  vi.useRealTimers();
});

it("ignores incomplete and nonnumeric input and submits a complete code only once", async () => {
  let resolve!: (value: { verification_token: string }) => void;
  confirm.mockReturnValue(
    new Promise((r) => {
      resolve = r;
    }),
  );
  const onVerified = vi.fn();
  const view = render(
    <VerificationForm
      email="alice@example.test"
      purpose="recovery"
      onVerified={onVerified}
      onResend={vi.fn()}
    />,
  );
  try {
    await fill(view.container, "input", "x");
    expect(view.container.querySelector("input")!.value).toBe("");
    await pasteCode(view.container, "123");
    expect(confirm).not.toHaveBeenCalled();
    await pasteCode(view.container, "01 23-45");
    // A second event while the request is pending must not spend another attempt.
    await pasteCode(view.container, "012345");
    expect(confirm).toHaveBeenCalledExactlyOnceWith("alice@example.test", "012345", "recovery");
    expect(onVerified).not.toHaveBeenCalled();
    await act(async () => {
      resolve({ verification_token: "verified" });
    });
    await act(async () => {
      await vi.advanceTimersByTimeAsync(1750);
    });
    expect(onVerified).toHaveBeenCalledExactlyOnceWith("verified");
  } finally {
    view.cleanup();
  }
});

it("clears a rejected code and permits a fresh attempt", async () => {
  confirm
    .mockRejectedValueOnce(new Error("invalid code"))
    .mockResolvedValueOnce({ verification_token: "verified" });
  const onVerified = vi.fn();
  const view = render(
    <VerificationForm
      email="alice@example.test"
      purpose="registration"
      onVerified={onVerified}
      onResend={vi.fn()}
    />,
  );
  try {
    await pasteCode(view.container, "123456");
    await act(async () => {
      await vi.advanceTimersByTimeAsync(500);
    });
    expect(view.container.querySelector('[role="alert"]')!.textContent).toContain("Invalid code");
    expect(
      [...view.container.querySelectorAll("input")].every(
        (input) => input.value === "" && !input.disabled,
      ),
    ).toBe(true);
    expect(onVerified).not.toHaveBeenCalled();
    await pasteCode(view.container, "654321");
    await act(async () => {
      await vi.advanceTimersByTimeAsync(1750);
    });
    expect(confirm).toHaveBeenCalledTimes(2);
    expect(onVerified).toHaveBeenCalledExactlyOnceWith("verified");
  } finally {
    view.cleanup();
  }
});

it("applies resend cooldown only after a successful send", async () => {
  const resend = vi
    .fn()
    .mockRejectedValueOnce(new Error("network unavailable"))
    .mockResolvedValue(undefined);
  const view = render(
    <VerificationForm
      email="alice@example.test"
      purpose="registration"
      onVerified={vi.fn()}
      onResend={resend}
    />,
  );
  try {
    const button = [...view.container.querySelectorAll("button")].find(
      (b) => b.textContent === "Resend code",
    )!;
    await act(async () => button.click());
    expect(button.disabled).toBe(false);
    expect(view.container.querySelector('[role="alert"]')!.textContent).toContain(
      "Network unavailable",
    );
    await act(async () => button.click());
    expect(button.disabled).toBe(true);
    await act(async () => button.click());
    expect(resend).toHaveBeenCalledTimes(2);
    for (let i = 0; i < 60; i++) {
      await act(async () => {
        await vi.advanceTimersByTimeAsync(1000);
      });
    }
    expect(button.disabled).toBe(false);
    await act(async () => button.click());
    expect(resend).toHaveBeenCalledTimes(3);
  } finally {
    view.cleanup();
  }
});
