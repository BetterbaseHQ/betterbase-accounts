// @vitest-environment happy-dom
import { act } from "react";
import { MemoryRouter } from "react-router-dom";
import { expect, it, vi } from "vitest";
import { RecoveryForm } from "@/components/recovery/recovery-form";
import { render, fill, submit } from "../dom";

// BIP39's all-zero entropy vector; exercise real checksum validation.
const phrase =
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

it.each(["", "   ", "not a recovery phrase", Array(12).fill("abandon").join(" ")])(
  "rejects an invalid phrase without submitting: %j",
  async (invalid) => {
    const onSubmit = vi.fn();
    const view = render(
      <MemoryRouter>
        <RecoveryForm defaultEmail="alice@example.test" onSubmit={onSubmit} />
      </MemoryRouter>,
    );
    try {
      await fill(view.container, "#phrase", invalid);
      await submit(view.container);
      expect(onSubmit).not.toHaveBeenCalled();
      expect(view.container.querySelector('[role="alert"]')!.textContent).toContain(
        "Invalid recovery phrase",
      );
      await fill(view.container, "#phrase", phrase);
      expect(view.container.querySelector('[role="alert"]')).toBeNull();
      await submit(view.container);
      expect(onSubmit).toHaveBeenCalledExactlyOnceWith("alice@example.test", phrase);
    } finally {
      view.cleanup();
    }
  },
);

it("requires an email even when the form is submitted directly", async () => {
  const onSubmit = vi.fn();
  const view = render(
    <MemoryRouter>
      <RecoveryForm onSubmit={onSubmit} />
    </MemoryRouter>,
  );
  try {
    await fill(view.container, "#phrase", phrase);
    expect(view.container.querySelector<HTMLButtonElement>('button[type="submit"]')!.disabled).toBe(
      true,
    );
    await submit(view.container);
    expect(view.container.querySelector('[role="alert"]')!.textContent).toContain(
      "Please enter your email address",
    );
    expect(onSubmit).not.toHaveBeenCalled();
    await fill(view.container, "#email", "alice@example.test");
    await submit(view.container);
    expect(onSubmit).toHaveBeenCalledWith("alice@example.test", phrase);
  } finally {
    view.cleanup();
  }
});

it("normalizes case and whitespace and uses the verified read-only email", async () => {
  const onSubmit = vi.fn().mockResolvedValue(undefined);
  const view = render(
    <MemoryRouter>
      <RecoveryForm emailReadOnly defaultEmail="alice@example.test" onSubmit={onSubmit} />
    </MemoryRouter>,
  );
  try {
    expect(view.container.querySelector("#email")).toBeNull();
    expect(view.container.textContent).toContain("Enter Recovery Phrase");
    await fill(view.container, "#phrase", ` \n${phrase.toUpperCase().replaceAll(" ", " \n\t ")}  `);
    await submit(view.container);
    expect(onSubmit).toHaveBeenCalledExactlyOnceWith("alice@example.test", phrase);
  } finally {
    view.cleanup();
  }
});

it.each([new Error("network unavailable"), "unexpected rejection"])(
  "restores controls and permits retry after a failed request",
  async (failure) => {
    let reject!: (reason: unknown) => void;
    const onSubmit = vi
      .fn()
      .mockImplementationOnce(
        () =>
          new Promise((_, rejectRequest) => {
            reject = rejectRequest;
          }),
      )
      .mockResolvedValueOnce(undefined);
    const view = render(
      <MemoryRouter>
        <RecoveryForm defaultEmail="alice@example.test" onSubmit={onSubmit} />
      </MemoryRouter>,
    );
    try {
      await fill(view.container, "#phrase", phrase);
      await submit(view.container);
      const button = view.container.querySelector<HTMLButtonElement>('button[type="submit"]')!;
      expect(button.disabled).toBe(true);
      expect(view.container.querySelector<HTMLInputElement>("#email")!.disabled).toBe(true);
      expect(view.container.querySelector<HTMLTextAreaElement>("#phrase")!.disabled).toBe(true);
      await act(async () => button.click());
      expect(onSubmit).toHaveBeenCalledTimes(1);
      await act(async () => reject(failure));
      expect(view.container.querySelector('[role="alert"]')!.textContent).toContain(
        failure instanceof Error ? "Network unavailable" : "An error occurred",
      );
      expect(button.disabled).toBe(false);
      expect(view.container.querySelector<HTMLInputElement>("#email")!.disabled).toBe(false);
      expect(view.container.querySelector<HTMLTextAreaElement>("#phrase")!.value).toBe(phrase);
      await submit(view.container);
      expect(onSubmit).toHaveBeenCalledTimes(2);
      expect(view.container.querySelector('[role="alert"]')).toBeNull();
    } finally {
      view.cleanup();
    }
  },
);
