// @vitest-environment happy-dom
import { MemoryRouter } from "react-router-dom";
import { expect, it, vi } from "vitest";
import { AuthForm } from "@/components/auth-form";
import { render, fill, submit } from "../dom";

it.each(["password", "short", "tangle-jupiter-cobalt-whisper-726!"])(
  "submits an existing login password regardless of signup strength: %s",
  async (password) => {
    const onSubmit = vi.fn().mockResolvedValue(undefined);
    const view = render(
      <MemoryRouter>
        <AuthForm mode="login" onSubmit={onSubmit} />
      </MemoryRouter>,
    );
    try {
      await fill(view.container, "#username", "Alice");
      await fill(view.container, "#password", password);
      await submit(view.container);
      expect(onSubmit).toHaveBeenCalledExactlyOnceWith("alice", "", password);
    } finally {
      view.cleanup();
    }
  },
);

it.each([
  ["password", "password"],
  ["tangle-jupiter-cobalt-whisper-726!", "different-password"],
  ["", ""],
])(
  "rejects invalid signup passwords even on direct form submission",
  async (password, confirmation) => {
    const onSubmit = vi.fn();
    const view = render(
      <MemoryRouter>
        <AuthForm
          mode="signup"
          defaultUsername="alice"
          defaultEmail="alice@example.test"
          onSubmit={onSubmit}
        />
      </MemoryRouter>,
    );
    try {
      await fill(view.container, "#password", password);
      await fill(view.container, "#confirmPassword", confirmation);
      expect(
        view.container.querySelector<HTMLButtonElement>('button[type="submit"]')!.disabled,
      ).toBe(true);
      await submit(view.container);
      expect(onSubmit).not.toHaveBeenCalled();
    } finally {
      view.cleanup();
    }
  },
);

it("shows server failures and allows retry", async () => {
  const onSubmit = vi
    .fn()
    .mockRejectedValueOnce(new Error("invalid credentials"))
    .mockResolvedValueOnce(undefined);
  const view = render(
    <MemoryRouter>
      <AuthForm mode="login" defaultUsername="alice" onSubmit={onSubmit} />
    </MemoryRouter>,
  );
  try {
    await fill(view.container, "#password", "tangle-jupiter-cobalt-whisper-726!");
    await submit(view.container);
    expect(view.container.querySelector('[role="alert"]')!.textContent).toContain(
      "Invalid credentials",
    );
    expect(view.container.querySelector<HTMLButtonElement>('button[type="submit"]')!.disabled).toBe(
      false,
    );
    await submit(view.container);
    expect(onSubmit).toHaveBeenCalledTimes(2);
    expect(view.container.querySelector('[role="alert"]')).toBeNull();
  } finally {
    view.cleanup();
  }
});
