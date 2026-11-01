import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it } from "vitest";
import { Heatmap, shadeLevel } from "../pages/AttackPage";

describe("heatmap", () => {
  it("buckets counts relative to the max", () => {
    expect(shadeLevel(0, 10)).toBe(0);
    expect(shadeLevel(1, 10)).toBe(1);
    expect(shadeLevel(3, 10)).toBe(2);
    expect(shadeLevel(6, 10)).toBe(3);
    expect(shadeLevel(10, 10)).toBe(4);
    expect(shadeLevel(5, 0)).toBe(0);
  });

  it("shades cells and links to filtered alerts", () => {
    render(
      <MemoryRouter>
        <Heatmap
          data={{
            tactics: [
              {
                tactic: "Credential Access",
                techniques: [
                  { id: "T1110", name: "Brute Force", alerts: 10, max_severity: "high" },
                  { id: "T1078", name: "Valid Accounts", alerts: 1, max_severity: "low" },
                ],
              },
            ],
          }}
        />
      </MemoryRouter>,
    );
    const hot = screen.getByRole("link", { name: /T1110/ });
    const cool = screen.getByRole("link", { name: /T1078/ });
    expect(hot).toHaveAttribute("data-level", "4");
    expect(cool).toHaveAttribute("data-level", "1");
    expect(hot).toHaveAttribute("href", "/alerts?technique=T1110");
  });
});
