// src/__tests__/Popup.test.tsx
import { render, screen } from "@testing-library/react";
import Popup from "../components/Popup";

test("renders popup with correct text", () => {
  render(<Popup />);
  const headerElement = screen.getByText(/My Extension/i);
  expect(headerElement).toBeInTheDocument();
});
