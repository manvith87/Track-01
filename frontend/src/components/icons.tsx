/** Minimal inline icon set (no icon dependency). All icons are decorative. */

import type { SVGProps } from "react";

type IconProps = SVGProps<SVGSVGElement>;

function Base({ children, ...props }: IconProps) {
  return (
    <svg
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={1.8}
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      focusable="false"
      width={18}
      height={18}
      {...props}
    >
      {children}
    </svg>
  );
}

export function ShieldIcon(props: IconProps) {
  return (
    <Base {...props}>
      <path d="M12 3l7 3v5c0 4.5-3 8.2-7 10-4-1.8-7-5.5-7-10V6l7-3z" />
      <path d="M9.5 12l2 2 3.5-4" />
    </Base>
  );
}

export function RepositoryIcon(props: IconProps) {
  return (
    <Base {...props}>
      <path d="M4 7a2 2 0 0 1 2-2h12a2 2 0 0 1 2 2v10a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V7z" />
      <path d="M8 5v14" />
      <path d="M12 9h5M12 13h5" />
    </Base>
  );
}

export function FindingsIcon(props: IconProps) {
  return (
    <Base {...props}>
      <path d="M12 4l8 14H4l8-14z" />
      <path d="M12 10v4" />
      <path d="M12 16.5h.01" />
    </Base>
  );
}

export function GraphIcon(props: IconProps) {
  return (
    <Base {...props}>
      <circle cx="6" cy="6" r="2.5" />
      <circle cx="18" cy="8" r="2.5" />
      <circle cx="10" cy="18" r="2.5" />
      <path d="M8.3 7.2l7.4.6M7 8.4l2 7.2M16.4 10.2l-4.2 6" />
    </Base>
  );
}

export function AnalystIcon(props: IconProps) {
  return (
    <Base {...props}>
      <path d="M4 5h16v10H9l-4 4v-4H4V5z" />
      <path d="M8 9h8M8 12h5" />
    </Base>
  );
}

export function RemediationIcon(props: IconProps) {
  return (
    <Base {...props}>
      <path d="M6 4h12v5H6z" />
      <path d="M9 9v4" />
      <path d="M12 9v6" />
      <path d="M6 20h12" />
      <path d="M15 9v4" />
    </Base>
  );
}

export function IssueIcon(props: IconProps) {
  return (
    <Base {...props}>
      <circle cx="12" cy="12" r="8.5" />
      <path d="M12 8v.01M12 11v5" />
    </Base>
  );
}

export function RefreshIcon(props: IconProps) {
  return (
    <Base {...props}>
      <path d="M20 11a8 8 0 1 0-2.3 5.7" />
      <path d="M20 5v6h-6" />
    </Base>
  );
}

export function ChevronDownIcon(props: IconProps) {
  return (
    <Base {...props}>
      <path d="M6 9l6 6 6-6" />
    </Base>
  );
}

export function ChevronRightIcon(props: IconProps) {
  return (
    <Base {...props}>
      <path d="M9 6l6 6-6 6" />
    </Base>
  );
}

export function CheckIcon(props: IconProps) {
  return (
    <Base {...props}>
      <path d="M5 13l4 4L19 7" />
    </Base>
  );
}

export function XIcon(props: IconProps) {
  return (
    <Base {...props}>
      <path d="M6 6l12 12M18 6L6 18" />
    </Base>
  );
}

export function WarningIcon(props: IconProps) {
  return (
    <Base {...props}>
      <path d="M12 4l8 14H4l8-14z" />
      <path d="M12 10v4M12 16.5h.01" />
    </Base>
  );
}

export function InfoIcon(props: IconProps) {
  return (
    <Base {...props}>
      <circle cx="12" cy="12" r="8.5" />
      <path d="M12 11v5M12 8h.01" />
    </Base>
  );
}

export function SpinnerIcon(props: IconProps) {
  return (
    <Base {...props} className={`animate-spin ${props.className ?? ""}`}>
      <path d="M12 3a9 9 0 1 0 9 9" />
    </Base>
  );
}

export function CopyIcon(props: IconProps) {
  return (
    <Base {...props}>
      <path d="M9 9h10v10H9z" />
      <path d="M5 15V5h10" />
    </Base>
  );
}

export function SearchIcon(props: IconProps) {
  return (
    <Base {...props}>
      <circle cx="11" cy="11" r="6" />
      <path d="M20 20l-3.5-3.5" />
    </Base>
  );
}

export function ArrowLeftIcon(props: IconProps) {
  return (
    <Base {...props}>
      <path d="M19 12H5" />
      <path d="M11 6l-6 6 6 6" />
    </Base>
  );
}

export function LinkIcon(props: IconProps) {
  return (
    <Base {...props}>
      <path d="M10 14a4 4 0 0 0 5.7 0l3-3a4 4 0 1 0-5.7-5.7L11.5 7" />
      <path d="M14 10a4 4 0 0 0-5.7 0l-3 3a4 4 0 1 0 5.7 5.7l1.5-1.5" />
    </Base>
  );
}

export function LockIcon(props: IconProps) {
  return (
    <Base {...props}>
      <path d="M6 11h12v9H6z" />
      <path d="M9 11V8a3 3 0 0 1 6 0v3" />
    </Base>
  );
}
