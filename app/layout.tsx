import './globals.css';
import type { Metadata } from 'next';

export const metadata: Metadata = {
  title: 'Sensitive Data Detector',
  description: 'Detect and redact likely sensitive information from user text.'
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
