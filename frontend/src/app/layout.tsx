export const metadata = {
  title: 'Vigilant Guardian',
  description: 'AI-Powered Zero-Day Vulnerability Intelligence',
}

export default function RootLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  )
}
