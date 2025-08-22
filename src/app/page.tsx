import Link from 'next/link';

export default function Page() {
  return (
    <main className="p-4 space-y-4">
      <h1 className="text-2xl font-bold">Hello, Next.js!</h1>
      <Link href="/tracker" className="text-blue-600 underline">Открыть Yandex Tracker</Link>
    </main>
  );
}
