'use client';

import { useState } from 'react';
import Link from 'next/link';

export default function TrackerPage() {
  const [queue, setQueue] = useState('');
  const [query, setQuery] = useState('');
  const [issues, setIssues] = useState<any[]>([]);
  const [createQueue, setCreateQueue] = useState('');
  const [summary, setSummary] = useState('');
  const [description, setDescription] = useState('');
  const [searchLoading, setSearchLoading] = useState(false);
  const [searchError, setSearchError] = useState('');
  const [createLoading, setCreateLoading] = useState(false);
  const [createError, setCreateError] = useState('');
  const [createMessage, setCreateMessage] = useState('');

  const searchIssues = async () => {
    setSearchLoading(true);
    setSearchError('');
    const params = new URLSearchParams();
    if (queue) params.set('queue', queue);
    if (query) params.set('query', query);
    try {
      const res = await fetch(`/api/tracker/issues?${params.toString()}`);
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || 'Error');
      }
      const items = Array.isArray(data) ? data : (data.issues || data.items || data.data || []);
      setIssues(items);
    } catch (e: any) {
      setSearchError(e.message);
    } finally {
      setSearchLoading(false);
    }
  };

  const createIssue = async () => {
    setCreateLoading(true);
    setCreateError('');
    setCreateMessage('');
    try {
      const res = await fetch('/api/tracker/issues', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ queue: createQueue, summary, description }),
      });
      const data = await res.json();
      if (res.ok) {
        setCreateMessage(`Создана задача ${data.key || data.id}`);
      } else {
        throw new Error(data.error || 'Error');
      }
    } catch (e: any) {
      setCreateError(e.message);
    } finally {
      setCreateLoading(false);
    }
  };

  return (
    <div className="p-4 space-y-6">
      <h1 className="text-2xl font-bold">Yandex Tracker</h1>

      <section className="space-y-2">
        <h2 className="font-semibold">Поиск задач</h2>
        <div className="flex flex-wrap gap-2">
          <input className="border p-1" placeholder="Очередь" value={queue} onChange={e => setQueue(e.target.value)} />
          <input className="border p-1" placeholder="Запрос" value={query} onChange={e => setQuery(e.target.value)} />
          <button disabled={searchLoading} className="bg-blue-600 text-white px-3 py-1 disabled:opacity-50" onClick={searchIssues}>
            {searchLoading ? <span className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin" /> : 'Искать'}
          </button>
        </div>
        {searchError && <div className="text-red-600">{searchError}</div>}
        <ul className="list-disc pl-5">
          {issues.map((it: any) => (
            <li key={it.id || it.key}>
              <Link href={`/tracker/${it.key}`} className="text-blue-600 underline">
                {it.key}: {it.summary}
              </Link>
            </li>
          ))}
        </ul>
      </section>

      <section className="space-y-2">
        <h2 className="font-semibold">Создать задачу</h2>
        <div className="flex flex-col gap-2 max-w-md">
          <input className="border p-1" placeholder="Очередь" value={createQueue} onChange={e => setCreateQueue(e.target.value)} />
          <input className="border p-1" placeholder="Заголовок" value={summary} onChange={e => setSummary(e.target.value)} />
          <textarea className="border p-1" placeholder="Описание" value={description} onChange={e => setDescription(e.target.value)} />
          <button disabled={createLoading} className="bg-green-600 text-white px-3 py-1 disabled:opacity-50" onClick={createIssue}>
            {createLoading ? <span className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin" /> : 'Создать'}
          </button>
        </div>
        {createError && <div className="text-red-600">{createError}</div>}
        {createMessage && <div className="text-green-600">{createMessage}</div>}
      </section>
    </div>
  );
}

