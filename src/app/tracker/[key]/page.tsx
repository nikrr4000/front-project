'use client';

import { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';

export default function IssuePage({ params }: { params: { key: string } }) {
  const { key } = params;
  const router = useRouter();
  const [summary, setSummary] = useState('');
  const [description, setDescription] = useState('');
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const load = async () => {
      const res = await fetch(`/api/tracker/issues/${key}`);
      const data = await res.json();
      if (res.ok) {
        setSummary(data.summary || '');
        setDescription(data.description || '');
      } else {
        alert(data.error || 'Error');
      }
      setLoading(false);
    };
    load();
  }, [key]);

  const save = async () => {
    const res = await fetch(`/api/tracker/issues/${key}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ summary, description }),
    });
    const data = await res.json();
    if (res.ok) {
      alert('Сохранено');
    } else {
      alert(data.error || 'Error');
    }
  };

  const remove = async () => {
    if (!confirm('Удалить задачу?')) return;
    const res = await fetch(`/api/tracker/issues/${key}`, { method: 'DELETE' });
    if (res.ok) {
      alert('Удалено');
      router.push('/tracker');
    } else {
      const data = await res.json();
      alert(data.error || 'Error');
    }
  };

  if (loading) return <div className="p-4">Загрузка...</div>;

  return (
    <div className="p-4 space-y-4">
      <h1 className="text-2xl font-bold">Задача {key}</h1>
      <div className="flex flex-col gap-2 max-w-lg">
        <input className="border p-1" value={summary} onChange={e => setSummary(e.target.value)} />
        <textarea className="border p-1" value={description} onChange={e => setDescription(e.target.value)} />
        <div className="flex gap-2">
          <button className="bg-blue-600 text-white px-3 py-1" onClick={save}>Сохранить</button>
          <button className="bg-red-600 text-white px-3 py-1" onClick={remove}>Удалить</button>
        </div>
      </div>
    </div>
  );
}

