import React, { useCallback, useEffect, useState } from 'react';
import { Database, FileText, Layers, Search, Trash2, UploadCloud } from 'lucide-react';

import { knowledge } from '../api/client';
import { Banner, Card, Collapsible, EmptyState, Spinner, StatTile } from '../components/ui';

const SAMPLE_QUERIES = [
  'Which plugin enforces authentication on a Kong service?',
  'rate limiting thresholds',
  'GDPR data privacy requirements',
  'input validation rules for request bodies',
];

export default function KnowledgeBase({ notify }) {
  const [stats, setStats] = useState(null);
  const [busy, setBusy] = useState('');
  const [ingestResult, setIngestResult] = useState(null);
  const [chunks, setChunks] = useState([]);
  const [query, setQuery] = useState(SAMPLE_QUERIES[0]);
  const [results, setResults] = useState(null);
  const [error, setError] = useState(null);

  const refreshStats = useCallback(async () => {
    try {
      setStats(await knowledge.stats());
    } catch (err) {
      setError(err.message);
    }
  }, []);

  useEffect(() => {
    refreshStats();
  }, [refreshStats]);

  const handleIngest = async () => {
    setBusy('ingest');
    setError(null);
    setIngestResult(null);
    try {
      const data = await knowledge.ingest({ reset: true });
      setIngestResult(data);
      notify(`Ingested ${data.total_chunks} chunks from ${data.files_processed} policy files.`, 'success');
      await refreshStats();
    } catch (err) {
      setError(err.message);
      notify('Ingestion failed.', 'error');
    } finally {
      setBusy('');
    }
  };

  const handleSearch = async (overrideQuery) => {
    const q = overrideQuery ?? query;
    if (!q.trim()) return;
    setBusy('search');
    setError(null);
    try {
      const data = await knowledge.search(q, 5);
      setResults(data);
    } catch (err) {
      setError(err.message);
      setResults(null);
    } finally {
      setBusy('');
    }
  };

  const handleLoadChunks = async () => {
    setBusy('list');
    setError(null);
    try {
      const data = await knowledge.listEmbeddings({ limit: 100 });
      setChunks(data.embeddings || []);
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy('');
    }
  };

  const handleDelete = async () => {
    // eslint-disable-next-line no-restricted-globals
    if (!window.confirm('Delete every ingested policy chunk? The audit will lose its grounding until you re-ingest.')) {
      return;
    }
    setBusy('delete');
    try {
      const data = await knowledge.deleteAll();
      setChunks([]);
      setResults(null);
      setIngestResult(null);
      notify(`Deleted ${data.deleted_count} chunks.`, 'success');
      await refreshStats();
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy('');
    }
  };

  return (
    <div className="space-y-6">
      <header>
        <h2 className="text-xl font-bold text-ink-primary">Knowledge Base &amp; RAG</h2>
        <p className="mt-1 text-sm text-ink-muted">
          Chunk, embed and store the organization&apos;s security policies in Redis, then query
          them with vector search. The audit agent issues these same queries to ground its verdicts.
        </p>
      </header>

      {error ? <Banner tone="error" title="Request failed">{error}</Banner> : null}

      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <StatTile
          label="Stored chunks"
          value={stats ? stats.stored_chunks : '--'}
          hint={stats ? `index: ${stats.index_name}` : 'loading'}
          tone="brand"
          icon={Layers}
        />
        <StatTile
          label="Indexed documents"
          value={stats ? stats.num_docs ?? 0 : '--'}
          hint="reported by RediSearch"
          icon={Database}
        />
        <StatTile
          label="Vector dimensions"
          value={stats ? stats.vector_dimensions : '--'}
          hint={stats && stats.search_module ? 'RediSearch present' : 'RediSearch missing'}
          tone={stats && stats.search_module ? 'good' : 'bad'}
          icon={FileText}
        />
        <StatTile
          label="Redis"
          value={stats ? (stats.reachable ? 'Online' : 'Offline') : '--'}
          hint={stats ? `${stats.redis_host}:${stats.redis_port}` : ''}
          tone={stats && stats.reachable ? 'good' : 'bad'}
        />
      </div>

      <Card
        title="Ingestion"
        subtitle="Re-ingesting resets the corpus first, so chunks are never duplicated."
        actions={
          <>
            <button className="btn-ghost" onClick={handleLoadChunks} disabled={!!busy}>
              {busy === 'list' ? <Spinner /> : null} View chunks
            </button>
            <button className="btn-danger" onClick={handleDelete} disabled={!!busy}>
              {busy === 'delete' ? <Spinner /> : <Trash2 className="h-4 w-4" />} Clear
            </button>
            <button className="btn-accent" onClick={handleIngest} disabled={!!busy}>
              {busy === 'ingest' ? <Spinner /> : <UploadCloud className="h-4 w-4" />}
              {busy === 'ingest' ? 'Ingesting...' : 'Ingest policies'}
            </button>
          </>
        }
      >
        {ingestResult ? (
          <div className="space-y-3">
            <Banner tone="success" title={ingestResult.message}>
              {ingestResult.total_chunks} chunks from {ingestResult.files_processed} files in{' '}
              {ingestResult.elapsed_seconds}s &middot; provider{' '}
              <code className="rounded bg-[#e7f6e7] px-1 font-mono text-xs text-[#09660a]">
                {ingestResult.embedding_provider}
              </code>
            </Banner>
            <div className="table-wrap">
              <table className="min-w-full">
                <thead>
                  <tr>
                    <th className="th">Policy file</th>
                    <th className="th">Chunks</th>
                  </tr>
                </thead>
                <tbody>
                  {(ingestResult.files || []).map((f) => (
                    <tr key={f.file}>
                      <td className="td font-medium text-ink-primary">{f.file}</td>
                      <td className="td tabular-nums">{f.chunks}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        ) : (
          <EmptyState icon={UploadCloud} title="No ingestion run in this session">
            Click <strong>Ingest policies</strong> to load{' '}
            <code className="font-mono text-xs">backend/knowledge_base/</code> into the vector store.
          </EmptyState>
        )}
      </Card>

      <Card
        title="Vector search"
        subtitle="Cosine similarity over the policy corpus - this is the retrieval half of RAG."
      >
        <div className="flex flex-col gap-3 sm:flex-row">
          <input
            type="text"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && handleSearch()}
            placeholder="Ask about a security policy..."
            className="w-full rounded-lg border border-ink-hairline px-3.5 py-2.5 text-sm shadow-sm
                       focus:border-brand-500 focus:outline-none focus:ring-2 focus:ring-brand-500/30"
          />
          <button className="btn-primary shrink-0" onClick={() => handleSearch()} disabled={!!busy}>
            {busy === 'search' ? <Spinner /> : <Search className="h-4 w-4" />} Search
          </button>
        </div>

        <div className="mt-3 flex flex-wrap gap-2">
          {SAMPLE_QUERIES.map((q) => (
            <button
              key={q}
              type="button"
              onClick={() => {
                setQuery(q);
                handleSearch(q);
              }}
              className="chip border border-ink-hairline bg-surface-sunken text-ink-secondary hover:border-brand-300 hover:text-brand-700"
            >
              {q.length > 42 ? `${q.slice(0, 42)}...` : q}
            </button>
          ))}
        </div>

        {results ? (
          <div className="mt-5 space-y-3">
            <p className="text-sm text-ink-muted">
              {results.count} result{results.count === 1 ? '' : 's'} for{' '}
              <span className="font-medium text-ink-secondary">&ldquo;{results.query}&rdquo;</span>
            </p>
            {(results.results || []).map((r, i) => (
              <div key={r.id} className="rounded-lg border border-ink-hairline bg-surface-sunken p-4">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <span className="chip-info">#{i + 1} {r.source}</span>
                  <span className="font-mono text-xs text-ink-muted">similarity {r.score}</span>
                </div>
                <p className="mt-2 whitespace-pre-wrap text-sm leading-relaxed text-ink-secondary">
                  {r.content.length > 480 ? `${r.content.slice(0, 480)}...` : r.content}
                </p>
              </div>
            ))}
          </div>
        ) : null}
      </Card>

      {chunks.length > 0 ? (
        <Card title={`Stored chunks (${chunks.length})`}>
          <div className="space-y-2">
            {chunks.map((c) => (
              <Collapsible
                key={c.id}
                summary={
                  <span className="min-w-0 truncate">
                    <span className="font-mono text-xs text-ink-muted">{c.id.slice(0, 26)}...</span>
                    <span className="ml-2 font-medium">{c.source}</span>
                  </span>
                }
              >
                <p className="whitespace-pre-wrap text-sm text-ink-secondary">{c.content}</p>
                <p className="mt-2 font-mono text-xs text-ink-muted">
                  chunk {(c.metadata && c.metadata.chunk_index) ?? '?'} of{' '}
                  {(c.metadata && c.metadata.chunk_count) ?? '?'} &middot; {c.vector_dimensions} dims
                </p>
              </Collapsible>
            ))}
          </div>
        </Card>
      ) : null}
    </div>
  );
}
